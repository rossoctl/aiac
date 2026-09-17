"""Shared harness for the UC-1 onboarding integration-test ladder (rungs 1–3).

Spec: ``docs/testing/uc1-onboarding-pipeline.md``; live loop shape (handoff 08):
``k8s/opa-kind-runbook.md``. The evaluator is now the **deployed AuthBridge OPA plugin**, not a
standalone OPA-CLI run over dumped ``.rego`` — there is no ``.rego`` dump and no ``opa`` binary here.

Every rung follows the same shape against **one** live rossoctl/Kind cluster with the AuthBridge OPA
pipeline wired into both legs:

    start from a no-workloads slate (undeploy + delete registrations) + policy-store clear
      → deploy the rung's workloads in order, one at a time — each deploy fires the EVENT-DRIVEN
        trigger (operator registers a Keycloak client → Keycloak CLIENT_CREATED → the aiac-event-listener
        SPI publishes on NATS → the agent consumer runs onboard_service, upserting the AuthorizationPolicy
        CR on the live API), converging before the next
      → enable the outbound token-exchange leg (Part B: route + optional client scope + agent restart)
      → poll bundle-service + OPA until this run's CR is reflected in real decisions
      → drive REAL HTTP requests through AuthBridge and assert the real plugin's allow/deny
      → teardown full-to-pristine (undeploy + delete all registrations + delete CRs, verified)

The only thing that differs between rungs is *which workloads are onboarded and in what order*, so
all the machinery lives here and each ``test_uc1_onboard_*.py`` supplies just its own oracle
(verdicts computed from ``scenario_uc1.py``) and live assertions.

This module owns:

* **Config** (env, spec § Configuration) — single stack, no variants.
* **Keycloak** — ``connect_admin`` / ``provision_realm_and_users`` (the fixture UC-1 does *not* do) /
  ``cleanup_provisioned`` / ``delete_workload_registrations`` (teardown).
* **Onboarding (event-driven)** — ``ensure_agent_policy`` (mount the PRB's ``policy.md``) +
  ``deploy_workload`` (deploy fires the trigger) / ``wait_for_registration`` / ``undeploy_workload``.
* **Outbound-leg prep (Part B)** — ``ensure_github_tool_route`` / ``grant_exchange_scope`` /
  ``restart_agent`` so ``token-exchange`` runs and OPA is actually consulted on the outbound leg.
* **Live decision oracle + probes** — ``expected_inbound`` / ``expected_outbound_bare`` (verdicts from
  ``scenario_uc1``, keyed on the **bare** runtime tool names AuthBridge sends) and ``inbound_decision``
  / ``outbound_decision`` (mint a user token, send a real request through AuthBridge, classify the
  real plugin's response).
* **``onboarded_stack``** — the whole per-rung fixture flow, parameterised by the ordered workload
  list; each rung wraps it in a one-line session fixture and yields a probe context.

It imports only stdlib + ``requests`` + ``launcher`` + the pure-data ``scenario_uc1`` (never
``aiac``), so it is importable before the env-before-import dance, exactly like ``scenario_uc1`` and
``launcher``. It defines **no** ``test_*`` functions, so pytest does not collect it.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

import requests

HERE = Path(__file__).resolve().parent  # test/system/
REPO_ROOT = HERE.parents[1]  # -> aiac/
if str(REPO_ROOT) not in sys.path:  # so ``import test.system.*`` resolves
    sys.path.insert(0, str(REPO_ROOT))

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system.launcher import (  # noqa: E402
    _kubectl_try,
    inbound_outcome,
    inbound_probe,
    kubectl,
    kubectl_apply,
    kubectl_delete,
    kubectl_rollout_status,
    mint_token,
    outbound_outcome,
    outbound_probe,
    poll_until,
    port_forward,
    require_env,
    require_env_or_skip,
    require_event_path,
    require_pipeline,
    resolve_pod,
    verify_subject_mapper,
)

log = logging.getLogger(__name__)

# --- Config (env) — spec § Configuration; single stack (no variants) ------------------------
TEST_REALM = os.environ.get("AIAC_TEST_REALM", scn.REALM_DEFAULT)
NAMESPACE = os.environ.get("AIAC_DEMO_NAMESPACE", scn.DEMO_NAMESPACE_DEFAULT)
ADMIN_REALM = os.environ.get("KEYCLOAK_ADMIN_REALM", "master")

# Controller (in-cluster) namespace — the ns whose Controller Deployment the test patches (policy.md
# mount, default_effect). The onboarding trigger is event-driven (deploy fires it), so the harness no
# longer port-forwards to the Controller to POST /apply.
CONTROLLER_NAMESPACE = os.environ.get("AIAC_CONTROLLER_NAMESPACE", "aiac-system")

# Policy Store (in-cluster) reached via ``kubectl port-forward`` to clear stale SPMs before a run.
# The store's SQLite lives on a StatefulSet PV that survives image redeploys, so pre-fix cruft
# would otherwise accumulate across runs (onboarding appends with override=False). Defaults match
# the deployed stack (svc/aiac-policy-model-store-service:7074 in aiac-system).
STORE_NAMESPACE = os.environ.get("AIAC_STORE_NAMESPACE", "aiac-system")
STORE_TARGET = os.environ.get("AIAC_STORE_TARGET", "svc/aiac-policy-model-store-service")
STORE_LOCAL_PORT = int(os.environ.get("AIAC_STORE_LOCAL_PORT", "7074"))
STORE_REMOTE_PORT = int(os.environ.get("AIAC_STORE_REMOTE_PORT", "7074"))

# The Controller Deployment + the abstract policy.md the PRB reads. The test mounts this policy on
# the Controller pod as a precondition-fixup (see ``ensure_agent_policy``); it is NOT written into
# any committed deployment manifest — the deployment stays free of test-specific config.
CONTROLLER_DEPLOYMENT = os.environ.get("AIAC_CONTROLLER_DEPLOYMENT", "aiac-agent")
POLICY_CONFIGMAP = os.environ.get("AIAC_POLICY_CONFIGMAP", "aiac-policy")
POLICY_MOUNT_PATH = os.environ.get("AIAC_POLICY_MOUNT_PATH", "/etc/aiac")

# --- Live-cluster loop knobs (handoff 08) ---------------------------------------------------

# The workload Deployment to restart after Part B so it reloads the new outbound route (and, on its
# OPA sidecar's next poll, the recomposed bundle). Defaults to the agent workload name.
AGENT_DEPLOYMENT = os.environ.get("AIAC_AGENT_DEPLOYMENT", scn.AGENT_WORKLOAD)

# SPIFFE trust domain the operator registers the demo workloads under (the ``spiffe://<td>/ns/...``
# authority). Matches the rossoctl Kind cluster's default; override for a differently-named cluster.
TRUST_DOMAIN = os.environ.get("AIAC_TRUST_DOMAIN", "localtest.me")

# After a CR is upserted, ``bundle-service`` recomposes the namespace bundle and each pod's OPA polls
# it on its own (~20–30 s) interval, and ``token-exchange`` needs a moment to settle after the agent
# restart. ``onboarded_stack`` polls real decisions until they converge, up to this budget (seconds).
BUNDLE_TIMEOUT = float(os.environ.get("AIAC_BUNDLE_TIMEOUT", "300"))
BUNDLE_POLL_INTERVAL = float(os.environ.get("AIAC_BUNDLE_POLL_INTERVAL", "10"))

# Deploying a workload fires the event-driven trigger (deploy -> operator registers a Keycloak client
# -> CLIENT_CREATED -> SPI -> NATS -> the agent consumer runs ``onboard_service``). The operator's
# client registration is asynchronous (reconcile after the pod comes up), so the fixture polls for it
# up to this budget (``AIAC_DEPLOY_TIMEOUT``, seconds).
DEPLOY_TIMEOUT = float(os.environ.get("AIAC_DEPLOY_TIMEOUT", "180"))

# The demo manifests each workload deploys, in apply order (agent: ConfigMaps THEN Deployment; tool:
# a single Deployment manifest). ``deploy.sh`` (demo/assets) applies this same set + order — keep the
# two in lockstep. The Deployment name matches the workload name, so ``deployment/{workload}`` is the
# rollout target. Undeploy walks these in reverse.
WORKLOAD_MANIFESTS: dict[str, list[Path]] = {
    scn.AGENT_WORKLOAD: [
        REPO_ROOT / "demo/assets/agents/github_agent/k8s/configmaps.yaml",
        REPO_ROOT / "demo/assets/agents/github_agent/k8s/github-agent-deployment.yaml",
    ],
    scn.TOOL_WORKLOAD: [
        REPO_ROOT / "demo/assets/tools/github_tool/k8s/github-tool-deployment.yaml",
    ],
}

# --- default_effect onboarding hook (#146 coupling seam; see ``_set_controller_default_effect``) ----
#
# The derived ``AgentPolicyModel.default_effect`` decides whether the generated Rego is deny-by-default
# (the shipped ``Deny``) or allow-by-default (``Allow``). It lives on the *derived* APM built in-cluster
# by the PCE (``engine._fresh_apm``) and defaults to ``Deny``, so a policy-agnostic onboarding run that
# needs allow-by-default must set it **before** onboarding and reset it on teardown. These are plain
# strings (matching ``RuleEffect``'s wire values ``"Allow"`` / ``"Deny"``) so the harness keeps its "no
# ``aiac`` import" property — importable before the env-before-import dance, like ``scenario_uc1``.
DEFAULT_EFFECT_ALLOW = "Allow"
DEFAULT_EFFECT_DENY = "Deny"  # the shipped default; the harness never patches this onto the stack
# The Controller/PCE env the #146 hook reads where it mints the APM. Overridable so this test tracks
# whatever name #146 ships without a code edit (verify the shape against #146 — handoff §3).
DEFAULT_EFFECT_ENV = os.environ.get("AIAC_DEFAULT_EFFECT_ENV", "AIAC_DEFAULT_EFFECT")


# ======================================================================================
# Expected-verdict oracle (pure functions over the scenario_uc1 truth table)
# ======================================================================================
#
# Two naming registers meet here (see ``scenario_uc1`` docstring): the *provisioned* grant sets stay
# PREFIXED (``github-tool.source-read`` — what UC-1 writes into Keycloak + the CR data maps), while
# the *request the test sends and the outcome it expects* are keyed on the BARE runtime names
# AuthBridge's mcp-parser puts in ``input.mcp.params.name`` (``source-read``). The grant-set constants
# below are the prefixed provisioned truth (for the fixture-independent oracle-contract tests); the
# ``expected_*`` helpers decide live outcomes over the bare names.

# Prefixed provisioned truth — the exact strings UC-1 provisions and the PCE writes into the CR maps.
INBOUND_GRANT_SET: set[tuple[str, str]] = set(scn.INBOUND_PAIRS)
OUTBOUND_SUBJECT_GRANT_SET: set[tuple[str, str]] = set(scn.OUTBOUND_SUBJECT_PAIRS)
OUTBOUND_TARGET_GRANT_SET: set[tuple[str, str]] = set(scn.OUTBOUND_TARGET_PAIRS)

_INBOUND_SOURCES = {role for role, _ in scn.INBOUND_PAIRS}  # user-roles reaching some agent scope


def expected_inbound(subject: str) -> bool:
    """A user may call the agent iff their realm role sources some agent scope (``INBOUND_PAIRS``).
    Unaffected by tool onboarding — the same for every rung."""
    return scn.USERS[subject] in _INBOUND_SOURCES


def expected_outbound_bare(subject: str, tool_bare: str) -> bool:
    """A user's outbound call to a **bare** tool name (``source-read``) is allowed iff **both** gates
    pass (per-scope AND): their realm role reaches it in the user→tool subject gate
    (``OUTBOUND_SUBJECT_BARE``) **and** the agent's own operator roles reach it in the capability gate
    (``OUTBOUND_TARGET_BARE``). This is the tool-onboarded oracle (rungs 2 & 3); rung 1's gate is
    empty (no tool onboarded), so rung 1 supplies its own all-deny oracle."""
    user_ok = (scn.USERS[subject], tool_bare) in scn.OUTBOUND_SUBJECT_BARE
    agent_ok = tool_bare in scn.OUTBOUND_TARGET_BARE
    return user_ok and agent_ok


def expected_inbound_decision(subject: str) -> str:
    """The inbound oracle as a decision string (``"allow"`` / ``"deny"``) — comparable to the live
    ``inbound_decision`` outcome."""
    return "allow" if expected_inbound(subject) else "deny"


def expected_outbound_decision(subject: str, tool_bare: str) -> str:
    """The tool-onboarded outbound oracle as a decision string — comparable to the live
    ``outbound_decision`` outcome (rungs 2 & 3)."""
    return "allow" if expected_outbound_bare(subject, tool_bare) else "deny"


# ======================================================================================
# Keycloak provisioning + cleanup (the fixture UC-1 does NOT do)
# ======================================================================================


def connect_admin():
    """Connect to the admin realm so the fixture can provision users + clean up provisioned entities."""
    from keycloak import KeycloakAdmin

    creds = require_env("KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    return KeycloakAdmin(
        server_url=creds["KEYCLOAK_URL"],
        realm_name=ADMIN_REALM,
        user_realm_name=ADMIN_REALM,
        username=creds["KEYCLOAK_ADMIN_USERNAME"],
        password=creds["KEYCLOAK_ADMIN_PASSWORD"],
    )


def provision_realm_and_users(admin, realm: str) -> None:
    """Idempotently ensure ``realm`` holds ``scenario_uc1``'s users + realm roles with the
    descriptions the PRB reads. Realm roles carry the ``aiac.managed`` marker so the IdP populates
    each role's ``actorIds`` (member usernames) — the PCE needs them to build the ``subject_roles``
    map the inbound/outbound gates key on. Never deletes/recreates — reruns converge (spec: shared
    realm, leave-in-place)."""
    from keycloak.exceptions import KeycloakError

    try:
        admin.create_realm({"realm": realm, "enabled": True})
    except KeycloakError:
        pass  # already exists — leave in place
    admin.change_current_realm(realm)

    for name, description in scn.USER_ROLES.items():
        payload = {"name": name, "description": description, "attributes": {"aiac.managed": ["true"]}}
        admin.create_realm_role(payload, skip_exists=True)
        admin.update_realm_role(name, payload)  # ensure the marker on a pre-existing role too

    for username, role_name in scn.USERS.items():
        user_id = admin.create_user({"username": username, "enabled": True}, exist_ok=True)
        admin.set_user_password(user_id, scn.USER_PASSWORD, temporary=False)
        admin.assign_realm_roles(user_id, [admin.get_realm_role(role_name)])


def cleanup_provisioned(admin, realm: str) -> None:
    """Delete the entities UC-1 onboarding provisions — the realm role(s) and client scopes prefixed
    ``github-agent.`` / ``github-tool.`` — so each run starts from a clean slate and reruns converge.

    Leaves the fixture's own ``developer`` / ``tester`` / ``devops`` roles, the operator's audience
    client scopes (``*-aud``, no ``.`` after the workload), and everything else in place. Best-effort:
    a delete of an already-absent entity is ignored."""
    from keycloak.exceptions import KeycloakError

    admin.change_current_realm(realm)
    prefixes = (f"{scn.AGENT_WORKLOAD}.", f"{scn.TOOL_WORKLOAD}.")

    for role in admin.get_realm_roles():
        name = role.get("name", "")
        if name.startswith(prefixes):
            try:
                admin.delete_realm_role(name)
            except KeycloakError as exc:
                log.warning("cleanup: delete realm role %r failed: %s", name, exc)

    for scope in admin.get_client_scopes():
        name = scope.get("name", "")
        if name.startswith(prefixes):
            try:
                admin.delete_client_scope(scope["id"])
            except KeycloakError as exc:
                log.warning("cleanup: delete client scope %r failed: %s", name, exc)


def reenable_provisioned_clients(admin, realm: str) -> None:
    """Re-enable any demo workload client (``{namespace}/github-agent`` / ``{namespace}/github-tool``)
    left **disabled** by a prior run before onboarding starts.

    A failed onboard rolls back by disabling the service's Keycloak client as a failed-service marker
    (``orchestrator._rollback`` -> ``set_service_enabled(False)``); a fully successful onboard re-enables
    it. So a client left disabled is the fingerprint of an earlier crashed/aborted run, and it makes the
    next run's discovery-token mint fail with ``invalid_client`` (a disabled client cannot use the
    client_credentials grant). Flipping it back to ``enabled`` here restores the same clean slate the
    onboard's own success path would — idempotent: an already-enabled client is left untouched.

    Keys clients by ``name`` (``{namespace}/{workload}``), exactly as ``wait_for_registration`` and
    ``require_pipeline`` do — never the SPIFFE ``clientId``. Best-effort: a failure to re-enable one
    client is logged, not raised, so the run proceeds to onboard (which will surface the real cause)."""
    from keycloak.exceptions import KeycloakError

    admin.change_current_realm(realm)
    demo_client_names = {f"{NAMESPACE}/{scn.AGENT_WORKLOAD}", f"{NAMESPACE}/{scn.TOOL_WORKLOAD}"}
    for client in admin.get_clients():
        if client.get("name") in demo_client_names and not client.get("enabled", True):
            try:
                admin.update_client(client["id"], {"enabled": True})
                log.info("cleanup: re-enabled disabled client %r left by a prior run", client.get("name"))
            except KeycloakError as exc:
                log.warning("cleanup: re-enable client %r failed: %s", client.get("name"), exc)


def clear_policy_store() -> None:
    """Drop every persisted SPM from the in-cluster Policy Store before a run — the store-side twin
    of ``cleanup_provisioned``'s Keycloak reset.

    The store's SQLite lives on a StatefulSet PV that outlives image redeploys, and onboarding
    appends to each SPM with ``override=False``; without this the store accumulates pre-fix cruft
    (stale role-id generations, retired ``*-aud`` edges, cross-run pollution) that the PCE replays
    into every regenerated policy — so a fixed pipeline still emits defective policy. Clearing here
    guarantees each run derives its policy from only the edges this run onboarded.

    Hits ``DELETE /policy/services`` directly through a port-forward (the harness never imports
    ``aiac``). Best-effort about *reachability* — a store that is unreachable (or a port-forward that
    won't come up) is tolerated and only warned about. But a store that answers with a **non-2xx**
    means the clear actually failed: proceeding would run the rung on dirty state (stale SPMs
    replayed into every regenerated policy), so that case fails loudly rather than silently."""
    try:
        with port_forward(
            STORE_TARGET,
            namespace=STORE_NAMESPACE,
            local_port=STORE_LOCAL_PORT,
            remote_port=STORE_REMOTE_PORT,
            ready_url=f"http://127.0.0.1:{STORE_LOCAL_PORT}/health",
        ) as base_url:
            resp = requests.delete(f"{base_url}/policy/services", timeout=30)
    except (requests.ConnectionError, requests.Timeout, RuntimeError) as exc:
        # Store unreachable / port-forward failed — best-effort, must not fail the run.
        log.warning("clear_policy_store: store unreachable, skipping clear (%s)", exc)
        return
    if not (200 <= resp.status_code < 300):
        raise AssertionError(
            f"clear_policy_store: DELETE /policy/services returned HTTP {resp.status_code} — the "
            f"store was reached but the clear failed, so the run would proceed on dirty state "
            f"(stale SPMs): {resp.text[:500]}"
        )
    log.info("cleared Policy Store SPMs (HTTP %s)", resp.status_code)


# ======================================================================================
# Event-driven onboarding: policy precondition + deploy/undeploy/registration lifecycle
# ======================================================================================


def ensure_agent_policy(namespace: str, policy_md: str = scn.POLICY_ABSTRACT) -> None:
    """Ensure the PRB's ``policy.md`` is mounted in the Controller pod — the one mutable stack
    precondition the ladder owns, so a fresh AIAC stack needs no manual patching.

    Phase-1's PRB reads the single abstract policy from ``AIAC_POLICY_FILE`` (default
    ``/etc/aiac/policy.md``). This idempotently provisions that file as a ConfigMap and mounts it on
    the Controller Deployment, rolling out **only** when the mount is absent. The mounted text is
    ``policy_md`` — defaulting to ``scenario_uc1.POLICY_ABSTRACT`` (Policy A) so existing callers mount
    the same abstract policy the scenario's verdicts assume; a second policy (e.g. the denyworld
    ``POLICY_DENYWORLD``) is driven through the same harness by passing its prose here. It is never
    written into a committed deployment manifest (that stays free of test config) and is left in place
    on teardown (benign, and keeps reruns fast).

    The content-diff below (``kubectl apply`` "unchanged" vs "configured") already forces a Controller
    rollout whenever ``policy.md``'s prose changes, so **switching between policies reloads correctly**:
    a run that swaps Policy A for Policy B (or back) sees "configured", rolls the Controller, and waits,
    so the PRB reads the new prose before onboarding."""
    cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": POLICY_CONFIGMAP, "namespace": namespace},
        "data": {"policy.md": policy_md},
    }
    apply_out = kubectl("apply", "-f", "-", input_text=json.dumps(cm))
    # ``kubectl apply`` reports "created"/"configured" when the ConfigMap's content differs from the
    # cluster and "unchanged" when it matches; use that to decide whether a rollout is needed.
    cm_changed = "unchanged" not in apply_out

    mounted = kubectl(
        "get",
        "deployment",
        CONTROLLER_DEPLOYMENT,
        "-n",
        namespace,
        "-o",
        "jsonpath={.spec.template.spec.volumes[*].configMap.name}",
    )
    if POLICY_CONFIGMAP in mounted.split():
        # Already mounted, so no deployment patch (and thus no rollout) is triggered. But a projected
        # ConfigMap volume only re-syncs on the kubelet's own (~minute) cadence, and the PRB reads
        # policy.md once at startup — so if we just changed the ConfigMap's content the running pod
        # would keep serving the stale policy. Force a rollout + wait so the new policy.md is in
        # place before onboarding; skip it when apply reported the ConfigMap unchanged (fast reruns).
        if cm_changed:
            kubectl("rollout", "restart", f"deployment/{CONTROLLER_DEPLOYMENT}", "-n", namespace)
            kubectl_rollout_status(f"deployment/{CONTROLLER_DEPLOYMENT}", namespace=namespace)
        return  # already mounted — content is now current

    patch = {
        "spec": {
            "template": {
                "spec": {
                    "volumes": [{"name": "aiac-policy", "configMap": {"name": POLICY_CONFIGMAP}}],
                    "containers": [
                        {
                            "name": CONTROLLER_DEPLOYMENT,
                            "volumeMounts": [{"name": "aiac-policy", "mountPath": POLICY_MOUNT_PATH, "readOnly": True}],
                        }
                    ],
                }
            }
        }
    }
    kubectl(
        "patch",
        "deployment",
        CONTROLLER_DEPLOYMENT,
        "-n",
        namespace,
        "--type",
        "strategic",
        "-p",
        json.dumps(patch),
    )
    kubectl_rollout_status(f"deployment/{CONTROLLER_DEPLOYMENT}", namespace=namespace)


def _set_controller_default_effect(namespace: str, effect: str) -> None:
    """Apply the ``default_effect`` onboarding hook: set the Controller/PCE env the engine reads when
    it mints the ``AgentPolicyModel`` (``engine._fresh_apm``), then roll the Controller so the new
    value is live **before** the next ``onboard`` derives a policy under it. Mirrors
    ``ensure_agent_policy``'s patch-and-rollout precondition-fixup — a test-owned mutation of the
    running Controller, never written into a committed manifest.

    This is the single hard coupling to Task 1 (#146), which owns the reader side. The env **name**
    (``DEFAULT_EFFECT_ENV``, default ``AIAC_DEFAULT_EFFECT``) and the string values (``"Allow"`` /
    ``"Deny"``) are #146's contract — verify/realign them once #146 lands (handoff §3). The strategic
    merge patch is keyed on the env-var ``name``, so it upserts just this one var and leaves the
    Controller's other env untouched."""
    patch = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": CONTROLLER_DEPLOYMENT, "env": [{"name": DEFAULT_EFFECT_ENV, "value": effect}]}
                    ]
                }
            }
        }
    }
    kubectl(
        "patch",
        "deployment",
        CONTROLLER_DEPLOYMENT,
        "-n",
        namespace,
        "--type",
        "strategic",
        "-p",
        json.dumps(patch),
    )
    kubectl("rollout", "restart", f"deployment/{CONTROLLER_DEPLOYMENT}", "-n", namespace)
    kubectl_rollout_status(f"deployment/{CONTROLLER_DEPLOYMENT}", namespace=namespace)


# The demo-asset image loader. ``kind load`` needs the ``kind`` CLI + a container runtime on the pytest
# host, and that host must be the one hosting the Kind node — the system suite's local-Kind topology.
# There is no ``kubectl`` equivalent, so this is the one place the harness shells out to a demo script.
KIND_LOAD_SCRIPT = REPO_ROOT / "demo/assets/kind-load.sh"
# Selector flags so a rung stages only the image(s) it will deploy (rung 1 = agent only); both -> no flag.
_KIND_LOAD_FLAG = {scn.AGENT_WORKLOAD: "--agent-only", scn.TOOL_WORKLOAD: "--tool-only"}


def _kind_cluster_name() -> str:
    """The Kind cluster name ``kind-load.sh`` loads into — it targets a cluster *by name* (``kind load
    ... --name``), independent of the current kube-context, so the fixture must tell it which one.
    Prefer an explicit ``AIAC_KIND_CLUSTER`` override; else derive it from the current kube-context,
    which ``kind`` names ``kind-<cluster>``, so images land in the same cluster the rest of the suite
    talks to. Fall back to ``kind-load.sh``'s own ``rossoctl`` default when the context is unreadable
    or not a ``kind-`` one."""
    override = os.environ.get("AIAC_KIND_CLUSTER")
    if override:
        return override
    try:
        ctx = subprocess.run(
            ["kubectl", "config", "current-context"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "rossoctl"
    return ctx[len("kind-") :] if ctx.startswith("kind-") else "rossoctl"


def load_workload_images(workloads: Sequence[str]) -> None:
    """Fulfill the **images precondition**: build (if absent) + ``kind load`` each requested workload's
    demo image into the Kind node, via ``demo/assets/kind-load.sh``. This is the *load* half of the
    demo-asset lifecycle the suite now owns end-to-end (load -> deploy -> teardown to pristine);
    ``deploy_workload`` still does only ``kubectl apply`` + rollout, so the two stay cleanly separable.

    No ``--rebuild`` — an already-built image is only re-loaded into the node, not rebuilt (build-if-
    absent), so this is cheap on a warm host and never silently ships stale source. It runs on the pytest
    host, which must carry ``kind`` + ``kubectl`` + a container runtime and host the Kind node; when it
    does not, the script exits non-zero and the test **fails loudly** (never a false pass). The target
    Kind cluster is passed via ``CLUSTER_NAME`` (``_kind_cluster_name``) so a cluster not named
    ``rossoctl`` still loads correctly. Only the requested workloads are staged: a single workload passes
    its ``--agent-only`` / ``--tool-only`` selector; both passes no selector (loads both)."""
    cmd = ["bash", str(KIND_LOAD_SCRIPT)]
    if len(workloads) == 1:
        cmd.append(_KIND_LOAD_FLAG[workloads[0]])
    subprocess.run(cmd, check=True, env={**os.environ, "CLUSTER_NAME": _kind_cluster_name()})


def deploy_workload(workload: str) -> None:
    """Deploy ``workload`` (``github-agent`` / ``github-tool``) into the cluster — the **event-driven
    onboarding trigger**: the operator reconciles the bundled ``AgentRuntime`` CR, registers a Keycloak
    client, Keycloak emits ``CLIENT_CREATED``, the SPI publishes on NATS, and the agent consumer runs
    ``onboard_service`` (the same handler the retired ``POST /apply`` called).

    ``kubectl apply``s the workload's demo manifests in order via the generic ``kubectl_apply`` and
    waits for the Deployment rollout. It does **not** build or ``kind load`` images — ``onboarded_stack``
    fulfills that precondition first via ``load_workload_images`` (``demo/assets/kind-load.sh``); a
    missing image still surfaces as a pod that never becomes Ready, which the rollout wait / convergence
    poll turns into a loud failure, never a false pass."""
    for manifest in WORKLOAD_MANIFESTS[workload]:
        kubectl_apply(manifest, namespace=NAMESPACE)
    kubectl_rollout_status(f"deployment/{workload}", namespace=NAMESPACE, timeout=DEPLOY_TIMEOUT)


def wait_for_registration(admin, workload: str) -> bool:
    """Poll until the operator has registered the Keycloak client ``{ns}/{workload}`` (async reconcile
    after the pod comes up — "rollout complete" is not "registered"). Returns whether it appeared
    within ``DEPLOY_TIMEOUT``. Keyed on the client ``name`` (``{ns}/{workload}``), exactly as
    ``reenable_provisioned_clients`` / ``grant_exchange_scope`` do — never the SPIFFE ``clientId``."""
    client_name = f"{NAMESPACE}/{workload}"

    def _registered() -> bool:
        admin.change_current_realm(TEST_REALM)
        return client_name in {c.get("name") for c in admin.get_clients()}

    return poll_until(_registered, timeout=DEPLOY_TIMEOUT, interval=5)


def undeploy_workload(workload: str) -> None:
    """``kubectl delete`` ``workload``'s demo manifests in **reverse** apply order, tolerant of
    already-absent objects (``kubectl_delete`` passes ``--ignore-not-found --wait=true``). Deleting the
    bundled ``AgentRuntime`` CR stops the operator managing the workload's Keycloak client, so the
    explicit registration cleanup that follows is not racing an active reconcile."""
    for manifest in reversed(WORKLOAD_MANIFESTS[workload]):
        try:
            kubectl_delete(manifest, namespace=NAMESPACE)
        except subprocess.CalledProcessError as exc:
            log.warning("undeploy_workload(%s): delete %s failed: %s", workload, manifest.name, exc)


def workload_clients_present(admin) -> set[str]:
    """The subset of ``{ns}/github-agent`` / ``{ns}/github-tool`` currently registered as Keycloak
    clients — empty when the cluster is pristine. Used to poll a clean slate before deploy and to
    verify a footprint-free teardown."""
    admin.change_current_realm(TEST_REALM)
    names = {c.get("name") for c in admin.get_clients()}
    return {n for n in (f"{NAMESPACE}/{scn.AGENT_WORKLOAD}", f"{NAMESPACE}/{scn.TOOL_WORKLOAD}") if n in names}


def tool_scopes_present(admin) -> bool:
    """True once every ``github-tool.*`` client scope (``scn.TOOL_SCOPES``) is provisioned in the realm
    — the tool's convergence gate. The tool is a pure target: it produces **no** ``AuthorizationPolicy``
    CR and **no** enforced decision of its own, so its scopes existing (not a live probe) is the signal
    the operator finished registering it."""
    admin.change_current_realm(TEST_REALM)
    names = {s.get("name") for s in admin.get_client_scopes()}
    return all(scope in names for scope in scn.TOOL_SCOPES)


def delete_workload_registrations(admin, realm: str) -> None:
    """Explicitly delete both workloads' Keycloak footprint — their clients, their ``*-aud`` audience
    client scopes, and the operator's client-credentials Secret — so teardown does not trust an
    unverified operator cascade. Best-effort + tolerant (already-absent is fine), so it is safe to run
    both at startup (pristine slate) and at teardown.

    ``cleanup_provisioned`` only clears the ``github-agent.`` / ``github-tool.``-**prefixed** roles and
    scopes; the operator's ``*-aud`` scopes (e.g. ``agent-team1-github-tool-aud``, no ``.`` after the
    workload) and the dynamically-named ``rossoctl-keycloak-client-credentials-<hash>`` Secret are not
    covered there, so this sweep handles them by suffix / prefix."""
    from keycloak.exceptions import KeycloakError

    admin.change_current_realm(realm)
    target_client_names = {f"{NAMESPACE}/{scn.AGENT_WORKLOAD}", f"{NAMESPACE}/{scn.TOOL_WORKLOAD}"}
    for client in admin.get_clients():
        if client.get("name") in target_client_names:
            try:
                admin.delete_client(client["id"])
            except KeycloakError as exc:
                log.warning("teardown: delete client %r failed: %s", client.get("name"), exc)

    for scope in admin.get_client_scopes():
        name = scope.get("name", "")
        if name.endswith("-aud") and (scn.AGENT_WORKLOAD in name or scn.TOOL_WORKLOAD in name):
            try:
                admin.delete_client_scope(scope["id"])
            except KeycloakError as exc:
                log.warning("teardown: delete audience client scope %r failed: %s", name, exc)

    # The operator mints a ``rossoctl-keycloak-client-credentials-<hash>`` Secret per client (dynamic
    # hash); sweep by prefix so the namespace is left with none. Tolerant — a query failure or an
    # already-absent Secret is not a teardown error.
    ok, out, _ = _kubectl_try("get", "secret", "-n", NAMESPACE, "-o", "name")
    if ok:
        for ref in out.split():
            if ref.startswith("secret/rossoctl-keycloak-client-credentials-"):
                _kubectl_try("delete", ref, "-n", NAMESPACE, "--ignore-not-found")


def sweep_authpolicies() -> None:
    """Delete every ``AuthorizationPolicy`` CR left in the namespace. ``delete_agent_cr`` removes only
    the agent's own CR (named for the agent workload); this sweeps any other that leaked. ``bundle-service``
    recomposes the namespace bundle in-memory from the live CR set, so removing the CRs self-cleans the
    OPA bundle — there is no separate OPA-bundle CR/ConfigMap to delete. Best-effort + tolerant."""
    ok, out, _ = _kubectl_try("get", "authorizationpolicy", "-n", NAMESPACE, "-o", "name")
    if not ok:
        return
    for ref in out.split():
        if ref.strip():
            _kubectl_try("delete", ref, "-n", NAMESPACE, "--ignore-not-found", timeout=60)


def no_authpolicies_remain() -> bool:
    """True when no ``AuthorizationPolicy`` CR remains in the namespace — the CR half of the pristine
    teardown verification (the Keycloak half is ``workload_clients_present`` being empty)."""
    ok, out, _ = _kubectl_try("get", "authorizationpolicy", "-n", NAMESPACE, "-o", "name")
    return ok and not out.split()


def delete_agent_cr() -> None:
    """Best-effort delete of the agent's ``AuthorizationPolicy`` CR so each run starts and ends from a
    clean policy slate (the CR is named for the agent workload, matched by bundle-service against the
    SPIFFE SA segment). Ignored if absent; a delete failure is logged, not raised."""
    try:
        kubectl(
            "delete",
            "authorizationpolicy",
            scn.AGENT_WORKLOAD,
            "-n",
            NAMESPACE,
            "--ignore-not-found",
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        log.warning("delete_agent_cr: %s", (exc.stderr or exc.output or exc))


# ======================================================================================
# Outbound token-exchange leg prep (runbook Part B) — so OPA is actually consulted outbound
# ======================================================================================
#
# The outbound OPA gate is only reached if ``token-exchange`` first intercepts + exchanges the agent's
# call to github-tool. That needs: (B.1) an outbound route for the github-tool host, (B.2) the agent's
# Keycloak client granted the github-tool audience scope as optional, and (B.3) the agent restarted so
# it reloads the route. Without this the call would pass through unexchanged and never reach OPA.


def _tool_audience() -> str:
    """The RFC 8693 ``audience`` for the github-tool exchange — its SPIFFE ID."""
    return f"spiffe://{TRUST_DOMAIN}/ns/{NAMESPACE}/sa/{scn.TOOL_WORKLOAD}"


def _tool_aud_scope() -> str:
    """The realm client-scope whose audience mapper stamps the github-tool audience (runbook B.2)."""
    return f"agent-{NAMESPACE}-{scn.TOOL_WORKLOAD}-aud"


def ensure_github_tool_route(namespace: str) -> None:
    """Ensure ``authproxy-routes`` carries an outbound route for the github-tool host (runbook B.1).

    Reads the current ``routes.yaml``, appends the github-tool route if it is not already present
    (preserving any existing routes, e.g. the weather route), and patches it back. Creates the
    ConfigMap if it does not exist. Idempotent: a second call is a no-op when the route is present."""
    tool = scn.TOOL_WORKLOAD
    route_block = (
        f'- host: "{tool}"\n  target_audience: "{_tool_audience()}"\n  token_scopes: "openid {_tool_aud_scope()}"\n'
    )
    try:
        current = kubectl(
            "get",
            "configmap",
            "authproxy-routes",
            "-n",
            namespace,
            "-o",
            r"jsonpath={.data.routes\.yaml}",
            timeout=30,
        )
    except subprocess.CalledProcessError:
        current = ""  # ConfigMap (or key) absent — treat as empty, create below

    if f'host: "{tool}"' in current or f"host: {tool}" in current:
        return  # already routed
    new_routes = (current + ("\n" if current.strip() else "") + route_block) if current.strip() else route_block

    patch = {"data": {"routes.yaml": new_routes}}
    try:
        kubectl(
            "patch",
            "configmap",
            "authproxy-routes",
            "-n",
            namespace,
            "--type",
            "merge",
            "-p",
            json.dumps(patch),
            timeout=30,
        )
    except subprocess.CalledProcessError:
        # ConfigMap does not exist yet — create it with just the github-tool route.
        cm = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "authproxy-routes", "namespace": namespace},
            "data": {"routes.yaml": new_routes},
        }
        kubectl("apply", "-f", "-", input_text=json.dumps(cm), timeout=30)


def grant_exchange_scope(admin) -> None:
    """Grant the agent's Keycloak client the github-tool audience scope as **optional** (runbook B.2),
    so the ``client_credentials`` token exchange to the github-tool audience succeeds.

    Resolves the agent client by its SPIFFE ``clientId`` (``.../sa/github-agent``) or its
    ``name`` (``{ns}/github-agent``), and the client scope by name (``agent-{ns}-github-tool-aud``).
    Idempotent — Keycloak's assign-optional-scope is a PUT."""
    from keycloak.exceptions import KeycloakError

    admin.change_current_realm(TEST_REALM)
    aud_scope = _tool_aud_scope()

    client_uuid = None
    for client in admin.get_clients():
        cid = client.get("clientId", "")
        if cid.endswith(f"/sa/{scn.AGENT_WORKLOAD}") or client.get("name") == f"{NAMESPACE}/{scn.AGENT_WORKLOAD}":
            client_uuid = client["id"]
            break
    if client_uuid is None:
        raise AssertionError(
            f"no Keycloak client for {NAMESPACE}/{scn.AGENT_WORKLOAD} in realm {TEST_REALM!r} — is "
            "the agent registered by the operator?"
        )

    scope = next((s for s in admin.get_client_scopes() if s.get("name") == aud_scope), None)
    if scope is None:
        raise AssertionError(
            f"client scope {aud_scope!r} not found in realm {TEST_REALM!r} — is {scn.TOOL_WORKLOAD} "
            "deployed + registered by the operator?"
        )
    try:
        admin.add_client_optional_client_scope(client_uuid, scope["id"], {})
    except KeycloakError as exc:
        log.info("grant_exchange_scope: assign %r returned (benign if already assigned): %s", aud_scope, exc)


def restart_agent(namespace: str) -> None:
    """Restart the agent Deployment so it reloads the outbound route (routes are read once at
    startup — runbook B.3) and its OPA sidecar re-fetches the recomposed bundle on its next poll."""
    kubectl("rollout", "restart", f"deployment/{AGENT_DEPLOYMENT}", "-n", namespace, timeout=60)
    kubectl_rollout_status(f"deployment/{AGENT_DEPLOYMENT}", namespace=namespace, timeout=180)


# ======================================================================================
# Live decisions — mint a user token, send a real request through AuthBridge, classify the plugin
# ======================================================================================


def inbound_decision(ctx: dict, user: str) -> str:
    """Mint a fresh ``user`` token and send a real inbound request through AuthBridge; return the real
    OPA plugin's classified decision (``"allow"`` 200 / ``"deny"`` 403 / ``"error"`` otherwise)."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    code, _ = inbound_probe(token, namespace=ctx["namespace"], agent_service=scn.AGENT_WORKLOAD)
    return inbound_outcome(code)


def resolve_agent_pod() -> str:
    """Resolve the **current** live agent pod (newest Running+Ready, non-terminating — see
    ``resolve_pod``). Re-resolved per outbound probe rather than pinned once at fixture setup: the
    outbound leg ``kubectl exec``s into a specific pod (unlike inbound, which reaches the agent through
    its pod-agnostic Service), so a pod name captured before/during ``restart_agent``'s rolling
    replacement can go stale and every later exec then fails ``NotFound`` -> ``"error"`` forever (issue
    #139). Resolving fresh self-heals across any pod churn."""
    return resolve_pod(f"app.kubernetes.io/name={scn.AGENT_WORKLOAD}", namespace=NAMESPACE)


def outbound_decision(ctx: dict, user: str, tool_bare: str) -> str:
    """Mint a fresh ``user`` token, drive an outbound MCP ``tools/call`` for the **bare** ``tool_bare``
    through AuthBridge's forward proxy (token-exchange → OPA), and return the real plugin's classified
    decision (``"deny"`` for an OPA error frame or 403; ``"allow"`` for a non-OPA 200; ``"error"`` for
    a 503/transport failure)."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    code, body = outbound_probe(token, tool_bare, namespace=ctx["namespace"], agent_pod=resolve_agent_pod())
    return outbound_outcome(code, body)


# ======================================================================================
# Convergence probe — the parametrized readiness signal each policy supplies
# ======================================================================================


@dataclass(frozen=True)
class ReadySignal:
    """One convergence probe: a live decision this run must reach a **definitive** verdict on before
    any assertion. ``onboarded_stack`` polls the whole signal set until every one matches, so each
    signal must be deterministic for its scenario regardless of a stale CR the run replaced (a live
    ``deny`` that the permissive default would flip to ``allow``, or vice-versa, is the tracer that
    proves *this* run's bundle is in force). Polling each to a definitive ``allow``/``deny`` (never
    ``error``) also waits out the post-restart token-exchange 503 window.

    ``kind`` selects the probe: ``"inbound"`` → ``inbound_decision(ctx, subject)``; ``"outbound"`` →
    ``outbound_decision(ctx, subject, tool_bare)`` (``tool_bare`` required). ``expected`` is the
    terminal ``"allow"``/``"deny"`` the signal converges to."""

    kind: str
    subject: str
    expected: str
    tool_bare: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("inbound", "outbound"):
            raise ValueError(f"ReadySignal.kind must be 'inbound' or 'outbound', got {self.kind!r}")
        if self.kind == "outbound" and self.tool_bare is None:
            raise ValueError("an outbound ReadySignal needs a bare tool name (tool_bare=...)")

    def decide(self, ctx: dict) -> str:
        """Send this signal's live probe through AuthBridge and return the plugin's classified verdict."""
        if self.kind == "inbound":
            return inbound_decision(ctx, self.subject)
        return outbound_decision(ctx, self.subject, self.tool_bare)

    def label(self) -> str:
        """Short human-readable probe name for the raw-diagnostics message."""
        if self.kind == "inbound":
            return f"inbound({self.subject})"
        return f"outbound({self.subject},{self.tool_bare})"


def _default_ready_signals(tool_onboarded: bool) -> list[ReadySignal]:
    """The Policy-A convergence signal set:

      * ``dev-user`` reaches the agent (inbound allow),
      * ``test-user`` reaches the agent (inbound allow) — the ``tester -> issue_operations`` grant,
      * ``devops-user`` is blocked (inbound deny — proves the restrictive client-scoped gate is live,
        not the allow-all baseline),
      * ``dev-user``'s outbound ``source-read`` reaches ``allow`` once a tool is onboarded (rungs 2 & 3),
      * ``test-user``'s outbound ``issues-read`` reaches ``allow`` once a tool is onboarded — the
        tester's outbound issue leg.

    **Outbound signals exist only when a tool is onboarded.** The agent-only rung (rung 1) has no tool
    to gate, so there is no real ``agent -> tool`` call and its outbound leg is neither prepared (Part B
    is skipped) nor probed nor asserted — on a tool-less rung token-exchange short-circuits before OPA
    (no ``github-tool`` audience grant), so an outbound "deny" there would be a Keycloak audience
    refusal, not an OPA verdict. Rung 1's empty outbound gate is instead asserted at the unit level
    (grant-set oracle) and by ``test_no_tool_scopes_provisioned``. So the tool-less signal set is
    inbound-only.

    ``test-user`` inbound was ADDED after the 2026-09-10 report: the prior set polled only
    ``dev-user``/``devops-user`` inbound and ``dev-user`` outbound, so a one-sided ``tester``-only
    miss on the inbound ``issue_operations`` grant (the abstract "Testers … full read and write
    access to issues" clause) let the fixture yield "converged" while that gate was missing — the
    gap surfaced as a late test failure instead of a convergence timeout. Polling both of the
    tester's legs (the two projections of the same clause) closes that hole: the harness can no
    longer report convergence while either the inbound agent-scope grant or the outbound tool-scope
    grant for ``tester`` is absent."""
    signals = [
        ReadySignal("inbound", "dev-user", "allow"),
        ReadySignal("inbound", "test-user", "allow"),
        ReadySignal("inbound", "devops-user", "deny"),
    ]
    if tool_onboarded:
        # Both outbound legs only have a terminal ``allow`` once a tool exists to gate; on the
        # agent-only rung there is no tool scope, so neither is a convergence signal (see above).
        signals.append(ReadySignal("outbound", "dev-user", "allow", tool_bare="source-read"))
        signals.append(ReadySignal("outbound", "test-user", "allow", tool_bare="issues-read"))
    return signals


# ======================================================================================
# Per-rung fixture flow — no-workloads slate → deploy (in order, event-driven trigger) → Part B →
# poll bundle → yield → teardown to pristine
# ======================================================================================


def _scrub_to_pristine(admin) -> None:
    """Remove every AIAC registration + stored state a UC-1 run leaves behind, so the realm/cluster
    is back to a no-workloads slate. Shared by the fixture's pre-run reset and its teardown — the two
    ran the same sequence inline. Each step is best-effort (its helper tolerates already-absent
    objects), and the five steps touch independent object classes (Keycloak clients + ``*-aud`` scopes,
    the agent CR, stray AuthorizationPolicy CRs, prefixed roles/scopes, and the Policy Store), so their
    order is not load-bearing. The caller owns undeploying the workloads first and verifying the
    result — this only scrubs registrations + state, it does not delete Deployments."""
    delete_workload_registrations(admin, TEST_REALM)  # clients + *-aud scopes + credentials Secret
    delete_agent_cr()  # this run's (or a prior run's) CR
    sweep_authpolicies()  # any leaked AuthorizationPolicy CR — the OPA bundle self-cleans from the CR set
    cleanup_provisioned(admin, TEST_REALM)  # prefixed roles/scopes (Keycloak)
    clear_policy_store()  # Policy Store SPMs (PV survives redeploys)


@contextmanager
def onboarded_stack(
    workloads: list[str],
    *,
    policy_md: str = scn.POLICY_ABSTRACT,
    default_effect: str = DEFAULT_EFFECT_DENY,
    ready_signals: Sequence[ReadySignal] | None = None,
) -> Iterator[dict]:
    """Run one rung's whole live flow and yield a probe ``ctx`` for its assertions.

    ``ctx`` = ``{"admin", "namespace", "agent_pod", "keycloak_url", "realm", "tool_onboarded"}``.

    Flow (event-driven trigger): skip cleanly (never false-pass) if the OPA pipeline or the event path
    is not wired, or the integration env is unset; **start from a no-workloads slate** (a leftover
    workload + its Keycloak client would stop the fresh deploy from re-firing ``CLIENT_CREATED``, so the
    event would never trigger), provision users/roles + clear the store; **load** the demo image(s) into
    the Kind node (``load_workload_images`` — build-if-absent, the images precondition), then **deploy**
    the given ``workloads`` **in order, one at a time** — each ``kubectl apply`` fires the production trigger
    (operator registers a Keycloak client -> Keycloak ``CLIENT_CREATED`` -> the ``aiac-event-listener``
    SPI publishes on NATS -> the agent consumer runs ``onboard_service``, the same handler the retired
    ``POST /apply`` called) — waiting for each to converge before the next; enable the outbound leg
    (Part B: route + optional client scope + agent restart); then **poll real decisions** until
    ``bundle-service`` + OPA reflect this run's CR (and token-exchange has settled) before yielding.
    Teardown is **full-to-pristine** — the workloads and every registration are removed and the removal
    is verified. The workload order is the rung's identity — e.g. rung 2 passes ``[agent, tool]`` so
    tool onboarding retroactively completes the agent's outbound gate; rung 3 passes ``[tool, agent]``
    and must converge to the same live decisions.

    **Policy-agnostic parametrization (#149).** Every keyword defaults to today's Policy-A behavior,
    so the rung callers (which pass only a positional ``workloads``) are byte-for-byte unchanged, while
    a second policy can drive the very same flow:

    * ``policy_md`` — the ``policy.md`` prose to mount before onboarding (default: Policy A's
      ``POLICY_ABSTRACT``). Forwarded to ``ensure_agent_policy``; a prose change reloads the Controller
      via the existing content-diff rollout.
    * ``default_effect`` — the derived ``AgentPolicyModel.default_effect`` this run onboards under
      (default: ``DEFAULT_EFFECT_DENY``, the shipped deny-by-default). A non-default value is applied to
      the Controller **before** onboarding via ``_set_controller_default_effect`` and **reset to
      ``Deny`` on teardown** so a subsequent Policy-A run on the shared stack is unaffected. ``Deny`` is
      a no-op (the stack is never patched), keeping Policy-A runs from touching the Controller env.
    * ``ready_signals`` — the convergence probe set to poll before yielding (default: the Policy-A
      ``_default_ready_signals``). A policy whose truth differs from Policy A (e.g. denyworld, where
      ``devops-user`` inbound is *allow*, not *deny*) supplies its own deterministic signals so the run
      converges on the right decisions; the raw-diagnostics message is recomputed against them."""
    # Skip gates first — before any cluster mutation (acceptance #4: skip, never false-pass).
    # Gate on the *wiring* only (OPA plugin on both legs, bundle-service, CRD) — NOT on the demo
    # workloads being pre-Running. This is the event-driven flow: the fixture starts from a
    # no-workloads slate and deploys the workloads itself as the onboarding trigger, so requiring
    # them up front would skip every rung on a correctly-wired cluster. A missing/unloadable image or
    # a deploy that never converges surfaces later as a loud RuntimeError from the deploy/convergence
    # poll below — never a skip, never a false pass.
    require_pipeline(namespace=NAMESPACE, workloads=[])
    creds = require_env_or_skip("KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    keycloak_url = creds["KEYCLOAK_URL"]

    admin = connect_admin()
    # Event-path skip gate — placed here (not at the ``require_pipeline`` line) because it needs the
    # admin client to read the realm's events config, and ``launcher`` has no KeycloakAdmin of its own.
    require_event_path(admin=admin, realm=TEST_REALM)

    # Pre-run: start from a NO-WORKLOADS slate. The trigger is event-driven — deploying a workload only
    # re-fires ``CLIENT_CREATED`` if there is no client for it yet, so a leftover workload + its Keycloak
    # client from a prior run would silently swallow the event and onboarding would never trigger. Remove
    # both workloads and every registration first (best-effort, tolerant of already-absent), then poll the
    # clients actually gone before deploying.
    undeploy_workload(scn.AGENT_WORKLOAD)
    undeploy_workload(scn.TOOL_WORKLOAD)
    _scrub_to_pristine(
        admin
    )  # clients + *-aud scopes + agent CR + stray AuthorizationPolicy CRs + roles/scopes + store
    reenable_provisioned_clients(
        admin, TEST_REALM
    )  # undo any prior run's failed-service disable (a no-op once scrubbed)
    if not poll_until(lambda: not workload_clients_present(admin), timeout=DEPLOY_TIMEOUT, interval=5):
        raise RuntimeError(
            f"pre-run cleanup left Keycloak client(s) {workload_clients_present(admin)} for {NAMESPACE!r} — the "
            "fresh deploy would not re-fire CLIENT_CREATED, so event-driven onboarding would never trigger."
        )

    provision_realm_and_users(admin, TEST_REALM)  # BEFORE deploying (PRB reads the role universe when the event fires)
    # username->sub mapper + Direct Access Grants are a one-time realm prereq the fixture does NOT
    # provision; skip (don't fail) if a token can't be minted or its ``sub`` isn't the username.
    verify_subject_mapper(keycloak_url=keycloak_url, realm=TEST_REALM, user="dev-user", password=scn.USER_PASSWORD)

    tool_onboarded = scn.TOOL_WORKLOAD in workloads
    signals = list(ready_signals) if ready_signals is not None else _default_ready_signals(tool_onboarded)
    # A non-default effect is patched onto the Controller here and reset in ``finally``; ``Deny`` (the
    # shipped default) never touches the stack, so Policy-A runs are unchanged. Tracked so teardown
    # only resets what this run actually applied.
    default_effect_applied = default_effect != DEFAULT_EFFECT_DENY
    try:
        if default_effect_applied:
            _set_controller_default_effect(CONTROLLER_NAMESPACE, default_effect)  # BEFORE deploying
        ensure_agent_policy(CONTROLLER_NAMESPACE, policy_md=policy_md)  # mount this run's policy.md BEFORE deploying

        # Minimal probe ctx for the per-workload agent convergence gate: the inbound leg reaches the
        # agent through its pod-agnostic Service, so no ``agent_pod`` is needed yet (it is resolved after
        # Part B for the outbound leg). The full ``ctx`` is assembled below once ``agent_pod`` is known.
        probe_ctx = {"admin": admin, "namespace": NAMESPACE, "keycloak_url": keycloak_url, "realm": TEST_REALM}

        # Fulfill the images precondition BEFORE any deploy: build-if-absent + ``kind load`` the demo
        # image(s) for exactly the workloads this rung deploys. Loading is order-independent, so it is
        # done once here rather than per-iteration; the loop below then only ``kubectl apply``s.
        load_workload_images(workloads)

        # Deploy in the rung's ``workloads`` order, one at a time, converging before the next — each
        # ``deploy_workload`` fires the event-driven trigger (deploy -> operator -> CLIENT_CREATED ->
        # SPI -> NATS -> consumer). The order is the rung's ordering proof.
        for workload in workloads:
            deploy_workload(workload)
            if not wait_for_registration(admin, workload):
                raise RuntimeError(
                    f"operator did not register Keycloak client {NAMESPACE}/{workload!r} within "
                    f"{DEPLOY_TIMEOUT:.0f}s of deploying it — is the event path wired (NATS broker + "
                    "aiac-event-listener SPI)? (The rollout already passed, so the image is loaded.) "
                    "See k8s/opa-kind-runbook.md."
                )
            if workload == scn.AGENT_WORKLOAD:
                # Option A′ — one representative ENFORCED decision proves OPA loaded the agent's bundle.
                # A bare AuthorizationPolicy CR proves only that the operator reconciled, not that the
                # bundle is in force; a live inbound dev-user=allow through AuthBridge->OPA is positive
                # proof. dev-user inbound is deterministically allow on every rung.
                gate = ReadySignal("inbound", "dev-user", "allow")
                if not poll_until(
                    lambda g=gate: g.decide(probe_ctx) == g.expected,
                    timeout=BUNDLE_TIMEOUT,
                    interval=BUNDLE_POLL_INTERVAL,
                ):
                    raise RuntimeError(
                        f"agent did not converge after deploy: {gate.label()}={gate.decide(probe_ctx)!r} "
                        f"(want {gate.expected!r}) within {BUNDLE_TIMEOUT:.0f}s — OPA had not loaded the agent's "
                        "bundle. See k8s/opa-kind-runbook.md and issue #139."
                    )
            else:
                # Tool — a pure target: no CR, no enforced decision of its own, so its convergence signal
                # is that the operator provisioned all of its ``github-tool.*`` client scopes.
                if not poll_until(lambda: tool_scopes_present(admin), timeout=DEPLOY_TIMEOUT, interval=5):
                    raise RuntimeError(
                        f"tool did not converge after deploy: not all {sorted(scn.TOOL_SCOPES)} client scopes "
                        f"present within {DEPLOY_TIMEOUT:.0f}s — did the operator finish registering "
                        f"{scn.TOOL_WORKLOAD}?"
                    )

        # Part B — enable the outbound token-exchange leg so OPA is actually consulted outbound. Done
        # after onboarding so the restarted agent (and its OPA sidecar) picks up both the new route
        # and, on its next poll, the recomposed bundle.
        #
        # Prepared ONLY when this run actually probes outbound (``has_outbound``). The agent-only rung
        # (rung 1) has no tool onboarded, so there is no real ``agent -> tool`` call to make and no
        # outbound signal in its set — its outbound leg has no real-life counterpart, and token-exchange
        # would short-circuit before OPA anyway (no ``github-tool`` audience grant, since the operator
        # creates ``agent-{ns}-github-tool-aud`` only on TOOL deploy). So on a tool-less rung Part B is
        # skipped entirely: no outbound route, no restart. Its inbound gate already converged in the
        # per-workload loop above, and skipping the restart means rung 1 asserts the exact bundle the
        # live event-driven onboard produced (no restart papering over a bad compose).
        #
        # When there IS an outbound leg: add the route so the forward proxy intercepts the github-tool
        # call and runs token-exchange, grant the agent client the ``*-aud`` scope (only ever present
        # once the tool is deployed) so the exchange succeeds and OPA is reached, then restart the agent
        # so it reloads the route and re-fetches the recomposed bundle.
        has_outbound = any(sig.kind == "outbound" for sig in signals)
        if has_outbound:
            ensure_github_tool_route(NAMESPACE)
            if tool_onboarded:
                grant_exchange_scope(admin)
            restart_agent(NAMESPACE)
        # Resolved once for the ctx contract, but the live outbound path re-resolves per probe
        # (``resolve_agent_pod``) so a pod replaced after this point can't poison the whole run (#139).
        agent_pod = resolve_agent_pod()

        ctx = {
            "admin": admin,
            "namespace": NAMESPACE,
            "agent_pod": agent_pod,
            "keycloak_url": keycloak_url,
            "realm": TEST_REALM,
            "tool_onboarded": tool_onboarded,
        }

        # Wait for bundle-service + OPA to reflect THIS run's CR (and token-exchange to settle) before
        # any assertion. The ``signals`` set (this policy's ``ready_signals``, or the Policy-A default)
        # is polled until every probe reaches its terminal verdict — each deterministic for its
        # scenario regardless of a stale CR (which the run replaced), and each polled to a *definitive*
        # allow/deny (not ``error``) so we also wait out the post-restart token-exchange 503 window.
        def _ready() -> bool:
            return all(sig.decide(ctx) == sig.expected for sig in signals)

        if not poll_until(_ready, timeout=BUNDLE_TIMEOUT, interval=BUNDLE_POLL_INTERVAL):
            # Surface the RAW outbound (code, body) — not just the classified outcome — so a stalled
            # run is self-diagnosing (issue #139). The classifier collapses three very different
            # failures into ``"error"``; the raw ``(code, body)`` tells them apart in one shot:
            #   * ``code=None`` + body ``"outbound probe exec failed: ..."`` — the *probe's* ``kubectl
            #     exec`` failed (e.g. the agent pod was replaced by a restart and its name went stale,
            #     ``NotFound``). A harness/pod issue, not the pipeline — OPA was never reached.
            #   * ``code=503`` — the ``token-exchange`` leg failed upstream (audience refused, IdP
            #     unreachable), so OPA was never consulted.
            #   * a genuine OPA policy stall can't show as ``"error"`` at all: it surfaces as ``"deny"``
            #     under deny-by-default (HTTP 200 + an OPA error frame), because the generated Rego
            #     carries ``default allow := false``.
            # The observed-vs-expected line is recomputed against *this run's* signals so a denyworld
            # (or any parametrized) run diagnoses itself, not a hardcoded Policy-A probe.
            observed = "; ".join(f"{sig.label()}={sig.decide(ctx)!r}(want {sig.expected!r})" for sig in signals)
            # Re-resolve the pod fresh here (not the possibly-stale ``ctx["agent_pod"]``) so the raw
            # line reflects the *current* live pod. Dump the raw (code, body) for the first outbound
            # signal — the leg where the #139 stale-pod / 503 failures actually show up.
            raw_line = ""
            ob_sig = next((s for s in signals if s.kind == "outbound"), None)
            if ob_sig is not None:
                ob_token = mint_token(
                    ob_sig.subject, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"]
                )
                ob_code, ob_body = outbound_probe(
                    ob_token, ob_sig.tool_bare, namespace=ctx["namespace"], agent_pod=resolve_agent_pod()
                )
                raw_line = f" [raw {ob_sig.label()}: HTTP {ob_code}, body={ob_body[:300]!r}]"
            raise RuntimeError(
                f"live pipeline did not converge within {BUNDLE_TIMEOUT:.0f}s after onboarding "
                f"{workloads} + Part B: {observed}.{raw_line} code=None + 'exec failed' body = a "
                "stale/gone agent pod (harness); 503 = token-exchange never came up (OPA not reached); "
                "under deny-by-default a real policy stall reads 'deny', never 'error' — see "
                "k8s/opa-kind-runbook.md and issue #139."
            )
        yield ctx
    finally:
        # Teardown — full-to-pristine, best-effort per step (each helper tolerates already-absent objects).
        if default_effect_applied:
            # Reset the shared stack to the shipped default so a later Policy-A run is unaffected.
            _set_controller_default_effect(CONTROLLER_NAMESPACE, DEFAULT_EFFECT_DENY)
        for workload in reversed(workloads):  # undeploy in reverse deploy order
            undeploy_workload(workload)
        # Explicit scrub — do not trust an unverified operator cascade. Same reset the pre-run slate runs.
        _scrub_to_pristine(admin)
        # Verify pristine: both clients gone AND no AuthorizationPolicy CR remains. A leaked footprint is
        # a test failure, not silent drift — but do not mask a failure already propagating out of the try.
        if not poll_until(
            lambda: not workload_clients_present(admin) and no_authpolicies_remain(), timeout=DEPLOY_TIMEOUT, interval=5
        ):
            msg = (
                f"teardown did not restore pristine: Keycloak client(s) still present="
                f"{workload_clients_present(admin)}, AuthorizationPolicy CR(s) remain={not no_authpolicies_remain()} "
                f"in {NAMESPACE!r}. See handoff 03 teardown (full-to-pristine)."
            )
            if sys.exc_info()[0] is not None:
                log.error("%s [suppressed — a prior error is propagating]", msg)
            else:
                raise RuntimeError(msg)
