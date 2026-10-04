"""Shared harness for the UC-1 onboarding integration-test ladder (rungs 1–3, 5 and 6).

Spec: ``docs/testing/uc1-onboarding-pipeline.md``; live loop shape (handoff 08):
``k8s/opa-kind-runbook.md``. The evaluator is now the **deployed AuthBridge OPA plugin**, not a
standalone OPA-CLI run over dumped ``.rego`` — there is no ``.rego`` dump and no ``opa`` binary here.

**One CR per managed service (D20).** Every onboarded service — the tool included — has its own
``AuthorizationPolicy`` CR (name and namespace from its clientId, label
``app.kubernetes.io/managed-by: aiac-pdp-policy-writer``) with both request packages. The global
combiner denies a pod that has no client CR, so a missing CR means deny. Under the **target side**
(the default enforcement side) each callee checks the access to itself in its own inbound OPA: the
agent's outbound is a pass-through (``allow := true``), and github-tool's inbound decides each tool
call. Under the **agent side** the agent's outbound decides and github-tool has a pass-through CR.
The harness reads the live side (``live_enforcement_side``) and selects only the side-dependent
assertions (``cr_matches_side``, ``deny_origin``); the verdict tables do not depend on the side.

Every rung follows the same shape against **one** live rossoctl/Kind cluster with the AuthBridge OPA
pipeline wired into both legs:

    start from a no-workloads slate (undeploy + delete registrations) + policy-store clear
      → deploy the rung's workloads in order, one at a time — each deploy fires the EVENT-DRIVEN
        trigger (operator registers a Keycloak client → Keycloak CLIENT_CREATED → the aiac-event-listener
        SPI publishes on NATS → the agent consumer runs onboard_service, upserting the AuthorizationPolicy
        CR of each affected service on the live API), converging before the next
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
* **CRs** — ``delete_workload_crs`` (the agent's and the tool's CR) / ``sweep_authpolicies`` (every
  other CR in the namespace) / ``delete_authpolicy`` (one CR, raising).
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
* **CR readers and the enforcement side** — ``authpolicy_policies`` (one CR's ``{path: rego}``),
  ``aiac_crs`` / ``aiac_cr_uids`` (every CR with the managed-by label), ``cr_has_request_packages``,
  ``cr_has_grants``, ``rego_is_pass_through``, ``live_enforcement_side``, ``cr_matches_side`` /
  ``cr_side_mismatches``, and ``deny_origin`` + ``outbound_raw`` (where a deny comes from).
* **Failure path (rung 5)** — ``pristine_stack`` (the slate + teardown of ``onboarded_stack`` with no
  deploy / convergence, for a flow that must not converge), ``controller_llm_unusable`` (the LLM-seam
  failure injection, restored on exit), ``publish_service_event`` (re-fire the onboarding trigger for
  an existing client), and the quarantine readers (``workload_client``, ``spm_present``,
  ``controller_logs``) plus the MCP session probe ``mcp_session_decisions``.
* **Controller restart (rung 6)** — ``restart_controller`` (rollout restart + wait until no old pod
  is left; the resync at start ends before the new pod is Ready).

It imports only stdlib + ``requests`` + ``launcher`` + the pure-data ``scenario_uc1`` (never
``aiac``), so it is importable before the env-before-import dance, exactly like ``scenario_uc1`` and
``launcher``. It defines **no** ``test_*`` functions, so pytest does not collect it.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
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
    DENY_ORIGIN_AGENT_OUTBOUND,
    DENY_ORIGIN_TOOL_INBOUND,
    _kubectl_try,
    deny_origin,
    inbound_outcome,
    inbound_probe,
    kubectl,
    kubectl_apply,
    kubectl_delete,
    kubectl_rollout_status,
    mint_token,
    notification_outcome,
    outbound_outcome,
    outbound_probe,
    outbound_session_probe,
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
# mount). The onboarding trigger is event-driven (deploy fires it), so the harness no
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

# The Controller's start sequence (read the side, start check #4, then the resync under the PCE lock)
# ends before uvicorn serves, so a restarted Controller is Ready only after its resync. This budget
# (seconds) covers that start, for every Controller rollout the harness waits on.
CONTROLLER_RESTART_TIMEOUT = float(os.environ.get("AIAC_CONTROLLER_RESTART_TIMEOUT", "300"))

# --- Enforcement side (D16) ---------------------------------------------------------------
# ``AIAC_ENFORCEMENT_SIDE`` in the Controller's ConfigMap selects where the check runs. The harness
# only reads it (``live_enforcement_side``); an absent key means the default, ``target-side``.
AGENT_CONFIGMAP = os.environ.get("AIAC_AGENT_CONFIGMAP", "aiac-agent-config")
ENFORCEMENT_SIDE_KEY = "AIAC_ENFORCEMENT_SIDE"
TARGET_SIDE = "target-side"
AGENT_SIDE = "agent-side"

# The place a denied tool call comes from under each side (``deny_origin``): github-tool's inbound
# under target side (an HTTP 403 relayed by the agent's pass-through outbound), the agent's outbound
# under agent side (a JSON-RPC error frame at HTTP 200).
SIDE_ENFORCEMENT_POINT: dict[str, str] = {
    TARGET_SIDE: DENY_ORIGIN_TOOL_INBOUND,
    AGENT_SIDE: DENY_ORIGIN_AGENT_OUTBOUND,
}

# The label the OPA Policy Writer puts on every CR it owns (``_MANAGED_BY_LABEL`` in the writer).
MANAGED_BY_SELECTOR = "app.kubernetes.io/managed-by=aiac-pdp-policy-writer"

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

# A tool's onboarding ends only after the bootstrap CR reaches its OPA sidecar (the discovery waits up
# to ``AIAC_MCP_DISCOVERY_READY_TIMEOUT``, default 180 s, for the bundle poll), Provision, and the real
# PRB (LLM). The tool's convergence gate polls up to this budget (``AIAC_ONBOARD_TIMEOUT``, seconds).
ONBOARD_TIMEOUT = float(os.environ.get("AIAC_ONBOARD_TIMEOUT", "600"))

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
            kubectl_rollout_status(
                f"deployment/{CONTROLLER_DEPLOYMENT}", namespace=namespace, timeout=CONTROLLER_RESTART_TIMEOUT
            )
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
    kubectl_rollout_status(
        f"deployment/{CONTROLLER_DEPLOYMENT}", namespace=namespace, timeout=CONTROLLER_RESTART_TIMEOUT
    )


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
    — the Provision half of the tool's convergence gate (``tool_onboarding_state``)."""
    admin.change_current_realm(TEST_REALM)
    names = {s.get("name") for s in admin.get_client_scopes()}
    return all(scope in names for scope in scn.TOOL_SCOPES)


def tool_onboarding_state(admin) -> dict[str, bool]:
    """The three facts of the tool's convergence gate, each ``True`` when it holds:

    * ``scopes`` — every ``github-tool.*`` client scope is provisioned (Provision ran);
    * ``spm`` — ``SPM(github-tool)`` is in the Policy Store. The PCE stores the focus SPM also when it
      has zero rules (D21), and the bootstrap CR stores none, so this is the proof that the PRB and
      ``compute_and_apply`` ran — not only the bootstrap;
    * ``cr`` — github-tool's own CR is present with both request packages (D20).

    The bootstrap CR is present before Provision, so the CR alone does not prove the final CR; with
    the SPM it does (the PCE writes the CR right after the store write). A live decision on github-tool's
    inbound needs the outbound token-exchange leg, which the fixture prepares later, so this gate reads
    state; the live proof is the final convergence poll."""
    client = workload_client(admin, scn.TOOL_WORKLOAD)
    return {
        "scopes": tool_scopes_present(admin),
        "spm": bool(client) and spm_present(client["clientId"]),
        "cr": cr_has_request_packages(authpolicy_policies(scn.TOOL_WORKLOAD)),
    }


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
    """Delete every ``AuthorizationPolicy`` CR left in the namespace. ``delete_workload_crs`` removes
    only the two workloads' own CRs (named for each workload); this sweeps any other that leaked.
    ``bundle-service`` recomposes the namespace bundle in-memory from the live CR set, so removing the
    CRs self-cleans the OPA bundle — there is no separate OPA-bundle CR/ConfigMap to delete.
    Best-effort + tolerant."""
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


def delete_authpolicy(name: str) -> None:
    """Delete the ``AuthorizationPolicy`` CR ``name`` in the namespace (absent is fine). Raises on any
    other failure — a caller that needs the CR gone (rung 6, the D20 no-CR deny) must not go on when the
    delete did not happen."""
    kubectl("delete", "authorizationpolicy", name, "-n", NAMESPACE, "--ignore-not-found", timeout=60)


def delete_workload_crs() -> None:
    """Best-effort delete of every AIAC ``AuthorizationPolicy`` CR of the two workloads — the agent's
    and the tool's (D20: every managed service has its own CR) — so each run starts and ends from a
    clean policy slate. Each CR is named for its workload (``identity_ref`` of the clientId: the SPIFFE
    SA segment, which bundle-service matches). Ignored if absent; a delete failure is logged, not
    raised."""
    for workload in (scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD):
        try:
            delete_authpolicy(workload)
        except subprocess.CalledProcessError as exc:
            log.warning("delete_workload_crs(%s): %s", workload, (exc.stderr or exc.output or exc))


# ======================================================================================
# Outbound token-exchange leg prep (runbook Part B) — so OPA is actually consulted outbound
# ======================================================================================
#
# The tool check is only reached if ``token-exchange`` first intercepts + exchanges the agent's call to
# github-tool. That needs: (B.1) an outbound route for the github-tool host, (B.2) the agent's Keycloak
# client granted the github-tool audience scope as optional, and (B.3) the agent restarted so it
# reloads the route. Without this the call would pass through unexchanged and never reach OPA. Under
# target side the leg is still necessary: the agent's outbound is a pass-through, but github-tool's
# inbound ``jwt-validation`` accepts only a token whose audience is github-tool, so ``token-exchange``
# must mint it.


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


def outbound_raw(ctx: dict, user: str, tool_bare: str) -> tuple[int | None, str]:
    """Mint a fresh ``user`` token, drive an outbound MCP ``tools/call`` for the **bare** ``tool_bare``
    through AuthBridge's forward proxy, and return the raw ``(http_code, body)`` — for ``deny_origin``
    and for diagnostics."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    return outbound_probe(token, tool_bare, namespace=ctx["namespace"], agent_pod=resolve_agent_pod())


def outbound_decision(ctx: dict, user: str, tool_bare: str) -> str:
    """Drive one outbound ``tools/call`` (``outbound_raw``) and return the real plugin's classified
    decision (``outbound_outcome``): ``"deny"`` for an OPA verdict — github-tool's inbound 403 under
    target side, the agent's outbound JSON-RPC error frame under agent side; ``"allow"`` for a non-OPA
    200; ``"error"`` for a token-exchange refusal, a 503 or a transport failure."""
    return outbound_outcome(*outbound_raw(ctx, user, tool_bare))


def outbound_deny_probe(ctx: dict, user: str, tool_bare: str) -> dict:
    """Drive one outbound ``tools/call`` and return ``{"decision", "origin", "code", "body"}``:
    ``decision`` from ``outbound_outcome``, and ``origin`` from ``deny_origin`` — where a deny comes
    from (``DENY_ORIGIN_TOOL_INBOUND`` / ``DENY_ORIGIN_AGENT_OUTBOUND``; ``None`` when it is not an OPA
    deny). Compare ``origin`` with ``SIDE_ENFORCEMENT_POINT[ctx["side"]]``."""
    code, body = outbound_raw(ctx, user, tool_bare)
    return {"decision": outbound_outcome(code, body), "origin": deny_origin(code, body), "code": code, "body": body}


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
    the agent's and the tool's CR, stray AuthorizationPolicy CRs, prefixed roles/scopes, and the Policy
    Store), so their order is not load-bearing. The caller owns undeploying the workloads first and
    verifying the result — this only scrubs registrations + state, it does not delete Deployments."""
    delete_workload_registrations(admin, TEST_REALM)  # clients + *-aud scopes + credentials Secret
    delete_workload_crs()  # this run's (or a prior run's) agent and tool CRs
    sweep_authpolicies()  # any leaked AuthorizationPolicy CR — the OPA bundle self-cleans from the CR set
    cleanup_provisioned(admin, TEST_REALM)  # prefixed roles/scopes (Keycloak)
    clear_policy_store()  # Policy Store SPMs (PV survives redeploys)


@contextmanager
def onboarded_stack(
    workloads: list[str],
    *,
    policy_md: str = scn.POLICY_ABSTRACT,
    ready_signals: Sequence[ReadySignal] | None = None,
) -> Iterator[dict]:
    """Run one rung's whole live flow and yield a probe ``ctx`` for its assertions.

    ``ctx`` = ``{"admin", "namespace", "agent_pod", "keycloak_url", "realm", "tool_onboarded", "side"}``
    (``side`` = ``live_enforcement_side()``, read once at setup).

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
    tool onboarding completes the tool check (under target side it writes github-tool's own CR with
    both gates; under agent side it completes the agent's outbound gate); rung 3 passes
    ``[tool, agent]`` and must converge to the same live decisions.

    **Policy-agnostic parametrization (#149).** Every keyword defaults to today's Policy-A behavior,
    so the rung callers (which pass only a positional ``workloads``) are byte-for-byte unchanged, while
    a second policy can drive the very same flow:

    * ``policy_md`` — the ``policy.md`` prose to mount before onboarding (default: Policy A's
      ``POLICY_ABSTRACT``). Forwarded to ``ensure_agent_policy``; a prose change reloads the Controller
      via the existing content-diff rollout.
    * ``ready_signals`` — the convergence probe set to poll before yielding (default: the Policy-A
      ``_default_ready_signals``). A policy whose truth differs from Policy A (e.g. denyworld, where
      ``devops-user`` inbound is *allow*, not *deny*) supplies its own deterministic signals so the run
      converges on the right decisions; the raw-diagnostics message is recomputed against them."""
    # Skip gates first — before any cluster mutation (acceptance #4: skip, never false-pass).
    # Gate on the *wiring* only (OPA plugin on both legs, bundle-service, CRD, the changed combiner of
    # D20) — NOT on the demo workloads being pre-Running. This is the event-driven flow: the fixture starts from a
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
    side = live_enforcement_side()  # read-only; the suite runs under the live side

    # Pre-run: start from a NO-WORKLOADS slate. The trigger is event-driven — deploying a workload only
    # re-fires ``CLIENT_CREATED`` if there is no client for it yet, so a leftover workload + its Keycloak
    # client from a prior run would silently swallow the event and onboarding would never trigger. Remove
    # both workloads and every registration first (best-effort, tolerant of already-absent), then poll the
    # clients actually gone before deploying.
    undeploy_workload(scn.AGENT_WORKLOAD)
    undeploy_workload(scn.TOOL_WORKLOAD)
    _scrub_to_pristine(
        admin
    )  # clients + *-aud scopes + workload CRs + stray AuthorizationPolicy CRs + roles/scopes + store
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
    try:
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
                # proof. dev-user inbound is deterministically allow on every rung. The changed combiner
                # denies the agent pod until its own CR is loaded (D20), so the allow cannot come from a
                # missing CR.
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
                # Tool — it has its own CR (D20): under target side its inbound decides the tool calls,
                # under agent side it is a pass-through CR. A live decision on its inbound needs the
                # outbound leg (Part B, below), so the per-workload gate reads state instead: the scopes
                # provisioned, SPM(github-tool) stored (the PRB ran, not only the bootstrap), and the CR
                # present with both request packages (``tool_onboarding_state``).
                seen = {"state": {}}

                def _tool_converged() -> bool:
                    seen["state"] = tool_onboarding_state(admin)
                    return all(seen["state"].values())

                if not poll_until(_tool_converged, timeout=ONBOARD_TIMEOUT, interval=5):
                    raise RuntimeError(
                        f"tool did not converge after deploy within {ONBOARD_TIMEOUT:.0f}s: {seen['state']} "
                        f"(scopes = all of {sorted(scn.TOOL_SCOPES)} provisioned; spm = SPM({scn.TOOL_WORKLOAD}) "
                        f"stored; cr = its AuthorizationPolicy CR with both request packages). A failed "
                        "onboarding check (D30: the tool pod has no authbridge-proxy sidecar — injectTools; no "
                        "opa / mcp-parser in the namespace inbound pipeline; an httpGet probe) leaves no CR — "
                        "see the Controller log and k8s/opa-kind-enable.sh."
                    )

        # Part B — enable the outbound token-exchange leg so the tool check is actually reached (under
        # target side github-tool's inbound OPA, which accepts only a token with its audience; under
        # agent side the agent's outbound OPA). Done after onboarding so the restarted agent (and its
        # OPA sidecar) picks up both the new route and, on its next poll, the recomposed bundle.
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
            "side": side,
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
            #     under deny-by-default (target side: github-tool's inbound HTTP 403 with an OPA body;
            #     agent side: HTTP 200 + an OPA error frame), because the generated Rego carries
            #     ``default allow := false``.
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


# ======================================================================================
# AuthorizationPolicy CRs, stored SPMs and the enforcement side — read-only views for every rung
# ======================================================================================
#
# Every managed service has its own CR (D20) with exactly the two request packages
# (``aiac.pdp.service.policy.opa.main._build_cr``); there is no response package. The shapes by side
# (spec § *CR end state for each side*): a **rules-based** package carries ``default allow := false``
# (D25); a **pass-through** package is only ``allow := true`` (D24).
#
#   side         github-agent CR                           github-tool CR
#   target side  inbound: rules + grants; outbound: pass     inbound: rules + grants (D26); outbound: pass
#   agent side   inbound: rules + grants; outbound: rules    inbound and outbound: pass (a pass-through CR)
#
# A service with no stored SPM (for example after a quarantine) has no CR, and the combiner denies it.

CR_INBOUND_PATH = "inbound/request.rego"
CR_OUTBOUND_PATH = "outbound/request.rego"
CR_REQUEST_PATHS = frozenset({CR_INBOUND_PATH, CR_OUTBOUND_PATH})

# The Rego bindings that carry the grants of each rules-based package. An empty one renders as ``[]`` /
# ``{}`` (``rego._render_list`` / ``_render_map``).
#   * agent inbound (both sides, agent-level, D26a): the agent's own scopes + the user gate;
#   * tool inbound (target side, D26): the user gate + the calling-agent gate, keyed by the bare tool;
#   * agent outbound (agent side only): the user→tool gate + the per-target capability gate.
AGENT_INBOUND_GRANT_BINDINGS = ("agent_scopes", "subject_role_allow_scopes")
TOOL_INBOUND_GRANT_BINDINGS = ("subject_role_allow_scopes", "source_role_allow_scopes")
AGENT_SIDE_OUTBOUND_GRANT_BINDINGS = ("subject_role_allow_scopes", "target_allow_scopes")

# The kind of a service, for the CR shape. The demo agent and tool are the two kinds.
AGENT_KIND = "agent"
TOOL_KIND = "tool"
WORKLOAD_KIND: dict[str, str] = {scn.AGENT_WORKLOAD: AGENT_KIND, scn.TOOL_WORKLOAD: TOOL_KIND}


def workload_client(admin, workload: str) -> dict | None:
    """The Keycloak client representation (``id`` UUID, ``clientId``, ``enabled``, ``attributes``) of
    ``{ns}/{workload}``, keyed on the client ``name`` like ``wait_for_registration``; ``None`` if absent."""
    admin.change_current_realm(TEST_REALM)
    return next((c for c in admin.get_clients() if c.get("name") == f"{NAMESPACE}/{workload}"), None)


def spm_present(client_id: str) -> bool:
    """Whether the Policy Store holds an SPM for the service keyed ``client_id`` (the SPM key is the
    client's ``clientId``) — that is, whether the service is in the **managed set** (D21).
    ``GET /policy/services/{id}`` takes the id as unpadded base64url
    (``aiac.policy.model_store.keying.encode_service_id``): 200 -> True, 404 -> False; any other
    answer raises, so an unreachable store is never read as "no SPM"."""
    encoded = base64.urlsafe_b64encode(client_id.encode("utf-8")).decode("ascii").rstrip("=")
    with port_forward(
        STORE_TARGET,
        namespace=STORE_NAMESPACE,
        local_port=STORE_LOCAL_PORT,
        remote_port=STORE_REMOTE_PORT,
        ready_url=f"http://127.0.0.1:{STORE_LOCAL_PORT}/health",
    ) as base_url:
        resp = requests.get(f"{base_url}/policy/services/{encoded}", timeout=30)
    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    raise AssertionError(f"GET /policy/services/<{client_id}> returned HTTP {resp.status_code}: {resp.text[:300]}")


def authpolicy_policies(name: str) -> dict[str, str] | None:
    """The ``AuthorizationPolicy`` CR ``name``'s policies as ``{path: rego}`` (``spec.policies[]``), or
    ``None`` when no such CR exists. ``--ignore-not-found`` makes an absent CR an empty output, so an
    unreachable API still raises instead of reading as "no CR"."""
    out = kubectl("get", "authorizationpolicy", name, "-n", NAMESPACE, "-o", "json", "--ignore-not-found", timeout=30)
    if not out.strip():
        return None
    spec = json.loads(out).get("spec", {})
    return {p.get("path", ""): p.get("content", "") for p in spec.get("policies", [])}


def _aiac_cr_items() -> list[dict]:
    """Every ``AuthorizationPolicy`` CR with the writer's managed-by label, cluster-wide — the set the
    writer's ``PUT /policy`` replaces (it deletes by that label)."""
    out = kubectl("get", "authorizationpolicy", "-A", "-l", MANAGED_BY_SELECTOR, "-o", "json", timeout=30)
    return json.loads(out).get("items", [])


def _cr_key(item: dict) -> str:
    meta = item.get("metadata", {})
    return f"{meta.get('namespace', '')}/{meta.get('name', '')}"


def aiac_crs() -> dict[str, dict[str, str]]:
    """Every AIAC CR (the managed-by label ``app.kubernetes.io/managed-by: aiac-pdp-policy-writer``),
    as ``{"<namespace>/<name>": {path: rego}}`` (``spec.policies``). Raises when the API is unreachable."""
    return {
        _cr_key(item): {p.get("path", ""): p.get("content", "") for p in item.get("spec", {}).get("policies", [])}
        for item in _aiac_cr_items()
    }


def aiac_cr_uids() -> dict[str, str]:
    """Every AIAC CR as ``{"<namespace>/<name>": metadata.uid}``. A CR that is deleted and created again
    gets a new uid, so an unchanged uid proves the object was only updated in place (or not at all)."""
    return {_cr_key(item): item.get("metadata", {}).get("uid", "") for item in _aiac_cr_items()}


def cr_key(workload: str) -> str:
    """The ``aiac_crs`` key of ``workload``'s CR in the demo namespace."""
    return f"{NAMESPACE}/{workload}"


def rego_binding_empty(rego: str, var: str) -> bool | None:
    """Whether the top-level Rego binding ``var := …`` is an empty list/map (``[]`` / ``{}``) — the
    form ``rego._render_list`` / ``_render_map`` emit for no entries. ``None`` when ``var`` is not
    bound at all (a CR format change, surfaced by the caller rather than read as empty)."""
    if not re.search(rf"^{re.escape(var)}\s*:=", rego, re.M):
        return None
    return re.search(rf"^{re.escape(var)}\s*:=\s*(\[\s*\]|\{{\s*\}})", rego, re.M) is not None


def _rego_lines(rego: str) -> list[str]:
    """The non-blank, non-comment lines of ``rego``, stripped."""
    return [ln.strip() for ln in rego.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def rego_is_pass_through(rego: str | None) -> bool:
    """True when ``rego`` is a **pass-through** package (D24): a ``package`` line, ``import rego.v1``,
    and ``allow := true`` — nothing else. The pass-throughs are the only ALLOW packages (D25)."""
    lines = _rego_lines(rego or "")
    if not lines or not lines[0].startswith("package "):
        return False
    return [ln for ln in lines[1:] if ln != "import rego.v1"] == ["allow := true"]


def rego_is_rules_based(rego: str | None) -> bool:
    """True when ``rego`` is a **rules-based** package: ``default allow := false`` (always DENY, D25)
    and not a pass-through."""
    return bool(rego) and "default allow := false" in _rego_lines(rego) and not rego_is_pass_through(rego)


def cr_has_request_packages(policies: dict[str, str] | None) -> bool:
    """True when ``policies`` is a present CR with exactly the two request packages
    (``inbound/request.rego`` and ``outbound/request.rego``) and no response package (D20)."""
    return bool(policies) and set(policies) == CR_REQUEST_PATHS


def cr_has_grants(policies: dict[str, str] | None, kind: str = AGENT_KIND) -> bool:
    """True when ``policies`` is a CR whose **inbound** package carries grants:

    * ``kind="agent"`` — the agent's scopes and some user role reaching one of them (non-empty
      ``agent_scopes`` + ``subject_role_allow_scopes``), under both sides;
    * ``kind="tool"`` — the target-side tool inbound (D26): the user gate and the calling-agent gate
      (non-empty ``subject_role_allow_scopes`` + ``source_role_allow_scopes``)."""
    if not policies:
        return False
    inbound = policies.get(CR_INBOUND_PATH, "")
    bindings = AGENT_INBOUND_GRANT_BINDINGS if kind == AGENT_KIND else TOOL_INBOUND_GRANT_BINDINGS
    return all(rego_binding_empty(inbound, v) is False for v in bindings)


def live_enforcement_side() -> str:
    """The live **enforcement side** (D16): ``AIAC_ENFORCEMENT_SIDE`` in the Controller's ConfigMap
    (``aiac-agent-config`` in the Controller namespace); an absent or empty key means the default,
    ``target-side``. Read-only — the harness never changes it here. Raises on an unknown value (the
    Controller does not start with one) or when the ConfigMap cannot be read."""
    out = kubectl(
        "get",
        "configmap",
        AGENT_CONFIGMAP,
        "-n",
        CONTROLLER_NAMESPACE,
        "-o",
        f"jsonpath={{.data.{ENFORCEMENT_SIDE_KEY}}}",
        timeout=30,
    )
    side = out.strip() or TARGET_SIDE
    if side not in SIDE_ENFORCEMENT_POINT:
        raise RuntimeError(
            f"unknown {ENFORCEMENT_SIDE_KEY}={side!r} in configmap/{AGENT_CONFIGMAP} ({CONTROLLER_NAMESPACE}); "
            f"want {TARGET_SIDE!r} or {AGENT_SIDE!r}"
        )
    return side


def cr_side_mismatches(policies: dict[str, str] | None, kind: str, side: str) -> list[str]:
    """Each way the CR ``policies`` of a service of ``kind`` (``"agent"`` / ``"tool"``) differs from
    the shape of ``side`` (the table above); an empty list means the CR matches. A missing CR is one
    mismatch (every managed service has a CR, D20)."""
    if not policies:
        return ["no CR"]
    problems: list[str] = []
    if not cr_has_request_packages(policies):
        problems.append(f"packages {sorted(policies)} (want exactly {sorted(CR_REQUEST_PATHS)})")
    inbound, outbound = policies.get(CR_INBOUND_PATH), policies.get(CR_OUTBOUND_PATH)
    if side == AGENT_SIDE and kind == TOOL_KIND:
        # A pass-through CR: the agent's outbound decides the calls to the tool.
        if not rego_is_pass_through(inbound):
            problems.append("inbound is not a pass-through")
        if not rego_is_pass_through(outbound):
            problems.append("outbound is not a pass-through")
        return problems
    if not rego_is_rules_based(inbound):
        problems.append("inbound is not rules-based (default allow := false)")
    elif not cr_has_grants(policies, kind):
        problems.append(f"inbound has no grants ({kind})")
    if side == AGENT_SIDE:  # the agent's outbound: per-tool checks + the MCP session rule
        if not rego_is_rules_based(outbound):
            problems.append("outbound is not rules-based")
        elif not all(rego_binding_empty(outbound or "", v) is False for v in AGENT_SIDE_OUTBOUND_GRANT_BINDINGS):
            problems.append("outbound has no grants")
    elif not rego_is_pass_through(outbound):  # target side: the callee decides (D24)
        problems.append("outbound is not a pass-through")
    return problems


def cr_matches_side(policies: dict[str, str] | None, kind: str, side: str) -> bool:
    """True when the CR ``policies`` of a service of ``kind`` has the shape of ``side``
    (``cr_side_mismatches`` is empty)."""
    return not cr_side_mismatches(policies, kind, side)


# ======================================================================================
# Failure path (rung 5) and Controller restart (rung 6) — LLM-seam injection, re-fired trigger,
# Controller rollouts, MCP session probe, pristine stack
# ======================================================================================
#
# A failed onboarding does not converge to a live allow, so ``onboarded_stack`` (which polls for the
# happy path) cannot drive it. These helpers let a failure-path flow compose the same building blocks:
# the pristine slate + teardown (``pristine_stack``), a Controller-side failure injection that is always
# undone (``controller_llm_unusable``), a re-fire of the onboarding trigger for an existing client
# (``publish_service_event``), and the read-only views above of the state a rollback + quarantine
# leaves (the quarantine deletes the CR under both sides, D20). Every Controller rollout runs the
# resync at start (D28) before the new pod is Ready; ``restart_controller`` is that rollout alone.

# The Controller pod selector (``app: aiac-agent`` in ``k8s/agent-deployment.yaml``) and the PRB's
# endpoint env (``aiac.agent.llm.load_llm_settings`` reads the bare ``LLM_BASE_URL``).
CONTROLLER_SELECTOR = os.environ.get("AIAC_CONTROLLER_SELECTOR", f"app={CONTROLLER_DEPLOYMENT}")
LLM_BASE_URL_ENV = "LLM_BASE_URL"

# The PRB endpoint the failure injection points the Controller at: a path the Controller's own FastAPI
# app (port 7070, same pod) does not serve, so every chat-completions call gets an immediate HTTP 404.
# A 4xx is not transient (``aiac.shared.upstream.is_transient``), so the PRB does not retry it and
# raises ``UnparseableLLMResponseError`` — a PERMANENT consumer error (dead-lettered on the first
# delivery). See the rung-5 test's module docstring for why this is preferred over an unreachable host.
UNUSABLE_LLM_BASE_URL = os.environ.get("AIAC_UNUSABLE_LLM_BASE_URL", "http://127.0.0.1:7070/aiac-system-test-no-llm/v1")


def resolve_controller_pod() -> str:
    """The current live Controller pod (newest Ready, non-terminating — see ``resolve_pod``)."""
    return resolve_pod(CONTROLLER_SELECTOR, namespace=CONTROLLER_NAMESPACE)


def _wait_controller_rolled() -> None:
    """Wait for the Controller rollout AND for every old Controller pod to be gone. ``rollout status``
    returns while the old pod may still be ``Terminating`` with its NATS consumer bound; an event it
    takes then runs on the OLD env (or is lost to the kill and redelivered only after ``ACK_WAIT``), so
    the injection is in force only once no terminating pod remains. The new pod is Ready only after its
    start sequence (the side, start check #4, the resync) ends, so the resync has run on return."""
    kubectl_rollout_status(
        f"deployment/{CONTROLLER_DEPLOYMENT}", namespace=CONTROLLER_NAMESPACE, timeout=CONTROLLER_RESTART_TIMEOUT
    )

    def _no_terminating() -> bool:
        doc = json.loads(kubectl("get", "pods", "-n", CONTROLLER_NAMESPACE, "-l", CONTROLLER_SELECTOR, "-o", "json"))
        items = doc.get("items", [])
        return bool(items) and not any(p.get("metadata", {}).get("deletionTimestamp") for p in items)

    if not poll_until(_no_terminating, timeout=DEPLOY_TIMEOUT, interval=3):
        raise RuntimeError(f"old {CONTROLLER_DEPLOYMENT} pod(s) still terminating after {DEPLOY_TIMEOUT:.0f}s")


def restart_controller() -> None:
    """Restart the Controller (``kubectl rollout restart``) and wait until the new pod is Ready and no
    old pod is left (``_wait_controller_rolled``). At each start the Controller runs the resync (D28)
    under the PCE lock before it serves: ``PUT /policy`` with the full policy model of the live side,
    then a teardown of each disabled service that still has an SPM. Changes no env and no ConfigMap."""
    kubectl("rollout", "restart", f"deployment/{CONTROLLER_DEPLOYMENT}", "-n", CONTROLLER_NAMESPACE, timeout=60)
    _wait_controller_rolled()


@contextmanager
def controller_env(overrides: dict[str, str]) -> Iterator[None]:
    """Set explicit env ``overrides`` on the Controller container for the duration of the block, then
    restore the container's **exact** original ``env`` list (or its absence) in ``finally`` — so a later
    test on the shared stack never sees the override, even when the block raises.

    An explicit container ``env`` entry wins over the ``envFrom`` ConfigMap/Secret, so the committed
    ``aiac-agent-config`` is never edited. Both the set and the restore are one JSON patch of the pod
    template's ``env`` list (a template change rolls the Controller), and both wait for the old pod to
    be gone (``_wait_controller_rolled``). Like ``ensure_agent_policy``, a test-owned mutation of the
    running Controller, never written into a committed manifest."""
    dep = json.loads(
        kubectl("get", "deployment", CONTROLLER_DEPLOYMENT, "-n", CONTROLLER_NAMESPACE, "-o", "json", timeout=30)
    )
    containers = dep["spec"]["template"]["spec"]["containers"]
    index = next((i for i, c in enumerate(containers) if c.get("name") == CONTROLLER_DEPLOYMENT), None)
    if index is None:
        raise RuntimeError(f"no container {CONTROLLER_DEPLOYMENT!r} in deployment/{CONTROLLER_DEPLOYMENT}")
    original = containers[index].get("env")  # None when the container declares no explicit env
    patched = [e for e in (original or []) if e.get("name") not in overrides]
    patched += [{"name": name, "value": value} for name, value in overrides.items()]
    path = f"/spec/template/spec/containers/{index}/env"

    def _patch(ops: list[dict]) -> None:
        kubectl(
            "patch",
            "deployment",
            CONTROLLER_DEPLOYMENT,
            "-n",
            CONTROLLER_NAMESPACE,
            "--type",
            "json",
            "-p",
            json.dumps(ops),
        )

    _patch([{"op": "add", "path": path, "value": patched}])  # JSON-patch "add" replaces an existing member
    try:
        _wait_controller_rolled()
        yield
    finally:
        _patch(
            [{"op": "add", "path": path, "value": original}]
            if original is not None
            else [{"op": "remove", "path": path}]
        )
        _wait_controller_rolled()


def controller_llm_unusable():
    """The rung-5 failure injection: point the Controller's PRB at ``UNUSABLE_LLM_BASE_URL`` for the
    block (``ServicePolicyBuilder.build`` then raises after Provision has run), restored on exit."""
    return controller_env({LLM_BASE_URL_ENV: UNUSABLE_LLM_BASE_URL})


def controller_logs() -> str:
    """The current Controller pod's full log (the app container). The consumer logs each PRB failure
    (``log_by_type``) and each dead-letter move at ERROR, so both reach the pod's stderr."""
    return kubectl(
        "logs", "-n", CONTROLLER_NAMESPACE, resolve_controller_pod(), "-c", CONTROLLER_DEPLOYMENT, timeout=60
    )


def publish_service_event(service_uuid: str) -> None:
    """Re-fire the onboarding trigger for an EXISTING Keycloak client: publish on
    ``aiac.apply.service.<uuid>`` (the subject + ``{"id": ...}`` payload the ``aiac-event-listener`` SPI
    publishes on ``CLIENT_CREATED``), so the agent consumer runs the same ``onboard_service`` →
    ``compute_and_apply(focus_service=client_id)`` → ``reenable_service`` path a deploy fires.

    A redeploy cannot do this — the SPI publishes only on client CREATE, and a re-created client has a
    new UUID (a new service, not the quarantined one). The publish runs from INSIDE the Controller pod,
    which already carries ``nats-py`` and resolves the in-cluster broker (``NATS_URL`` or the
    ``aiac-event-broker-service`` default), so the pytest host needs no NATS client or port-forward.
    Raises when the JetStream publish is not acknowledged."""
    subject = f"aiac.apply.service.{service_uuid}"
    script = (
        "import asyncio, os, nats\n"
        f"subject = {json.dumps(subject)}\n"
        f"payload = {json.dumps(json.dumps({'id': service_uuid}))}.encode()\n"
        "async def main():\n"
        "    nc = await nats.connect(os.environ.get('NATS_URL', 'nats://aiac-event-broker-service:4222'))\n"
        "    try:\n"
        "        ack = await nc.jetstream().publish(subject, payload)\n"
        "        print('AB_PUB:%d' % ack.seq)\n"
        "    finally:\n"
        "        await nc.close()\n"
        "asyncio.run(main())\n"
    )
    out = kubectl(
        "exec",
        "-i",
        "-n",
        CONTROLLER_NAMESPACE,
        resolve_controller_pod(),
        "-c",
        CONTROLLER_DEPLOYMENT,
        "--",
        "python",
        "-",
        input_text=script,
        timeout=60,
    )
    if "AB_PUB:" not in out:
        raise RuntimeError(f"publish on {subject!r} was not acknowledged by JetStream: {out.strip()[:300]!r}")


def mcp_session_frames(tool_bare: str) -> list[dict]:
    """One MCP session against the tool, in protocol order: ``initialize``, the
    ``notifications/initialized`` notification (no ``id``), ``tools/list``, then a ``tools/call`` of the
    **bare** ``tool_bare``. The demo tool is a stateless JSON-response FastMCP server, so each frame is
    answered on its own (no ``Mcp-Session-Id`` to carry)."""
    return [
        {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "aiac-system-test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": "2", "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": "3", "method": "tools/call", "params": {"name": tool_bare, "arguments": {}}},
    ]


def mcp_session_decisions(ctx: dict, user: str, tool_bare: str) -> dict[str, tuple[str, int | None, str]]:
    """Mint a fresh ``user`` token, send one MCP session (``mcp_session_frames``) through the agent's
    outbound (token-exchange, then the tool check: github-tool's inbound OPA under target side, the
    agent's outbound OPA under agent side), and return ``{method: (decision, http_code, body)}``. A
    request frame is classified by its body (``outbound_outcome``: a ``result`` frame = allow, an OPA
    403 or OPA error frame = deny); the notification by its status (``notification_outcome``: 202 =
    allow, 403 = deny)."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    frames = mcp_session_frames(tool_bare)
    raw = outbound_session_probe(token, frames, namespace=ctx["namespace"], agent_pod=resolve_agent_pod())
    return {
        frame["method"]: (
            (outbound_outcome(code, body) if "id" in frame else notification_outcome(code)),
            code,
            body,
        )
        for frame, (code, body) in zip(frames, raw)
    }


@contextmanager
def pristine_stack(workloads: Sequence[str], *, policy_md: str = scn.POLICY_ABSTRACT) -> Iterator[dict]:
    """The slate + teardown half of ``onboarded_stack`` with NO deploy and NO convergence poll, for a
    flow whose onboarding is meant to fail (``onboarded_stack`` would wait for a happy-path allow that
    never comes). Yields ``ctx = {"admin", "namespace", "keycloak_url", "realm", "side"}`` (``side`` =
    ``live_enforcement_side()``); the caller deploys.

    Same skip gates (pipeline wiring, env, event path — before any mutation), same no-workloads slate
    (undeploy + ``_scrub_to_pristine`` + ``reenable_provisioned_clients`` + clients-gone poll), same
    realm/users provisioning + ``sub`` mapper gate, ``policy.md`` mount and image load for
    ``workloads``; and the same full-to-pristine teardown, verified (clients gone, no CR left)."""
    require_pipeline(namespace=NAMESPACE, workloads=[])
    creds = require_env_or_skip("KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    keycloak_url = creds["KEYCLOAK_URL"]
    admin = connect_admin()
    require_event_path(admin=admin, realm=TEST_REALM)
    side = live_enforcement_side()

    undeploy_workload(scn.AGENT_WORKLOAD)
    undeploy_workload(scn.TOOL_WORKLOAD)
    _scrub_to_pristine(admin)
    reenable_provisioned_clients(admin, TEST_REALM)
    if not poll_until(lambda: not workload_clients_present(admin), timeout=DEPLOY_TIMEOUT, interval=5):
        raise RuntimeError(
            f"pre-run cleanup left Keycloak client(s) {workload_clients_present(admin)} for {NAMESPACE!r} — the "
            "fresh deploy would not re-fire CLIENT_CREATED, so event-driven onboarding would never trigger."
        )
    provision_realm_and_users(admin, TEST_REALM)
    verify_subject_mapper(keycloak_url=keycloak_url, realm=TEST_REALM, user="dev-user", password=scn.USER_PASSWORD)

    try:
        ensure_agent_policy(CONTROLLER_NAMESPACE, policy_md=policy_md)
        load_workload_images(list(workloads))
        yield {"admin": admin, "namespace": NAMESPACE, "keycloak_url": keycloak_url, "realm": TEST_REALM, "side": side}
    finally:
        for workload in reversed(list(workloads)):
            undeploy_workload(workload)
        _scrub_to_pristine(admin)
        if not poll_until(
            lambda: not workload_clients_present(admin) and no_authpolicies_remain(), timeout=DEPLOY_TIMEOUT, interval=5
        ):
            msg = (
                f"teardown did not restore pristine: Keycloak client(s) still present="
                f"{workload_clients_present(admin)}, AuthorizationPolicy CR(s) remain={not no_authpolicies_remain()} "
                f"in {NAMESPACE!r}."
            )
            if sys.exc_info()[0] is not None:
                log.error("%s [suppressed — a prior error is propagating]", msg)
            else:
                raise RuntimeError(msg)
