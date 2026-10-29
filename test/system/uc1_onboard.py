"""Shared harness for the UC-1 onboarding integration-test ladder (rungs 1–3 and 5–6).

Spec: ``docs/testing/uc1-onboarding-pipeline.md``; live loop shape:
``k8s/opa-kind-runbook.md``. The evaluator is now the **deployed AuthBridge OPA plugin**, not a
standalone OPA-CLI run over dumped ``.rego`` — there is no ``.rego`` dump and no ``opa`` binary here.

**One CR per managed service (D20).** Every onboarded service — the tool included — has its own
``AuthorizationPolicy`` CR (name and namespace from its clientId, label
``app.kubernetes.io/managed-by: aiac-pdp-policy-writer``) with both request packages. The global
combiner denies a pod that has no client CR, so a missing CR means deny. Each callee checks the
access to itself in its own inbound OPA (PRD D34): the agent's outbound is a pass-through
(``allow := true``), and github-tool's inbound decides each tool call. The harness asserts that
shape (``cr_mismatches``) and the place a deny comes from (``deny_origin``).

Every rung follows the same shape against **one** live rossoctl/Kind cluster with the AuthBridge OPA
pipeline wired into both legs:

    capture the leftover CRs of an earlier run to the pytest host (``capture_aiac_crs``, ``pre-run-slate``)
      → start from a no-workloads slate (undeploy + delete registrations) + policy-store clear
      → deploy the rung's workloads in order, one at a time — each deploy fires the EVENT-DRIVEN
        trigger (operator registers a Keycloak client → Keycloak CLIENT_CREATED → the aiac-event-listener
        SPI publishes on NATS → the agent consumer runs onboard_and_apply, upserting the AuthorizationPolicy
        CR of each affected service on the live API), converging before the next
      → right after each workload converges, check that its client links the subject scope
        ``aiac-username-sub`` as a default scope (``require_subject_scope``, D31; a missing link fails)
      → enable the outbound token-exchange leg (Part B: default client scope + agent restart)
      → poll bundle-service + OPA until this run's CR is reflected in real decisions
      → drive REAL HTTP requests through AuthBridge and assert the real plugin's allow/deny
      → capture every AIAC CR + the global combiner to the pytest host (``teardown``) — the first
        teardown step, on the success and the failure path, best-effort (it never raises)
      → teardown full-to-pristine (undeploy + delete all registrations + delete CRs, verified); the
        realm users and roles stay (leave-in-place)
      → Direct Access Grants on the login client: the first stack of the session turns it on before the
        pre-run slate, and the session end turns it off again if the harness turned it on
        (``hold_direct_access_grants``, with a marker on the client, so a killed run is undone later)

The only thing that differs between rungs is *which workloads are onboarded and in what order*, so
all the machinery lives here and each ``test_uc1_onboard_*.py`` supplies just its own oracle
(verdicts computed from ``scenario_uc1.py``) and live assertions.

This module owns:

* **Config** (env, spec § Configuration) — single stack, no variants.
* **Keycloak** — ``connect_admin`` / ``hold_direct_access_grants`` (the password grant on the login
  client, for the session) / ``provision_realm_and_users`` (the fixture UC-1 does *not* do) /
  ``cleanup_provisioned`` / ``delete_workload_registrations`` (teardown).
* **CRs** — ``delete_workload_crs`` (the agent's and the tool's CR) / ``sweep_authpolicies`` (every
  other CR in the namespace) / ``delete_authpolicy`` (one CR, raising).
* **Onboarding (event-driven)** — ``ensure_agent_policy`` (mount the PRB's ``policy.md``) +
  ``deploy_workload`` (deploy fires the trigger) / ``wait_for_registration`` / ``undeploy_workload``.
* **Outbound-leg prep (Part B)** — ``grant_exchange_scope`` / ``restart_agent`` so
  ``token-exchange-aiac`` mints the tool token and OPA is actually consulted on the outbound leg.
* **The subject on every leg (D31)** — ``SUBJECT_SCOPE`` (``aiac-username-sub``) and its mapper
  expectation; the pure ``subject_scope_problems``; the live reader ``subject_scope_link_problems`` and
  ``require_subject_scope`` (the login client ``rossoctl`` and each onboarded client link the scope as
  a **default** scope, and the scope has the ``username → sub`` mapper and no ``aiac.managed`` marker;
  ``onboarded_stack`` fails fast without it); and the ``sub`` probes
  ``login_subject`` (a password-grant token through ``rossoctl``) and ``exchanged_subject`` (a token
  exchanged as the agent client to the tool audience).
* **Live decision oracle + probes** — ``expected_inbound`` / ``expected_outbound_bare`` (verdicts from
  ``scenario_uc1``, keyed on the **bare** runtime tool names AuthBridge sends) and ``inbound_decision``
  / ``outbound_decision`` (mint a user token, send a real request through AuthBridge, classify the
  real plugin's response).
* **``onboarded_stack``** — the whole per-rung fixture flow, parameterised by the ordered workload
  list; each rung wraps it in a one-line session fixture and yields a probe context.
* **CR readers** — ``authpolicy_policies`` (one CR's ``{path: rego}``),
  ``aiac_crs`` / ``aiac_cr_uids`` (every CR with the managed-by label), ``cr_has_request_packages``,
  ``cr_has_grants``, ``rego_is_pass_through``, ``cr_matches`` / ``cr_mismatches``, and
  ``deny_origin`` + ``outbound_raw`` (where a deny comes from).
* **CR capture (post-mortem evidence)** — ``capture_aiac_crs``: before each teardown and each Controller
  restore, and before the pre-run slate, write every AIAC CR (the managed-by label, all namespaces) and
  the global combiner as YAML to the pytest host, one directory per capture under ``CR_CAPTURE_DIR``
  (``AIAC_CR_CAPTURE_DIR``; default the gitignored ``test/system/artifacts/cr-captures``). Read-only and
  best-effort: it never masks a test failure and never stops a teardown.
* **Failure path (rung 5)** — ``pristine_stack`` (the slate + teardown of ``onboarded_stack`` with no
  deploy / convergence, for a flow that must not converge), ``controller_llm_unusable`` (the LLM-seam
  failure injection, restored on exit after a CR capture), ``publish_service_event`` (re-fire the
  onboarding trigger for an existing client), and the quarantine readers (``workload_client``,
  ``spm_present``, ``controller_logs``) plus the MCP session probe ``mcp_session_decisions``.
* **The event-before-commit race hint (D33)** — the pure ``commit_race_hint`` (Controller
  log text in, hint out: a line with Keycloak's 404 ``Could not find client`` or the Controller's
  ``ServiceNotVisibleError``, optionally only for one client UUID) and its live reader
  ``controller_commit_race_hint`` (a bounded ``kubectl logs`` from just before the deploy; read-only and
  best-effort, it never raises). Each deploy gate that times out appends the hint (``append_hint``), so
  the message says when the onboarding event probably came before the Keycloak commit.
* **Controller restart (rung 6)** — ``restart_controller`` (rollout restart + wait until no old pod is
  left; the resync at start ends before the new pod is Ready).

It imports only stdlib + ``requests`` + ``launcher`` + the pure-data ``scenario_uc1`` (never
``aiac``; PyYAML only inside the capture's ``_to_yaml``), so it is importable before the
env-before-import dance, exactly like ``scenario_uc1`` and ``launcher``. It defines **no** ``test_*``
functions, so pytest does not collect it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Collection, Iterator, Mapping, Sequence

import requests

HERE = Path(__file__).resolve().parent  # test/system/
REPO_ROOT = HERE.parents[1]  # -> aiac/
if str(REPO_ROOT) not in sys.path:  # so ``import test.system.*`` resolves
    sys.path.insert(0, str(REPO_ROOT))

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system.launcher import (  # noqa: E402
    BUNDLE_SERVICE_NAMESPACE,
    DENY_ORIGIN_TOOL_INBOUND,  # noqa: F401 — re-exported: the rung tests compare a deny origin with it
    KEYCLOAK_CLIENT_ID,
    TokenExchangeError,
    _kubectl_try,
    curl_pod,
    deny_origin,
    exchange_token,
    inbound_outcome,
    inbound_probe,
    is_opa_violation,
    jwt_claim,
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
    target_disabled_refusal,  # noqa: F401 — re-exported: the rollback test proves the quarantine with it
    verify_login_subject,
)

log = logging.getLogger(__name__)


def _exc_text(exc: BaseException, limit: int) -> str:
    """The text of ``exc`` for a message: a failed ``kubectl``'s stderr, else ``str(exc)``, cut to ``limit``."""
    return str(getattr(exc, "stderr", None) or exc).strip()[:limit]


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

# The Controller's start sequence (start check #4, then the resync under the PCE lock)
# ends before uvicorn serves, so a restarted Controller is Ready only after its resync. This budget
# (seconds) covers that start, for every Controller rollout the harness waits on.
CONTROLLER_RESTART_TIMEOUT = float(os.environ.get("AIAC_CONTROLLER_RESTART_TIMEOUT", "300"))

# The label the OPA Policy Writer puts on every CR it owns (``_MANAGED_BY_LABEL`` in the writer).
MANAGED_BY_SELECTOR = "app.kubernetes.io/managed-by=aiac-pdp-policy-writer"

# The global combiner (D20): the ``default`` AuthorizationPolicy (scope ``global``) in the bundle-service
# namespace, applied by ``k8s/opa-kind-enable.sh``. It has no managed-by label (``PUT /policy`` would
# delete it), so the harness reads it by name, as the Controller start check #4 does.
COMBINER_CR_NAME = "default"

# --- CR capture (post-mortem evidence) -----------------------------------------------------
# Before a teardown deletes or rewrites the AIAC CRs, ``capture_aiac_crs`` writes every AIAC CR and the
# global combiner to the pytest host, so a failed run keeps the CRs that made its decisions. One new
# subdirectory per capture under this root. Default: the gitignored ``test/system/artifacts/cr-captures/``.
CR_CAPTURE_DIR = Path(os.environ.get("AIAC_CR_CAPTURE_DIR") or HERE / "artifacts" / "cr-captures").expanduser()

# --- Live-cluster loop knobs ---------------------------------------------------------------

# The workload Deployment to restart after Part B so it reloads the new outbound route (and, on its
# OPA sidecar's next poll, the recomposed bundle). Defaults to the agent workload name.
AGENT_DEPLOYMENT = os.environ.get("AIAC_AGENT_DEPLOYMENT", scn.AGENT_WORKLOAD)


# After a CR is upserted, ``bundle-service`` recomposes the namespace bundle and each pod's OPA polls
# it on its own interval (``polling_min_delay`` / ``polling_max_delay``, 10-120 s by default, up to about
# 144 s after a fetch error; a new pod fetches at once), and ``token-exchange`` needs a moment to settle
# after the agent restart. ``onboarded_stack`` polls real decisions until they converge, up to this budget
# (seconds). Rungs 5 and 6 use it for their own CR-change polls.
BUNDLE_TIMEOUT = float(os.environ.get("AIAC_BUNDLE_TIMEOUT", "300"))
BUNDLE_POLL_INTERVAL = float(os.environ.get("AIAC_BUNDLE_POLL_INTERVAL", "10"))

# Deploying a workload fires the event-driven trigger (deploy -> operator registers a Keycloak client
# -> CLIENT_CREATED -> SPI -> NATS -> the agent consumer runs ``onboard_and_apply``). The operator's
# client registration is asynchronous (reconcile after the pod comes up), so the fixture polls for it
# up to this budget (``AIAC_DEPLOY_TIMEOUT``, seconds).
DEPLOY_TIMEOUT = float(os.environ.get("AIAC_DEPLOY_TIMEOUT", "180"))

# A tool's onboarding ends only after the bootstrap CR reaches its OPA sidecar (the discovery waits up
# to ``AIAC_MCP_DISCOVERY_READY_TIMEOUT``, default 180 s, for the bundle poll), Provision, and the real
# PRB (LLM). The onboarded gate (``await_onboarded``) polls up to this budget for both kinds
# (``AIAC_ONBOARD_TIMEOUT``, seconds): a workload that is not ready yet is nak'd up to MAX_DELIVER (5)
# times with a 30 s delay (the not-ready naks), so its last try can start minutes after the event.
ONBOARD_TIMEOUT = float(os.environ.get("AIAC_ONBOARD_TIMEOUT", "600"))

# After the client is registered, the operator writes the credentials Secret and annotates the pod
# template, which rolls the workload once more. The final-rollout gate (``await_final_rollout``) polls up
# to this budget (seconds) until the template is final, rolled out, and every pod has the sidecar. It
# covers one operator restart and the last rollout.
ROLLOUT_TIMEOUT = float(os.environ.get("AIAC_ROLLOUT_TIMEOUT", "180"))

# The agent's live inbound gate after it is onboarded: its OPA must poll the new bundle (up to about
# 144 s, see ``BUNDLE_TIMEOUT``), plus one probe round (``AIAC_ENFORCED_TIMEOUT``, seconds).
ENFORCED_TIMEOUT = float(os.environ.get("AIAC_ENFORCED_TIMEOUT", "180"))

# Once both workloads are onboarded, the tool's CR has the agent's roles. The PCE writes the CRs in
# clientId order, so a read right after the agent's SPM can still see the tool's old CR. The tool CR
# content gate polls up to this budget (``AIAC_CR_CONTENT_TIMEOUT``, seconds).
CR_CONTENT_TIMEOUT = float(os.environ.get("AIAC_CR_CONTENT_TIMEOUT", "60"))

# Both deploy gates (the agent's on ``BUNDLE_TIMEOUT``, the tool's on ``ONBOARD_TIMEOUT``) hold with the
# defaults when the D33 fix is deployed: the SPI image that publishes after the commit, or
# both the IdP Configuration Service that keeps a Keycloak 404 and the Controller that reads a new client
# again for a bounded time. Without it, the SPI can publish ``CLIENT_CREATED`` before Keycloak commits
# the new client: the Controller's first IdP read gets 404 and the onboarding waits for the NATS
# redelivery after ``ACK_WAIT`` (600 s), so one race hit fails the gate. With the fix deployed, do not
# raise the budgets for this race: a gate that times out says when the Controller log shows it
# (``controller_commit_race_hint``). Verified live on 2026-10-07 with the fix in all three images
# (rungs 1, 2 twice and 3 passed with these defaults; the bounded wait and the nak did not trigger).

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
    of github-tool's inbound pass (per-scope AND, D26): their realm role reaches it in the user gate
    (``OUTBOUND_SUBJECT_BARE``) **and** the agent's own operator roles reach it in the calling-agent
    gate (``OUTBOUND_TARGET_BARE``). This is the tool-onboarded oracle (rungs 2 & 3); rung 1's gate is
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
    each role's ``actorIds`` (member usernames) — the PCE needs them to refresh the role holders,
    from which the writer builds the ``subject_roles`` map that the tool and agent inbound gates key
    on. Never deletes/recreates — reruns converge (spec: shared realm, leave-in-place: the users and
    the roles stay after the run). The password grant on the login client is not set here: see
    ``hold_direct_access_grants``."""
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
        profile = _user_profile(username)
        user_id = admin.create_user({"username": username, "enabled": True, **profile}, exist_ok=True)
        _complete_user_profile(admin, user_id, profile)
        admin.set_user_password(user_id, scn.USER_PASSWORD, temporary=False)
        admin.assign_realm_roles(user_id, [admin.get_realm_role(role_name)])


def _user_profile(username: str) -> dict:
    """The profile fields that a fresh ``rossoctl`` realm requires (``email``, ``firstName``,
    ``lastName``). Keycloak 26 refuses a password grant for a user without them (``invalid_grant``:
    "Account is not fully set up"), so ``mint_token`` would fail for that user."""
    return {"email": f"{username}@rossoctl.local", "emailVerified": True, "firstName": username, "lastName": "AIAC"}


def _complete_user_profile(admin, user_id: str, profile: dict) -> None:
    """Write only the ``profile`` fields that the stored user does not have; an existing value (for
    example the names of the platform's own ``dev-user``) is kept. The update sends the full root
    fields, so no stored field is lost."""
    user = admin.get_user(user_id)
    missing = {key: value for key, value in profile.items() if not user.get(key)}
    if missing:
        root = ("username", "enabled", "email", "emailVerified", "firstName", "lastName")
        admin.update_user(user_id, {**{key: user.get(key) for key in root if key in user}, **missing})


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
                _update_client(admin, realm, client["id"], {"enabled": True})
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
            capture_pod_logs("pre-policy-roll", namespace=namespace)  # the roll deletes the pod and its log
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
    capture_pod_logs("pre-policy-roll", namespace=namespace)  # the patch rolls the pod and deletes its log
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
    ``onboard_and_apply`` (the same handler the retired ``POST /apply`` called).

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


# The operator's marks on a workload's pod template (``../operator``, ``internal/clientreg/names.go``):
# the AgentRuntime controller adds the type label, and the ClientRegistration controller adds the
# credentials annotation after it registered the client and wrote the Secret. That annotation is the last
# template write, and the operator writes no condition or event for it, so it is the "registration done"
# fact. Read it on the Deployment's template: the webhook also puts it on every typed Pod at admission.
TYPE_LABEL = "rossoctl.io/type"
CREDENTIALS_ANNOTATION = "rossoctl.io/keycloak-client-credentials-secret-name"
# The AuthBridge sidecar the webhook injects (``preconditions.SIDECAR_CONTAINER`` on the Controller side).
SIDECAR_CONTAINER = "authbridge-proxy"


def final_rollout_reason(deployment: dict, pods: Sequence[dict], *, kind: str) -> str | None:
    """``None`` when ``deployment`` runs the operator's final template on pods that all have the
    AuthBridge sidecar, else the first reason it does not. **Pure.**

    The template must have the ``TYPE_LABEL`` of ``kind`` and the ``CREDENTIALS_ANNOTATION``; the rollout
    of that template must be complete (the Deployment controller's ``DeploymentComplete`` test; the API
    omits zero counters); and every live pod of ``pods`` (no ``deletionTimestamp``) must have the
    ``SIDECAR_CONTAINER``. Before that, the Service can route the probe to a pod with no sidecar, whose
    app answers 200, which reads as ``allow`` before AIAC onboarded the workload."""
    meta = (deployment.get("spec", {}).get("template", {}) or {}).get("metadata", {}) or {}
    have = (meta.get("labels") or {}).get(TYPE_LABEL)
    if have != kind:
        return f"the pod template has {TYPE_LABEL}={have!r} (want {kind!r}): the operator has not configured it yet"
    if not (meta.get("annotations") or {}).get(CREDENTIALS_ANNOTATION):
        return f"the pod template has no {CREDENTIALS_ANNOTATION} annotation: the operator has not finished the registration"
    status = deployment.get("status", {}) or {}
    generation = deployment.get("metadata", {}).get("generation") or 0
    observed = status.get("observedGeneration") or 0
    if observed < generation:
        return f"the Deployment controller has not observed generation {generation} (observedGeneration={observed})"
    want = deployment.get("spec", {}).get("replicas", 1)
    counters = {k: status.get(k) or 0 for k in ("replicas", "updatedReplicas", "availableReplicas")}
    if not (
        counters["updatedReplicas"] == want and counters["replicas"] == want and counters["availableReplicas"] == want
    ):
        return f"the rollout is not complete: spec.replicas={want}, " + ", ".join(
            f"{k}={v}" for k, v in counters.items()
        )
    live = [p for p in pods if not p.get("metadata", {}).get("deletionTimestamp")]
    if not live:
        return "no live pod of the workload"
    for pod in live:
        names = {c.get("name") for c in pod.get("spec", {}).get("containers", [])}
        if SIDECAR_CONTAINER not in names:
            return f"pod {pod.get('metadata', {}).get('name')!r} has no {SIDECAR_CONTAINER} container"
    return None


def rollout_counters(deployment: dict) -> str:
    """The template marks and every rollout counter of ``deployment``, for the state dump. **Pure.**
    The API omits a zero counter, so a missing one prints 0."""
    meta = (deployment.get("spec", {}).get("template", {}) or {}).get("metadata", {}) or {}
    status = deployment.get("status", {}) or {}
    has_secret = "yes" if (meta.get("annotations") or {}).get(CREDENTIALS_ANNOTATION) else "no"
    return (
        f"template {TYPE_LABEL}={(meta.get('labels') or {}).get(TYPE_LABEL)!r}, credentials annotation: {has_secret}; "
        f"generation {deployment.get('metadata', {}).get('generation') or 0}, "
        f"observedGeneration {status.get('observedGeneration') or 0}, "
        f"spec.replicas {deployment.get('spec', {}).get('replicas', 1)}, replicas {status.get('replicas') or 0}, "
        f"updatedReplicas {status.get('updatedReplicas') or 0}, availableReplicas {status.get('availableReplicas') or 0}"
    )


# The rossoctl operator (``../operator``, ``cmd/main.go``): one replica with ``--leader-elect``. On a lost
# lease the manager exits, so its container restarts in the same pod (``restartCount`` + 1). A deleted or
# evicted pod comes back as a new pod with ``restartCount`` 0, so the count alone misses it; the pod UID,
# the container start and the Lease holder (``<pod>_<uuid>``, new for each process) catch both. The pods
# are the ones that the operator Deployment's own selector matches.
OPERATOR_NAMESPACE = os.environ.get("AIAC_OPERATOR_NAMESPACE", "rossoctl-system")
OPERATOR_DEPLOYMENT = os.environ.get("AIAC_OPERATOR_DEPLOYMENT", "rossoctl-controller-manager")
OPERATOR_LEASE = os.environ.get("AIAC_OPERATOR_LEASE", "b7c4ae34.rossoctl.dev")
OPERATOR_CONTAINER = "manager"


@dataclass(frozen=True)
class OperatorIdentity:
    """The rossoctl operator's identity: per pod ``(name, uid, restartCount, startedAt)`` of the manager
    container, the Lease holder and transitions, and the read error when the pods could not be read."""

    pods: tuple[tuple, ...] = ()
    holder: str | None = None
    transitions: int | None = None
    error: str | None = None


def operator_identity(pods: Sequence[dict], lease: dict | None) -> OperatorIdentity:
    """The rossoctl operator's identity from its pods and its leader-election Lease. **Pure**; compare
    two of them with ``operator_change_note``."""
    found = []
    for pod in pods:
        meta = pod.get("metadata", {})
        status = next(
            (c for c in pod.get("status", {}).get("containerStatuses", []) if c.get("name") == OPERATOR_CONTAINER), {}
        )
        started = (status.get("state", {}).get("running") or {}).get("startedAt")
        found.append((meta.get("name"), meta.get("uid"), status.get("restartCount", 0), started))
    spec = (lease or {}).get("spec", {})
    return OperatorIdentity(tuple(sorted(found)), spec.get("holderIdentity"), spec.get("leaseTransitions"))


def _operator_pods_text(identity: OperatorIdentity) -> str:
    if not identity.pods:
        return "no operator pod"
    return "; ".join(
        f"pod {name}, restarts {restarts}, started {started}" for name, _, restarts, started in identity.pods
    )


def operator_change_note(before: OperatorIdentity, after: OperatorIdentity) -> str | None:
    """``None`` when the operator is the same process as at ``before``, else one line that gives both
    states. **Pure.** A restart is a note for a failure message, never a failure on its own. A failed read
    on either side is not evidence of a change: the note then says that the operator was not read."""
    if before.error or after.error:
        return f"not compared: the operator could not be read ({before.error or after.error})"
    if before == after:
        return None
    return (
        f"the rossoctl operator restarted or was replaced during the run (was {_operator_pods_text(before)}, "
        f"Lease holder {before.holder}; now {_operator_pods_text(after)}, Lease holder {after.holder}). "
        "Each start waits about 66 s before it reconciles, and while it is down the injection webhook "
        "(failurePolicy Fail) refuses new labelled pods."
    )


def _operator_selector() -> tuple[str | None, str]:
    """``(selector, error)``: the operator Deployment's ``matchLabels`` as a ``kubectl -l`` selector, or
    ``None`` and why it could not be read."""
    ok, out, err = _kubectl_try("get", "deployment", OPERATOR_DEPLOYMENT, "-n", OPERATOR_NAMESPACE, "-o", "json")
    if not ok:
        return None, err
    labels = json.loads(out).get("spec", {}).get("selector", {}).get("matchLabels") or {}
    if not labels:
        return None, f"deployment/{OPERATOR_DEPLOYMENT} has no spec.selector.matchLabels"
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items())), ""


def read_operator_identity() -> OperatorIdentity:
    """The live ``operator_identity``: the operator's pods and its Lease. A read failure gives an
    identity with an ``error``, so a later compare reports it, never raises."""
    selector, err = _operator_selector()
    if selector is None:
        return OperatorIdentity(error=err)
    ok, pods_out, err = _kubectl_try("get", "pods", "-n", OPERATOR_NAMESPACE, "-l", selector, "-o", "json")
    if not ok:
        return OperatorIdentity(error=err)
    ok, lease_out, _ = _kubectl_try("get", "lease", OPERATOR_LEASE, "-n", OPERATOR_NAMESPACE, "-o", "json")
    return operator_identity(json.loads(pods_out).get("items", []), json.loads(lease_out) if ok else None)


def capture_operator_logs(before: OperatorIdentity, after: OperatorIdentity) -> None:
    """Save the operator's log (and ``--previous`` after a container restart in the same pod) next to the
    Controller logs when it changed since ``before``. Best-effort: it never raises."""
    if before.error or after.error or operator_change_note(before, after) is None:
        return
    selector, err = _operator_selector()
    if selector is None:
        log.warning("operator log capture: %s", err)
        return
    capture_pod_logs("operator-changed", namespace=OPERATOR_NAMESPACE, selector=selector, container=OPERATOR_CONTAINER)


def _workload_pods(workload: str) -> list[dict]:
    """The pods of ``workload`` (the demo Service's selector ``app.kubernetes.io/name``)."""
    out = kubectl("get", "pods", "-n", NAMESPACE, "-l", f"app.kubernetes.io/name={workload}", "-o", "json", timeout=30)
    return json.loads(out).get("items", [])


def _read_rollout(workload: str) -> tuple[dict, str | None]:
    """The live Deployment of ``workload`` and its ``final_rollout_reason`` (raises on a read failure)."""
    deployment = json.loads(kubectl("get", "deployment", workload, "-n", NAMESPACE, "-o", "json", timeout=30))
    return deployment, final_rollout_reason(deployment, _workload_pods(workload), kind=WORKLOAD_KIND[workload])


def await_final_rollout(admin, workload: str, *, context: dict) -> None:
    """Block until ``workload`` runs the operator's final template on pods that all have the AuthBridge
    sidecar (``final_rollout_reason``), or raise ``RuntimeError`` with the last reason, the workload's
    ReplicaSet events, and the state dump. Call it after ``wait_for_registration`` and before any
    probe or onboarding check of ``workload``: before it, a probe can reach a pod with no sidecar."""
    seen = {"reason": "not checked"}

    def _final() -> bool:
        try:
            _, seen["reason"] = _read_rollout(workload)
        except Exception as exc:  # a read failure is a reason, so the poll goes on
            seen["reason"] = f"read failed: {_exc_text(exc, 300)}"
        return seen["reason"] is None

    if poll_until(_final, timeout=ROLLOUT_TIMEOUT, interval=3):
        return
    ok, events, _ = _kubectl_try(
        "get",
        "events",
        "-n",
        NAMESPACE,
        "--field-selector",
        "involvedObject.kind=ReplicaSet,type=Warning",
        "-o",
        "custom-columns=OBJECT:.involvedObject.name,REASON:.reason,MESSAGE:.message",
        "--no-headers",
    )
    warnings = [ln for ln in events.splitlines() if ln.startswith(f"{workload}-")] if ok else []
    raise RuntimeError(
        f"{NAMESPACE}/{workload} is not on the operator's final template within {ROLLOUT_TIMEOUT:.0f}s: "
        f"{seen['reason']}. ReplicaSet warnings: {warnings[-3:] or 'none'} ('failed calling webhook "
        '"inject.rossoctl.io"\' = the operator is down). ' + stack_diagnosis(admin, workload, context=context)
    )


def await_onboarded(admin, workload: str, *, context: dict, deployed_at: datetime) -> None:
    """Block until AIAC has onboarded ``workload``: its client has ``SERVICE_TYPE_ATTRIBUTE`` (Provision
    ended) and its SPM is stored (the PRB and the PCE ran); for a tool also its provisioned scopes and
    its CR (``tool_onboarding_state``). Raise ``RuntimeError`` at once when the client is disabled (a
    rollback ran, the quarantine marker), or at ``ONBOARD_TIMEOUT`` with the last state, the
    Controller lines of this onboarding, the event-before-commit race hint, and the state dump."""
    seen: dict = {"state": "not checked"}

    def _onboarded() -> bool:
        client = workload_client(admin, workload)
        state = {"client": client is not None}
        if client is not None:
            state["enabled"] = client.get("enabled", True)
            state["provisioned"] = provision_ended(client)
        seen["state"] = state
        if client is not None and state["enabled"] is False:
            return True  # the early exit below
        if not (client and state["provisioned"]):
            return False
        if workload == scn.TOOL_WORKLOAD:
            state.update(tool_onboarding_state(admin))
            return all(v for k, v in state.items() if k != "enabled")
        state["spm"] = spm_present(client["clientId"])
        return state["spm"]

    def _poll() -> bool:
        try:
            return _onboarded()
        except Exception as exc:  # keep the last read error for the message
            seen["error"] = _exc_text(exc, 300)
            return False

    reached = poll_until(_poll, timeout=ONBOARD_TIMEOUT, interval=5)
    state = seen["state"]
    if reached and not (isinstance(state, dict) and state.get("enabled") is False):
        return
    cause = (
        "its client is disabled: the onboarding failed and rolled back (the quarantine marker)"
        if reached
        else f"not onboarded within {ONBOARD_TIMEOUT:.0f}s"
    )
    message = (
        f"{NAMESPACE}/{workload}: {cause}. Last state: {state}"
        + (f", last read error: {seen['error']}" if seen.get("error") else "")
        + f" (provisioned = the client has {SERVICE_TYPE_ATTRIBUTE}, Provision ended; spm = its SPM is stored). "
        + controller_onboarding_lines(admin, workload, since=deployed_at)
    )
    raise RuntimeError(
        append_hint(message, controller_commit_race_hint(deployed_at, admin=admin, workload=workload))
        + " "
        + stack_diagnosis(admin, workload, context=context)
    )


# The consumer's lines of one onboarding that say why it did not end (``aiac.agent.eventbus.consumer``):
# a not-ready nak (``nak'd <subject> (<error>, delivery N)``) and the dead-letter move
# (``moved <subject> to aiac.apply.dlq (...)``). Each names the event subject, so the client UUID.
_ONBOARDING_LINE = re.compile(r"nak'd |moved \S+ to \S*dlq", re.IGNORECASE)


def onboarding_lines(log_text: str, *, service_uuid: str | None, keep: int = 5) -> list[str]:
    """The last ``keep`` consumer lines of ``log_text`` that match ``_ONBOARDING_LINE`` and name
    ``service_uuid`` (every such line when it is ``None``), each cut to ``_HINT_LINE_CHARS``. **Pure.**
    A nak line names the not-ready error; the dead-letter move is the last line of a failed onboarding."""
    lines = [
        ln.strip()[:_HINT_LINE_CHARS]
        for ln in log_text.splitlines()
        if _ONBOARDING_LINE.search(ln) and (service_uuid is None or service_uuid in ln)
    ]
    return lines[-keep:]


def controller_onboarding_lines(admin, workload: str, *, since: datetime) -> str:
    """``onboarding_lines`` over the live Controller log from ``since`` for the workload's client, as
    one sentence. Best-effort: a failed read says so, never raises."""
    try:
        client = workload_client(admin, workload)
        start = since - timedelta(seconds=CONTROLLER_LOG_SLACK_SECONDS)
        text = controller_logs(since=start, tail=CONTROLLER_LOG_TAIL)
    except Exception as exc:  # best-effort: never replace the gate's own error
        return f"(Controller log not read: {_exc_text(exc, 200)})"
    lines = onboarding_lines(text, service_uuid=client.get("id") if client else None)
    if not lines:
        return "The Controller log has no nak or dead-letter line for it."
    return f"Controller lines (the not-ready error is in each nak): {lines}."


# The SPIFFE trust domain of the bundle-service probe of the diagnosis, when it differs from the one the
# exchange uses (``AIAC_TRUST_DOMAIN``, as ``TRUST_DOMAIN`` of ``k8s/opa-kind-verify.sh``). Unset, the
# probe uses the trust domain of the live outbound leg (``require_pipeline``).
BUNDLE_TRUST_DOMAIN = os.environ.get("AIAC_TRUST_DOMAIN") or None


def bundle_service_probe(workload: str, *, trust_domain: str) -> tuple[str, str, str]:
    """GET bundle-service ``/readyz`` and ``/bundles?spiffe=<td>/ns/<ns>/sa/<workload>`` from a
    throwaway curl pod in ``NAMESPACE`` (the ztunnel path the sidecars use, as ``opa-kind-verify.sh``
    Verify 4 does); return the two HTTP codes as strings (``000`` = not reachable) and the SPIFFE ID it
    asked for. ``<td>`` is
    ``BUNDLE_TRUST_DOMAIN`` when set, else ``trust_domain``, the one the exchange uses
    (``require_pipeline``, read once per stack)."""
    base = f"http://bundle-service.{BUNDLE_SERVICE_NAMESPACE}.svc.cluster.local:8080"
    spiffe = f"{BUNDLE_TRUST_DOMAIN or trust_domain}/ns/{NAMESPACE}/sa/{workload}"
    # ``; true``: a failed curl still prints its code (``000``), and the pod must exit 0 to keep the output.
    script = (
        f"curl -s -m 10 -o /dev/null -w 'readyz %{{http_code}}\\n' {base}/readyz; "
        f"curl -s -m 10 -o /dev/null -w 'bundle %{{http_code}}\\n' '{base}/bundles?spiffe={spiffe}'; true"
    )
    out = curl_pod(NAMESPACE, script, name="probe-bundle")
    codes = dict(line.split(" ", 1) for line in out.splitlines() if line.startswith(("readyz ", "bundle ")))
    return codes.get("readyz", "none"), codes.get("bundle", "none"), spiffe


def _agentcard_state(workload: str) -> str:
    ok, out, err = _kubectl_try("get", "agentcards.agent.rossoctl.dev", "-n", NAMESPACE, "-o", "json")
    if not ok:
        return f"not read ({err})"
    # The Controller's match (``_await_agent_skills``): the card's targetRef, or a legacy card named after the
    # workload; a synced card wins over a stale one.
    cards = [
        c
        for c in json.loads(out).get("items", [])
        if workload in (c.get("spec", {}).get("targetRef", {}).get("name"), c.get("metadata", {}).get("name"))
    ]

    def _synced(c: dict) -> dict | None:
        return next((s for s in c.get("status", {}).get("conditions", []) if s.get("type") == "Synced"), None)

    card = next((c for c in cards if (_synced(c) or {}).get("status") == "True"), cards[0] if cards else None)
    if card is None:
        return f"no AgentCard (the operator makes one only after it puts {TYPE_LABEL}=agent on the Deployment)"
    synced = _synced(card)
    if synced is None:
        return f"{card['metadata']['name']} has no Synced condition yet"
    return f"{card['metadata']['name']} Synced={synced.get('status')} ({synced.get('reason')}): {synced.get('message')}"


def _bundle_probe_note(workload: str, context: dict) -> str:
    """``bundle_service_probe``'s codes, with the trust domain it probed. When ``AIAC_TRUST_DOMAIN``
    differs from the trust domain the exchange uses (``context["trust_domain"]``), say so: a 404 then
    may be the override's, not the cluster's."""
    live = context["trust_domain"]
    readyz, bundle, spiffe = bundle_service_probe(workload, trust_domain=live)
    note = f"readyz {readyz}, bundle {bundle} for spiffe={spiffe}"
    if BUNDLE_TRUST_DOMAIN and BUNDLE_TRUST_DOMAIN != live:
        note += (
            f" (AIAC_TRUST_DOMAIN={BUNDLE_TRUST_DOMAIN} differs from the live token-exchange-aiac trust domain {live})"
        )
    return note


def stack_diagnosis(admin, workload: str, *, context: dict) -> str:
    """The state dump that every gate failure appends: the operator change since the fixture start
    (``context["operator"]``), bundle-service reachability from the namespace, the Deployment's template
    marks and rollout, the AgentCard (agent), the client and the SPM, and the CR content check.
    Best-effort: each part that cannot be read says so; it never raises."""
    parts = []

    def _part(name: str, read) -> None:
        try:
            parts.append(f"{name}: {read()}")
        except Exception as exc:  # one failed read must not hide the others or the gate error
            parts.append(f"{name}: not read ({_exc_text(exc, 200)})")

    def _operator() -> str:
        now = read_operator_identity()
        capture_operator_logs(context["operator"], now)  # the --previous log of a restart in the same pod
        return operator_change_note(context["operator"], now) or "unchanged"

    _part("operator", _operator)
    _part(f"bundle-service from {NAMESPACE} (readyz, bundle)", lambda: _bundle_probe_note(workload, context))

    def _deployment() -> str:
        deployment, reason = _read_rollout(workload)
        return f"{reason or 'final and rolled out'} ({rollout_counters(deployment)})"

    _part("deployment", _deployment)
    if workload == scn.AGENT_WORKLOAD:
        _part("agentcard", lambda: _agentcard_state(workload))

    def _client() -> str:
        client = workload_client(admin, workload)
        if client is None:
            return "not registered"
        spm = spm_present(client["clientId"])
        return f"enabled={client.get('enabled')}, provisioned={provision_ended(client)}, spm={spm}"

    _part("client", _client)
    check = agent_cr_content_problems if workload == scn.AGENT_WORKLOAD else tool_cr_content_problems
    _part("CR content", lambda: check(authpolicy_policies(workload)) or "as expected")
    return "State: " + "; ".join(parts) + "."


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


def tool_onboarding_state(admin) -> dict[str, bool | None]:
    """The three facts of the tool's convergence gate, each ``True`` when it holds:

    * ``scopes`` — every ``github-tool.*`` client scope is provisioned (Provision ran);
    * ``spm`` — ``SPM(github-tool)`` is in the Policy Store. The PCE stores the focus SPM also when it
      has zero rules (D21), and the bootstrap CR stores none, so this is the proof that the PRB and
      ``compute_and_apply`` ran — not only the bootstrap;
    * ``cr`` — github-tool's own CR is present with both request packages (D20).

    The bootstrap CR is present before Provision, so the CR alone does not prove the final CR; with
    the SPM it does (the PCE writes the CR right after the store write). A live decision on github-tool's
    inbound needs the outbound token-exchange leg, which the fixture prepares later, so this gate reads
    state; the live proof is the final convergence poll.

    The SPM read needs a port-forward, so it runs only when the cheap facts hold; ``spm`` is ``None``
    (not read) before that."""
    state: dict[str, bool | None] = {
        "scopes": tool_scopes_present(admin),
        "cr": cr_has_request_packages(authpolicy_policies(scn.TOOL_WORKLOAD)),
        "spm": None,
    }
    if state["scopes"] and state["cr"]:
        client = workload_client(admin, scn.TOOL_WORKLOAD)
        state["spm"] = bool(client) and spm_present(client["clientId"])
    return state


def workload_aud_scope(workload: str) -> str:
    """The operator's audience client scope of ``workload`` in ``NAMESPACE`` (rossoctl/operator
    ``keycloak.AudienceScopeName`` of ``<ns>/<workload>``)."""
    return f"agent-{NAMESPACE}-{workload}-aud"


def client_credentials_secret_name(workload: str) -> str:
    """The client-credentials Secret the operator writes for ``workload`` in ``NAMESPACE`` (rossoctl/operator
    ``clientreg.KeycloakClientCredentialsSecretName``; ``demo/use-cases/onboarding/restore.sh`` names it
    the same way)."""
    key = f"{NAMESPACE}\0{workload}\0rossoctl-keycloak-client-credentials"
    return "rossoctl-keycloak-client-credentials-" + hashlib.sha256(key.encode()).hexdigest()[:16]


def delete_workload_registrations(admin, realm: str) -> None:
    """Explicitly delete both workloads' Keycloak footprint — their clients, their ``*-aud`` audience
    client scopes, and the operator's client-credentials Secret — so teardown does not trust an
    unverified operator cascade. Best-effort + tolerant (already-absent is fine), so it is safe to run
    both at startup (pristine slate) and at teardown.

    ``cleanup_provisioned`` only clears the ``github-agent.`` / ``github-tool.``-**prefixed** roles and
    scopes; the operator's ``*-aud`` scopes (e.g. ``agent-team1-github-tool-aud``, no ``.`` after the
    workload) and the ``rossoctl-keycloak-client-credentials-<hash>`` Secrets are not covered there. This
    sweep removes them by their **exact** names (``workload_aud_scope``,
    ``client_credentials_secret_name``): other workloads in the namespace have theirs there too, for
    example the production tool's ``agent-team1-github-tool-mcp-aud``, which a substring match would
    take."""
    from keycloak.exceptions import KeycloakError

    admin.change_current_realm(realm)
    target_client_names = {f"{NAMESPACE}/{scn.AGENT_WORKLOAD}", f"{NAMESPACE}/{scn.TOOL_WORKLOAD}"}
    for client in admin.get_clients():
        if client.get("name") in target_client_names:
            try:
                admin.delete_client(client["id"])
            except KeycloakError as exc:
                log.warning("teardown: delete client %r failed: %s", client.get("name"), exc)

    workloads = (scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD)
    aud_scopes = {workload_aud_scope(w) for w in workloads}
    for scope in admin.get_client_scopes():
        name = scope.get("name", "")
        if name in aud_scopes:
            try:
                admin.delete_client_scope(scope["id"])
            except KeycloakError as exc:
                log.warning("teardown: delete audience client scope %r failed: %s", name, exc)

    # The operator mints one ``rossoctl-keycloak-client-credentials-<hash>`` Secret per client, named
    # from (namespace, workload). Tolerant — an already-absent Secret is not a teardown error.
    for workload in workloads:
        secret = client_credentials_secret_name(workload)
        _kubectl_try("delete", "secret", secret, "-n", NAMESPACE, "--ignore-not-found")


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
# Outbound token-exchange leg prep — so OPA is actually consulted outbound
# ======================================================================================
#
# The tool check is only reached if ``token-exchange-aiac`` first exchanges the agent's call to
# github-tool. It has no routes: it derives the audience ``spiffe://<td>/ns/<ns>/sa/github-tool`` from
# the host and asks Keycloak, so the only prep is (B.1) the agent's Keycloak client granted the
# github-tool audience scope as a **default** scope — the plugin requests no ``scope``, so an optional
# scope is never applied and the exchange answers 403 "not granted" — and (B.2) the agent restarted, so
# a github-tool audience it remembered as unknown before the tool's client existed (cached for 5 min)
# is asked again. The leg is necessary: the agent's outbound is a pass-through, but github-tool's
# inbound ``jwt-validation`` accepts only a token whose audience is github-tool, so
# ``token-exchange-aiac`` must mint it.


def _tool_audience(trust_domain: str) -> str:
    """The RFC 8693 ``audience`` for the github-tool exchange — its SPIFFE ID in ``trust_domain``."""
    return f"spiffe://{trust_domain}/ns/{NAMESPACE}/sa/{scn.TOOL_WORKLOAD}"


def _tool_aud_scope() -> str:
    """The realm client-scope whose audience mapper stamps the github-tool audience."""
    return workload_aud_scope(scn.TOOL_WORKLOAD)


def grant_exchange_scope(admin) -> None:
    """Grant the agent's Keycloak client the github-tool audience scope as a **default** scope, so
    ``token-exchange-aiac``'s exchange to the github-tool audience (no ``scope`` requested) is granted.

    Resolves the agent client by its SPIFFE ``clientId`` (``.../sa/github-agent``) or its
    ``name`` (``{ns}/github-agent``), and the client scope by name (``agent-{ns}-github-tool-aud``).
    Idempotent — Keycloak's assign-default-scope is a PUT. Raises ``RuntimeError`` on any Keycloak error."""
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
    # The same move as _link_default_scope in src/aiac/idp/service/configuration/keycloak/main.py: an
    # optional link (the old optional grant of this harness) is moved to default first, since Keycloak
    # silently skips a default link of a scope already linked as optional. Copied, not imported:
    # importing that module configures the root logger and builds its FastAPI app in the test process.
    # Every Keycloak error raises: the assign is an idempotent PUT, so none is benign, and without the
    # default link every exchange is refused much later, far from this cause.
    try:
        if any(s.get("id") == scope["id"] for s in admin.get_client_optional_client_scopes(client_uuid)):
            admin.delete_client_optional_client_scope(client_uuid, scope["id"])
        admin.add_client_default_client_scope(client_uuid, scope["id"], {})
    except KeycloakError as exc:
        raise RuntimeError(
            f"could not link {aud_scope!r} to {NAMESPACE}/{scn.AGENT_WORKLOAD} as a default scope: {exc} — "
            "without it token-exchange-aiac refuses every call to the tool"
        ) from exc


def restart_agent(namespace: str) -> None:
    """Restart the agent Deployment so ``token-exchange-aiac`` starts with empty caches (an audience
    it remembered as unknown is asked again) and its OPA sidecar re-fetches the recomposed bundle."""
    kubectl("rollout", "restart", f"deployment/{AGENT_DEPLOYMENT}", "-n", namespace, timeout=60)
    kubectl_rollout_status(f"deployment/{AGENT_DEPLOYMENT}", namespace=namespace, timeout=180)


# ======================================================================================
# The subject on every leg (D31) — the subject scope ``aiac-username-sub`` and the ``sub`` probes
# ======================================================================================
#
# The policy keys users by **username**, and AuthBridge's ``jwt-validation`` reads the subject from the
# token ``sub``. One client scope, ``aiac-username-sub``, gives ``sub`` = username on every leg (D31).
# AIAC links it as a default scope to:
#
#   * the platform **login** client ``rossoctl`` — at the IdP Configuration Service startup and again
#     at each onboarding — so the login token has it (``verify_login_subject``);
#   * each client it onboards (Provision, before ``client.type``), so the **exchanged** token has it:
#     the Keycloak standard token exchange applies only the requester (agent) client's scopes.
#
# Both links are AIAC's own steps, so a missing link is an AIAC fault: ``require_subject_scope`` fails
# the run (it is not a skip). The scope has no ``aiac.managed`` marker (it is shared by many clients, so
# a marker would make it an own scope of each linked service). ``rossoctl`` has no client mapper of its
# own that writes ``sub``: no AIAC step adds one.

# The shared subject scope and the mapping it must carry. The harness never imports ``aiac``, so these
# repeat ``_SUBJECT_SCOPE`` / ``_SUBJECT_MAPPER`` and the mapper representation of the IdP service.
SUBJECT_SCOPE = "aiac-username-sub"
SUBJECT_MAPPER = "username-to-sub"
SUBJECT_MAPPER_TYPE = "oidc-usermodel-property-mapper"
SUBJECT_MAPPER_CONFIG: dict[str, str] = {
    "user.attribute": "username",
    "claim.name": "sub",
    "access.token.claim": "true",
}

# A client mapper on the login client that writes the username into ``sub`` (the old manual runbook
# step, now replaced by the scope link) is found by this mapping only.
LOGIN_MAPPER_CONFIG: dict[str, str] = {"user.attribute": "username", "claim.name": "sub"}

# The provisioning marker (PRD §10). The subject scope is the one AIAC-provisioned scope without it.
AIAC_MANAGED_ATTRIBUTE = "aiac.managed"

# The Keycloak client authenticator of a client that authenticates with its client secret. The harness can
# exchange a token as the agent client only with that authenticator (``exchanged_subject``).
CLIENT_SECRET_AUTHENTICATOR = "client-secret"


def _carries_aiac_managed(attributes: dict | None) -> bool:
    """True when ``attributes`` carry the ``aiac.managed`` marker. A client-scope value is a plain
    string and a realm-role value a list of strings; accept both (as the IdP service does)."""
    value = (attributes or {}).get(AIAC_MANAGED_ATTRIBUTE)
    return "true" in value if isinstance(value, list) else value == "true"


def _config_has(mapper: dict, config: Mapping[str, str]) -> bool:
    """True when the mapper's ``config`` holds every ``config`` pair (other keys are free)."""
    actual = mapper.get("config") or {}
    return all(actual.get(key) == value for key, value in config.items())


def is_subject_mapper(mapper: dict) -> bool:
    """True when ``mapper`` (a protocol-mapper representation) is the mapper the subject scope must
    carry: type ``SUBJECT_MAPPER_TYPE`` with every ``SUBJECT_MAPPER_CONFIG`` pair (the username into
    the access-token ``sub``). The name is not checked: the mapping is what sets ``sub``."""
    return mapper.get("protocolMapper") == SUBJECT_MAPPER_TYPE and _config_has(mapper, SUBJECT_MAPPER_CONFIG)


def is_login_subject_mapper(mapper: dict) -> bool:
    """True when ``mapper`` maps the username into ``sub`` (``LOGIN_MAPPER_CONFIG``) — a client mapper
    of the login client that would be a second source of ``sub`` (none is expected)."""
    return _config_has(mapper, LOGIN_MAPPER_CONFIG)


def _mapper_summary(mapper: dict) -> str:
    """A short form of a mapper for a problem message: its name, type and the two mapping keys."""
    config = mapper.get("config") or {}
    return (
        f"{mapper.get('name')!r} ({mapper.get('protocolMapper')}: user.attribute={config.get('user.attribute')!r}, "
        f"claim.name={config.get('claim.name')!r}, access.token.claim={config.get('access.token.claim')!r})"
    )


def subject_scope_problems(
    scope: dict | None,
    mappers: Sequence[dict],
    client_default_scope_ids: Mapping[str, Collection[str] | None],
    login_default_scope_ids: Collection[str] | None,
    *,
    client_optional_scope_ids: Mapping[str, Collection[str]] | None = None,
    login_optional_scope_ids: Collection[str] | None = None,
) -> list[str]:
    """Each way the live subject-scope state differs from D31, as one readable sentence that names the
    object; an empty list means the state is correct. **Pure** — it decides from data already read from
    the admin API (``subject_scope_link_problems`` reads it), so it is unit-testable offline.

    * ``scope`` — the client-scope representation of ``SUBJECT_SCOPE`` (``None`` when it is missing);
    * ``mappers`` — the protocol mappers of that scope;
    * ``client_default_scope_ids`` — for each onboarded client (keyed by its name, ``{ns}/{workload}``),
      the ids of its **default** client scopes, or ``None`` when the client is not registered;
    * ``login_default_scope_ids`` — the ids of the **default** client scopes of the login client
      ``rossoctl``, or ``None`` when the login client does not exist;
    * ``client_optional_scope_ids`` / ``login_optional_scope_ids`` — optional: the ids of each onboarded
      client's / the login client's optional scopes, only to say in a problem that a client links the
      scope as optional.

    The problems: the scope is missing; it carries the ``aiac.managed`` marker; it has no mapper of the
    expected type and config; an onboarded client or the login client is missing or does not link it as
    a **default** scope (an optional link does not count: the mapper of an optional scope runs only when
    the token request names the scope, so ``sub`` would stay the user ID)."""
    if scope is None:
        clients = ", ".join(repr(name) for name in client_default_scope_ids) or "none"
        return [
            f"client scope {SUBJECT_SCOPE!r} does not exist in realm {TEST_REALM!r}, so no onboarded client "
            f"({clients}) can link it"
        ]

    problems: list[str] = []
    if _carries_aiac_managed(scope.get("attributes")):
        problems.append(
            f"client scope {SUBJECT_SCOPE!r} carries the {AIAC_MANAGED_ATTRIBUTE!r} marker; the shared subject "
            "scope must not (a marked scope linked to many clients becomes an own scope of each linked service)"
        )
    if not any(is_subject_mapper(mapper) for mapper in mappers):
        found = ", ".join(_mapper_summary(mapper) for mapper in mappers) or "none"
        problems.append(
            f"client scope {SUBJECT_SCOPE!r} has no {SUBJECT_MAPPER_TYPE} mapper with {SUBJECT_MAPPER_CONFIG} "
            f"(the {SUBJECT_MAPPER!r} mapper); its mappers: {found}"
        )

    scope_id = scope.get("id")
    optional = client_optional_scope_ids or {}
    for client, default_ids in client_default_scope_ids.items():
        if default_ids is None:
            problems.append(f"onboarded client {client!r} is not registered, so it cannot link {SUBJECT_SCOPE!r}")
        elif scope_id not in default_ids:
            how = "links it only as an optional scope" if scope_id in optional.get(client, ()) else "does not link it"
            problems.append(
                f"onboarded client {client!r} does not have {SUBJECT_SCOPE!r} as a default scope ({how}; the "
                "mapper of an optional scope runs only when the token request names it, so the exchanged "
                "token keeps sub = the user ID)"
            )
    if login_default_scope_ids is None:
        problems.append(
            f"the login client {KEYCLOAK_CLIENT_ID!r} does not exist in realm {TEST_REALM!r}, so it cannot link "
            f"{SUBJECT_SCOPE!r}"
        )
    elif scope_id not in login_default_scope_ids:
        linked_optional = scope_id in (login_optional_scope_ids or ())
        how = "links it only as an optional scope" if linked_optional else "does not link it"
        problems.append(
            f"the login client {KEYCLOAK_CLIENT_ID!r} does not have {SUBJECT_SCOPE!r} as a default scope ({how}; "
            "the login token keeps sub = the user ID)"
        )
    return problems


def login_client(admin, realm: str = TEST_REALM, client_id: str = KEYCLOAK_CLIENT_ID) -> dict | None:
    """The Keycloak client representation of the login client ``client_id`` (default ``rossoctl``,
    ``KEYCLOAK_CLIENT_ID``: the client the harness mints user tokens through) in ``realm``; ``None`` if
    absent. A query filtered by ``clientId`` finds its UUID, so the call does not list every client of the
    realm."""
    admin.change_current_realm(realm)
    client_uuid = admin.get_client_id(client_id)
    return admin.get_client(client_uuid) if client_uuid else None


def _update_client(admin, realm: str, client_uuid: str, fields: dict) -> None:
    """A partial update of one Keycloak client of ``realm``: only ``fields`` change. In ``attributes``,
    only the given keys change, and ``""`` removes a key (Keycloak 26). So the write never puts a stale
    copy of the whole client over a change that the IdP Configuration Service made at the same time (for
    example its D31 scope link). The caller handles the errors."""
    admin.change_current_realm(realm)
    admin.update_client(client_uuid, fields)


# Direct Access Grants on the login client. The harness mints user tokens with the password grant, so the
# grant must be on. When the harness turns it on, it writes this client attribute in the same update. The
# marker is the record of the harness sessions that hold the grant, and it is in Keycloak, not in process
# memory. Its value is a JSON object: holder id (``_dag_holder``) -> expiry (epoch seconds, the hold time +
# ``_dag_hold_ttl``). A release removes its own holder and turns the grant off only when no other live
# (not expired) holder remains, so two runs at the same time do not turn the grant off under each other.
# A run that is killed before its release leaves its holder; the entry expires, and the next run takes the
# grant over and turns it off at its end. A marker with no live holder, or a value that is not such an
# object (the legacy ``"true"`` of an earlier harness), is stale: it is taken over the same way. A grant
# that is on with no marker belongs to the realm (or to an operator: the runbook snippet removes the
# marker), and the harness never changes it. Keycloak has no compare-and-set: two holds at the same
# instant can lose one entry, and then the first release can turn the grant off early (a skip or a
# failed mint in the other run, never a false pass).
DAG_MARKER_ATTRIBUTE = "aiac.test.direct-access-grants-by-harness"

# How long a holder entry stays live: longer than a whole system run. Override with this env var.
DAG_HOLD_TTL_ENV = "AIAC_DAG_HOLD_TTL_SECONDS"
DAG_HOLD_TTL_DEFAULT = 6 * 3600.0

# The run id of this process when pytest-xdist does not give one (a run with no ``-n``).
_PROCESS_RUN_ID = uuid.uuid4().hex

# The login clients whose grant the harness holds in this session: ``(realm, clientId)`` -> ``(admin,
# client UUID)``. ``release_direct_access_grants`` empties it at session end (``test/system/conftest.py``).
_dag_holds: dict[tuple[str, str], tuple[object, str]] = {}


def _dag_holder() -> str:
    """The holder id of this pytest session: ``<run id>:<worker>``. The run id is the same in all xdist
    workers of one run (``PYTEST_XDIST_TESTRUNUID``; else one id for this process). Each xdist worker is
    its own pytest session with its own session-end release, so the worker id (``PYTEST_XDIST_WORKER``)
    is part of the holder: the first worker to finish must not turn the grant off under its siblings."""
    run = os.environ.get("PYTEST_XDIST_TESTRUNUID") or _PROCESS_RUN_ID
    return f"{run}:{os.environ.get('PYTEST_XDIST_WORKER', 'main')}"


def _dag_hold_ttl() -> float:
    """The holder TTL in seconds (``DAG_HOLD_TTL_ENV``); a missing, non-numeric or non-positive value
    gives the default."""
    try:
        ttl = float(os.environ.get(DAG_HOLD_TTL_ENV, ""))
    except ValueError:
        return DAG_HOLD_TTL_DEFAULT
    return ttl if ttl > 0 else DAG_HOLD_TTL_DEFAULT


def _now() -> float:
    """The wall-clock time in epoch seconds (a seam for the unit tests)."""
    return time.time()


def _dag_holders(client: dict) -> dict[str, float] | None:
    """The holders that the marker of ``client`` records (holder id -> expiry), or ``None`` when the
    client has no marker. A value that is not a JSON object of holder -> number (the legacy ``"true"``)
    gives ``{}``: a stale marker with no holder."""
    raw = (client.get("attributes") or {}).get(DAG_MARKER_ATTRIBUTE)
    if isinstance(raw, list):  # an attribute read as a list of values
        raw = raw[0] if raw else None
    if not raw:
        return None
    try:
        doc = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(doc, dict):
        return {}
    return {
        str(holder): float(expiry)
        for holder, expiry in doc.items()
        if isinstance(expiry, (int, float)) and not isinstance(expiry, bool)
    }


def _live_others(holders: dict[str, float], me: str) -> dict[str, float]:
    """The holders other than ``me`` whose entry has not expired."""
    now = _now()
    return {holder: expiry for holder, expiry in holders.items() if holder != me and expiry > now}


def _marker_value(holders: dict[str, float]) -> str:
    """The marker attribute value for ``holders`` (sorted, so the same holders give the same value)."""
    return json.dumps({holder: round(expiry) for holder, expiry in sorted(holders.items())})


def _login_client_read_skip(realm: str, client_id: str, exc: Exception) -> str:
    """The skip message for a read of the login client that failed with ``exc``."""
    if getattr(exc, "response_code", None) == 404:
        return (
            f"the realm {realm!r} does not exist, so it has no login client {client_id!r} to enable Direct "
            f"Access Grants on ({exc}). The realm owns its login client; the harness does not create it."
        )
    return (
        f"cannot read the login client {client_id!r} in realm {realm!r} to enable Direct Access Grants: "
        f"{type(exc).__name__}: {exc}. Make sure that the admin user has the view-clients and manage-clients roles."
    )


def hold_direct_access_grants(admin, realm: str, client_id: str = KEYCLOAK_CLIENT_ID) -> None:
    """Make sure that Direct Access Grants is on for the login client ``client_id`` of ``realm`` until the
    end of the pytest session, so that ``mint_token`` can use the password grant.

    * The first call of the session reads the client. Later calls for the same client do nothing.
    * A grant that is on with no marker (``DAG_MARKER_ATTRIBUTE``) is the realm's own setting: it is not
      written, and it is not turned off later.
    * Else this session adds itself as a holder (``_dag_holder``, with an expiry) and turns the grant on,
      in one partial update (``_update_client``). The update keeps the other live holders and drops the
      expired ones. A marker with no live holder (a run that did not finish, or the legacy ``"true"``) is
      taken over. A grant that is off with the marker on is turned on again.

    ``release_direct_access_grants`` removes this holder at session end, and turns the grant off when no
    other live holder remains.

    ``pytest.skip`` (with the cause) when the realm or the login client does not exist (nothing is
    created) or when the read or the update fails, for any reason (refused by the admin API, a transport
    error, an unexpected response). These are prerequisite gaps, not AIAC failures. An update that fails
    is undone at once if the server applied it (``_release_one`` reads the client again), so a skip leaves
    the realm as it was."""
    import pytest

    key = (realm, client_id)
    if key in _dag_holds:
        return
    try:
        client = login_client(admin, realm, client_id)
    except Exception as exc:  # any read failure is a prerequisite gap: skip with the cause
        pytest.skip(_login_client_read_skip(realm, client_id, exc))
    if client is None:
        pytest.skip(
            f"the login client {client_id!r} does not exist in realm {realm!r}, so the harness cannot mint a "
            "user token through it (the realm owns its login client; the harness does not create it)"
        )
    holders = _dag_holders(client)
    if client.get("directAccessGrantsEnabled") and holders is None:
        return
    me = _dag_holder()
    others = _live_others(holders or {}, me)
    if holders is not None and not others:
        log.warning(
            "an earlier run turned on Direct Access Grants on the login client %r in realm %r and did not "
            "turn it off (no live holder in %r): this session takes it over and turns it off at its end",
            client_id,
            realm,
            DAG_MARKER_ATTRIBUTE,
        )
    elif others:
        log.info(
            "Direct Access Grants on the login client %r in realm %r is held by other live runs %s: this "
            "session joins them",
            client_id,
            realm,
            sorted(others),
        )
    # Record the hold before the write: a write that raises after the server applied it is still undone.
    _dag_holds[key] = (admin, client["id"])
    try:
        _update_client(
            admin,
            realm,
            client["id"],
            {
                "directAccessGrantsEnabled": True,
                "attributes": {DAG_MARKER_ATTRIBUTE: _marker_value({**others, me: _now() + _dag_hold_ttl()})},
            },
        )
    except Exception as exc:  # a refused write or a lost response: undo if applied, then skip
        _release_one(key)
        pytest.skip(
            f"cannot enable Direct Access Grants on the login client {client_id!r} in realm {realm!r}: "
            f"{type(exc).__name__}: {exc}. "
            "Give the admin user the manage-clients role, or enable the grant by hand "
            "(k8s/opa-kind-runbook.md, 'Direct Access Grants on the login client')."
        )
    log.warning(
        "holding Direct Access Grants on the login client %r in realm %r as %r (turned off again at session "
        "end when no other run holds it)",
        client_id,
        realm,
        me,
    )


def _release_one(key: tuple[str, str]) -> None:
    """Remove this session's holder from one held login client, and turn its grant off (and remove the
    marker) when no other live holder remains. The client is read again first: when the marker is gone,
    someone else took the grant over during the run (the runbook snippet removes the marker), and the
    grant is not changed. When another live holder remains, only this holder is removed (the expired
    ones are dropped too) and the grant stays on.
    Best-effort: any error is logged, never raised, so it does not mask a failure that is propagating.
    The marker stays when the write fails, so the entry expires and a later run turns the grant off."""
    admin, client_uuid = _dag_holds.pop(key)
    realm, client_id = key
    me = _dag_holder()
    try:
        admin.change_current_realm(realm)
        client = admin.get_client(client_uuid)
        holders = _dag_holders(client)
        if holders is None:
            log.info(
                "Direct Access Grants on the login client %r in realm %r has no harness marker now: not changed",
                client_id,
                realm,
            )
            return
        others = _live_others(holders, me)
        if others:
            if me in holders:
                _update_client(admin, realm, client_uuid, {"attributes": {DAG_MARKER_ATTRIBUTE: _marker_value(others)}})
            log.info(
                "Direct Access Grants on the login client %r in realm %r stays on: other live runs %s hold it",
                client_id,
                realm,
                sorted(others),
            )
            return
        _update_client(
            admin, realm, client_uuid, {"directAccessGrantsEnabled": False, "attributes": {DAG_MARKER_ATTRIBUTE: ""}}
        )
    except Exception as exc:  # best-effort teardown: log, never mask the real failure
        log.error(
            "cannot release Direct Access Grants on the login client %r in realm %r: %s. The marker %r "
            "stays, so its holder %r expires and a later run turns the grant off.",
            client_id,
            realm,
            exc,
            DAG_MARKER_ATTRIBUTE,
            me,
        )


def release_direct_access_grants() -> None:
    """At the end of the pytest session (``test/system/conftest.py``): release each login client that
    ``hold_direct_access_grants`` holds (``_release_one``). A realm that had the grant on is not changed.
    A no-op when no stack ran."""
    for key in list(_dag_holds):
        _release_one(key)


def _workload_list(workloads: str | Sequence[str]) -> list[str]:
    """One workload name or a sequence of them, as a list."""
    return [workloads] if isinstance(workloads, str) else list(workloads)


def subject_scope_link_problems(admin, workloads: str | Sequence[str]) -> list[str]:
    """Read the live subject-scope state of ``workloads`` (one workload name or a list) from the admin
    API and return ``subject_scope_problems`` over it; an empty list means the state is correct.

    Reads, in realm ``TEST_REALM``: ``SUBJECT_SCOPE`` by name (``get_client_scopes``) and its mappers;
    each workload's client (``workload_client``) and its default and optional client scopes; and the
    default and optional client scopes of the login client ``rossoctl``. Read-only. Raises when the
    admin API cannot be read."""
    admin.change_current_realm(TEST_REALM)
    scope = next((s for s in admin.get_client_scopes() if s.get("name") == SUBJECT_SCOPE), None)
    mappers = admin.get_mappers_from_client_scope(scope["id"]) if scope else []

    default_ids: dict[str, set[str] | None] = {}
    optional_ids: dict[str, set[str]] = {}
    for workload in _workload_list(workloads):
        name = f"{NAMESPACE}/{workload}"
        client = workload_client(admin, workload)
        if client is None:
            default_ids[name] = None
            continue
        default_ids[name] = {s.get("id") for s in admin.get_client_default_client_scopes(client["id"])}
        optional_ids[name] = {s.get("id") for s in admin.get_client_optional_client_scopes(client["id"])}

    login = login_client(admin)
    login_default: set[str] | None = None
    login_optional: set[str] = set()
    if login is not None:
        login_default = {s.get("id") for s in admin.get_client_default_client_scopes(login["id"])}
        login_optional = {s.get("id") for s in admin.get_client_optional_client_scopes(login["id"])}

    return subject_scope_problems(
        scope,
        mappers,
        default_ids,
        login_default,
        client_optional_scope_ids=optional_ids,
        login_optional_scope_ids=login_optional,
    )


# The client attribute Provision writes last (``set_service_type``, right after ``link_subject_scope``;
# ``aiac.idp.service.configuration.keycloak.main._SERVICE_TYPE_ATTRIBUTE``). A failed earlier call raises
# 502, so a client with it ended Provision. The pre-run slate deletes the clients, so it is fresh per run.
SERVICE_TYPE_ATTRIBUTE = "client.type"


def provision_ended(client: dict | None) -> bool:
    """Whether Provision ended for ``client`` (a ``workload_client`` representation): it has
    ``SERVICE_TYPE_ATTRIBUTE``."""
    return bool(((client or {}).get("attributes") or {}).get(SERVICE_TYPE_ATTRIBUTE))


def require_subject_scope(admin, workloads: str | Sequence[str]) -> None:
    """Raise ``RuntimeError`` that lists the problems when the subject scope is not in place for
    ``workloads`` (one workload name or a list; ``subject_scope_link_problems``). ``onboarded_stack``
    calls it right after each workload is onboarded (``await_onboarded``).

    A failure, not a skip: AIAC links ``aiac-username-sub`` itself at onboarding (Provision, through the
    IdP's ``POST /services/{id}/subject-scope``, which also links it to the login client), so a missing
    link is an AIAC fault, not a missing prerequisite. Without the link the token keeps ``sub`` = the
    user ID, and the calls are denied later with no clear cause; this check gives the cause at once.
    The message says, per workload, whether Provision ended (``provision_ended``): only then is the
    missing link a fault of the images that link."""
    problems = subject_scope_link_problems(admin, workloads)
    if not problems:
        return
    ended = {w: provision_ended(workload_client(admin, w)) for w in _workload_list(workloads)}
    done = [f"{NAMESPACE}/{w}" for w, e in ended.items() if e]
    not_done = [f"{NAMESPACE}/{w}" for w, e in ended.items() if not e]
    causes = []
    if any(KEYCLOAK_CLIENT_ID in p and "login client" in p for p in problems):
        causes.append(
            f"aiac-pdp-config links the scope to the login client {KEYCLOAK_CLIENT_ID!r} at its start and on each "
            "link call: check that its image has the D31 login link, and its log"
        )
    if done:
        causes.append(
            f"Provision ended for {done} ({SERVICE_TYPE_ATTRIBUTE} is set), so it ran without the link: an "
            "aiac-agent whose Provision does not call link_subject_scope (POST /services/{id}/subject-scope), "
            f"or an aiac-pdp-config that does not link the scope (it also links the login client "
            f"{KEYCLOAK_CLIENT_ID!r}): rebuild and redeploy aiac-agent and aiac-pdp-config"
        )
    if not_done:
        causes.append(
            f"Provision has not ended for {not_done} (no {SERVICE_TYPE_ATTRIBUTE}), so the link is not made yet: "
            "this check ran before the onboarding (see the Controller log)"
        )
    raise RuntimeError(
        f"the subject scope {SUBJECT_SCOPE!r} (D31) is not in place for {_workload_list(workloads)} in realm "
        f"{TEST_REALM!r}: " + "; ".join(problems) + ". " + "; ".join(causes) + "."
    )


def login_subject(ctx: dict, user: str) -> object:
    """The ``sub`` of a password-grant token for ``user`` through the login client ``rossoctl`` (D31: it
    comes from the login client's default scope ``aiac-username-sub``)."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    return jwt_claim(token, "sub")


def exchanged_subject(ctx: dict, user: str) -> str:
    """The ``sub`` of a token that the agent client exchanges for ``user`` to the tool audience (D31: it
    comes from the agent's default scope ``aiac-username-sub``).

    Mints ``user``'s login token through ``rossoctl``, reads the agent client and its client secret
    from the admin API, and sends the request that AuthBridge's ``token-exchange-aiac`` sends: a standard
    token exchange to ``_tool_audience(ctx["trust_domain"])`` with **no** ``scope`` (``exchange_token``), so only the agent's
    default scopes apply. The Keycloak standard token exchange builds the token for the requester
    (the agent), so its ``sub`` comes from the agent's scopes only.

    The harness can authenticate as the agent only with its client secret. AuthBridge's
    ``token-exchange-aiac`` (``k8s/opa-kind-enable.sh``) authenticates the same way: it reads the secret
    the operator writes to ``/shared/client-secret.txt`` and has no other way. So on that deployment the
    agent client uses the ``client-secret`` authenticator and the exchange must succeed:
    a refused client authentication then raises. ``pytest.skip`` only when the agent client uses
    another authenticator (``clientAuthenticatorType``, for example ``federated-jwt`` for a SPIFFE
    JWT-SVID) or has no readable secret. Then no other check reads the exchanged ``sub`` directly; only
    the tool-call verdicts (``test_outbound``) depend on it. Any other failure of the exchange raises
    ``TokenExchangeError`` (the HTTP status and the body)."""
    import pytest
    from keycloak.exceptions import KeycloakError

    admin = ctx["admin"]
    subject_token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    agent = workload_client(admin, scn.AGENT_WORKLOAD)
    if agent is None:
        raise AssertionError(f"no Keycloak client {NAMESPACE}/{scn.AGENT_WORKLOAD} in realm {ctx['realm']!r}")

    authenticator = agent.get("clientAuthenticatorType")
    skip_note = (
        "the harness can exchange only with a client secret; require_subject_scope still checks that the "
        "agent client links the subject scope"
    )
    if authenticator != CLIENT_SECRET_AUTHENTICATOR:
        pytest.skip(
            f"the agent client {agent.get('clientId')!r} uses the {authenticator!r} client authenticator, "
            f"not {CLIENT_SECRET_AUTHENTICATOR!r} — {skip_note}"
        )
    try:
        secret = (admin.get_client_secrets(agent["id"]) or {}).get("value")
    except KeycloakError as exc:
        pytest.skip(f"cannot read the client secret of {agent.get('clientId')!r} ({exc}) — {skip_note}")
    if not secret:
        pytest.skip(f"the agent client {agent.get('clientId')!r} has no client secret — {skip_note}")

    try:
        token = exchange_token(
            subject_token,
            keycloak_url=ctx["keycloak_url"],
            realm=ctx["realm"],
            client_id=agent["clientId"],
            client_secret=secret,
            audience=_tool_audience(ctx["trust_domain"]),
        )
    except TokenExchangeError as exc:
        if exc.client_auth_refused:
            # A client-secret client whose own secret is refused is a real fault, not a harness limit.
            raise AssertionError(
                f"Keycloak refused the client-secret authentication of the agent client "
                f"{agent.get('clientId')!r} (HTTP {exc.status}, {exc.error}), although the client uses the "
                f"{CLIENT_SECRET_AUTHENTICATOR!r} authenticator: {exc}"
            ) from exc
        raise
    sub = jwt_claim(token, "sub")
    if not isinstance(sub, str):
        raise AssertionError(f"the exchanged token for {user!r} has no string 'sub' claim: {sub!r}")
    return sub


# ======================================================================================
# Live decisions — mint a user token, send a real request through AuthBridge, classify the plugin
# ======================================================================================


def inbound_raw(ctx: dict, user: str) -> tuple[int | None, str]:
    """Mint a fresh ``user`` token, send a real inbound request through AuthBridge, and return the raw
    ``(http_code, body)`` — for ``probe_hint`` and for diagnostics."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    return inbound_probe(token, namespace=ctx["namespace"], agent_service=scn.AGENT_WORKLOAD)


def inbound_decision(ctx: dict, user: str) -> str:
    """Mint a fresh ``user`` token and send a real inbound request through AuthBridge; return the real
    OPA plugin's classified decision (``"allow"`` 200 / ``"deny"`` 403 / ``"error"`` otherwise)."""
    code, _ = inbound_raw(ctx, user)
    return inbound_outcome(code)


def probe_hint(code: int | None, body: str) -> str:
    """What the raw answer ``(code, body)`` of an inbound probe means, as a hint for a failure
    message; ``""`` for an allow. **Pure.** From the AuthBridge reject bodies (``../cortex``,
    ``pipeline.Violation.Render``: ``{"error", "message", "plugin"}``):

    * 503 from OPA ``opa policy engine not initialized``: the sidecar has loaded no bundle yet;
    * 403 that names OPA: OPA denied it, from the CR (the combiner denies a pod with no CR, D20);
    * any other 403: not from OPA (for example the Istio waypoint);
    * no code, or ``000``: the probe pod failed, or the Service was not reachable."""
    if code == 200:
        return ""
    if not code:
        return "no HTTP answer: the probe pod failed, or the Service was not reachable from the namespace."
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        doc = None
    doc = doc if isinstance(doc, dict) else {}
    if code == 403:
        if is_opa_violation(doc):
            return "OPA denied it: check the workload's CR (with no CR, the combiner denies the pod, D20)."
        return "a 403 that is not from OPA (for example the Istio waypoint)."
    plugin, message = doc.get("plugin"), doc.get("message")
    if plugin == "opa" and message == "opa policy engine not initialized":
        return (
            "OPA has no bundle yet: the sidecar did not fetch one from bundle-service (reachable from the "
            "namespace? see the state dump), or its next poll has not come (10-120 s)."
        )
    if plugin:
        return f"the AuthBridge plugin {plugin!r} rejected it: {message!r}."
    return f"HTTP {code} with no AuthBridge reject body."


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
    decision (``outbound_outcome``): ``"deny"`` for an OPA verdict (github-tool's inbound 403);
    ``"allow"`` for a non-OPA 200; ``"error"`` for an exchange refusal, a 503 or a transport
    failure."""
    return outbound_outcome(*outbound_raw(ctx, user, tool_bare))


def outbound_deny_probe(ctx: dict, user: str, tool_bare: str) -> dict:
    """Drive one outbound ``tools/call`` and return ``{"decision", "origin", "code", "body"}``:
    ``decision`` from ``outbound_outcome``, and ``origin`` from ``deny_origin`` — where a deny comes
    from (``DENY_ORIGIN_TOOL_INBOUND`` / ``DENY_ORIGIN_AGENT_OUTBOUND``; ``None`` when it is not an OPA
    deny). Compare ``origin`` with ``DENY_ORIGIN_TOOL_INBOUND``: the tool's inbound decides each tool
    call."""
    code, body = outbound_raw(ctx, user, tool_bare)
    return {"decision": outbound_outcome(code, body), "origin": deny_origin(code, body), "code": code, "body": body}


# ======================================================================================
# Convergence probe — the parametrized readiness signal each policy supplies
# ======================================================================================


@dataclass(frozen=True)
class Observation:
    """What one probe of a ``ReadySignal`` saw: the classified ``decision`` and the raw ``(code, body)``,
    or the ``error`` when the probe raised (then ``decision`` is ``None``)."""

    decision: str | None = None
    code: int | None = None
    body: str = ""
    error: str | None = None


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

    def observe(self, ctx: dict) -> Observation:
        """Send this signal's live probe and return the classified verdict and the raw answer, so a
        failure message can print what the poll saw last."""
        if self.kind == "inbound":
            code, body = inbound_raw(ctx, self.subject)
            return Observation(inbound_outcome(code), code, body)
        code, body = outbound_raw(ctx, self.subject, self.tool_bare)
        return Observation(outbound_outcome(code, body), code, body)

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
    is skipped) nor probed nor asserted — on a tool-less rung Keycloak has no ``github-tool`` client, so
    token-exchange-aiac passes the call through un-exchanged (``audience_unknown``), and an outbound
    "deny" there would be the agent's outbound OPA (a pass-through, D24) on a request that reaches no
    tool, not the tool check. Rung 1's empty tool check is instead asserted at the unit level
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


def poll_signals(
    signals: Sequence[ReadySignal], ctx: dict, *, timeout: float, interval: float
) -> tuple[bool, dict[str, Observation]]:
    """Poll every signal in each round (no short-circuit) until all reach their ``expected`` verdict.
    Return ``(reached, last)``: ``last`` maps each label to the last ``Observation`` (with its ``error``
    when the probe raised), so the failure message needs no new probe."""
    last: dict[str, Observation] = {}

    def _round() -> bool:
        for sig in signals:
            try:
                last[sig.label()] = sig.observe(ctx)
            except Exception as exc:  # keep the error, so the message can name it
                last[sig.label()] = Observation(error=f"{type(exc).__name__}: {str(exc)[:200]}")
        return all(last[sig.label()].decision == sig.expected for sig in signals)

    return poll_until(_round, timeout=timeout, interval=interval), last


def signals_report(signals: Sequence[ReadySignal], last: Mapping[str, Observation]) -> str:
    """One line per signal from ``last`` (``poll_signals``): the decision against the expected one, the
    raw answer, and what it means (``probe_hint`` for an inbound answer). **Pure** — no new probe."""
    lines = []
    for sig in signals:
        seen = last.get(sig.label())
        if seen is None or seen.decision is None:
            lines.append(f"{sig.label()} not observed ({seen.error if seen else 'no probe ran'})")
            continue
        line = (
            f"{sig.label()}={seen.decision!r} (want {sig.expected!r}) [HTTP {seen.code}, body={str(seen.body)[:300]!r}]"
        )
        hint = probe_hint(seen.code, seen.body) if sig.kind == "inbound" else ""
        lines.append(f"{line} {hint}".rstrip())
    return "; ".join(lines)


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
    Store), so their order is not load-bearing. The caller owns capturing the CRs before
    (``capture_aiac_crs``), undeploying the workloads first and verifying the result — this only
    scrubs registrations + state, it does not delete Deployments."""
    delete_workload_registrations(admin, TEST_REALM)  # clients + *-aud scopes + credentials Secret
    delete_workload_crs()  # this run's (or a prior run's) agent and tool CRs
    sweep_authpolicies()  # any leaked AuthorizationPolicy CR — the OPA bundle self-cleans from the CR set
    cleanup_provisioned(admin, TEST_REALM)  # prefixed roles/scopes (Keycloak)
    clear_policy_store()  # Policy Store SPMs (PV survives redeploys)


@contextmanager
def _clean_slate(admin, workloads: Sequence[str], *, keycloak_url: str) -> Iterator[None]:
    """The pre-run slate and the teardown that ``onboarded_stack`` and ``pristine_stack`` share. The
    caller runs the skip gates first; the ``with`` body onboards (or fails to onboard) ``workloads``.

    At entry: Direct Access Grants on the login client (``hold_direct_access_grants``, before the first
    mutation, so a skip there leaves the cluster as it was; it is turned off at session end), a
    ``pre-run-slate`` CR capture, the no-workloads slate (undeploy both workloads,
    ``_scrub_to_pristine``, ``reenable_provisioned_clients``, poll the clients gone), the realm users and
    roles, and the ``sub`` check of a login token (``verify_login_subject``). At exit, also when the body
    raises or skips: a ``teardown`` CR capture first, then full-to-pristine (undeploy ``workloads`` in
    reverse order, ``_scrub_to_pristine``), verified (clients gone, no CR left). The users and the roles
    are shared realm state and stay."""
    # Direct Access Grants on the login client (the password grant of ``mint_token`` needs it).
    hold_direct_access_grants(admin, TEST_REALM)

    # Pre-run: start from a NO-WORKLOADS slate. The trigger is event-driven — deploying a workload only
    # re-fires ``CLIENT_CREATED`` if there is no client for it yet, so a leftover workload + its Keycloak
    # client from a prior run would silently swallow the event and onboarding would never trigger. Remove
    # both workloads and every registration first (best-effort, tolerant of already-absent), then poll the
    # clients actually gone before deploying. Capture the CRs first: a prior run's leftovers are evidence.
    label = _capture_label()  # the rung, read once here (a session fixture is torn down after the session)
    capture_aiac_crs("pre-run-slate", label=label)
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
    # Skip if a token can't be minted (the grant is on: ``hold_direct_access_grants`` above). The login token's
    # ``sub`` comes from ``aiac-username-sub``, which the IdP Configuration Service links to the login client
    # at startup (D31): fail if it isn't the username. ``require_subject_scope`` checks the links again after
    # each onboarding.
    verify_login_subject(keycloak_url=keycloak_url, realm=TEST_REALM, user="dev-user", password=scn.USER_PASSWORD)

    try:
        yield
    finally:
        # Capture every AIAC CR and the combiner to the pytest host FIRST — the undeploy and the scrub
        # remove or change them. Best-effort: it never raises, on the success and the failure path.
        capture_aiac_crs("teardown", label=label)
        capture_pod_logs("teardown", label=label)  # the Controller's log of this run (best-effort too)
        # Teardown — full-to-pristine, best-effort per step (each helper tolerates already-absent objects).
        for workload in reversed(list(workloads)):  # undeploy in reverse deploy order
            undeploy_workload(workload)
        # Explicit scrub — do not trust an unverified operator cascade. Same reset the pre-run slate runs.
        _scrub_to_pristine(admin)
        # Verify pristine: both clients gone AND no AuthorizationPolicy CR remains. A leaked footprint is
        # a test failure, not silent drift — but do not mask a failure already propagating out of the body.
        if not poll_until(
            lambda: not workload_clients_present(admin) and no_authpolicies_remain(),
            timeout=DEPLOY_TIMEOUT,
            interval=5,
        ):
            msg = (
                f"teardown did not restore pristine: Keycloak client(s) still present="
                f"{workload_clients_present(admin)}, AuthorizationPolicy CR(s) remain={not no_authpolicies_remain()} "
                f"in {NAMESPACE!r}. See docs/testing/uc1-onboarding-pipeline.md, step 6 (Teardown → pristine)."
            )
            if sys.exc_info()[0] is not None:
                log.error("%s [suppressed — a prior error is propagating]", msg)
            else:
                raise RuntimeError(msg)


@contextmanager
def onboarded_stack(
    workloads: list[str],
    *,
    policy_md: str = scn.POLICY_ABSTRACT,
    ready_signals: Sequence[ReadySignal] | None = None,
) -> Iterator[dict]:
    """Run one rung's whole live flow and yield a probe ``ctx`` for its assertions.

    ``ctx`` = ``{"admin", "namespace", "agent_pod", "keycloak_url", "realm", "tool_onboarded",
    "trust_domain"}``.

    Flow (event-driven trigger): skip cleanly (never false-pass) if the OPA pipeline or the event path
    is not wired, or the integration env is unset; capture any leftover CR to the pytest host
    (``capture_aiac_crs``, phase ``pre-run-slate``); **start from a no-workloads slate** (a leftover
    workload + its Keycloak client would stop the fresh deploy from re-firing ``CLIENT_CREATED``, so the
    event would never trigger), provision users/roles + clear the store; **load** the demo image(s) into
    the Kind node (``load_workload_images`` — build-if-absent, the images precondition), then **deploy**
    the given ``workloads`` **in order, one at a time** — each ``kubectl apply`` fires the production trigger
    (operator registers a Keycloak client -> Keycloak ``CLIENT_CREATED`` -> the ``aiac-event-listener``
    SPI publishes on NATS -> the agent consumer runs ``onboard_and_apply``, the same handler the retired
    ``POST /apply`` called) — waiting for each to converge before the next, and then checking that its
    client links the subject scope ``aiac-username-sub`` as a default scope (``require_subject_scope``,
    D31: AIAC makes this link at onboarding, so a missing link **fails** the run at once, with the
    problems listed, rather than as a deny in the final poll); enable the outbound leg
    (Part B: default client scope + agent restart, no route); then **poll real decisions** until
    ``bundle-service`` + OPA reflect this run's CR (and the outbound exchange has settled) before yielding.
    Teardown first captures every AIAC CR and the global combiner to the pytest host
    (``capture_aiac_crs``, phase ``teardown``; best-effort, it never masks a failure), then is
    **full-to-pristine** — the workloads and every registration are removed and the removal is
    verified. The users and the roles of ``provision_realm_and_users`` are shared realm state and stay.
    The slate and the teardown are ``_clean_slate``, shared with ``pristine_stack``. Direct Access Grants
    on the login client is on for the whole flow (``hold_direct_access_grants``, after the skip gates and
    before the pre-run slate) and is turned off again at session end if the harness turned it on.
    The capture directories are named for the test module that started the stack. The workload order is
    the rung's identity — e.g. rung 2 passes ``[agent, tool]`` so tool onboarding
    completes the tool check (it writes github-tool's own CR with both gates); rung 3 passes
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
    # poll below — never a skip, never a false pass. The gate also gives the trust domain the live
    # outbound leg exchanges for, from the same read of the config it approved.
    trust_domain = require_pipeline(namespace=NAMESPACE, workloads=[])
    creds = require_env_or_skip("KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    keycloak_url = creds["KEYCLOAK_URL"]

    admin = connect_admin()
    # Event-path skip gate — placed here (not at the ``require_pipeline`` line) because it needs the
    # admin client to read the realm's events config, and ``launcher`` has no KeycloakAdmin of its own.
    require_event_path(admin=admin, realm=TEST_REALM)

    tool_onboarded = scn.TOOL_WORKLOAD in workloads
    signals = list(ready_signals) if ready_signals is not None else _default_ready_signals(tool_onboarded)
    with _clean_slate(admin, workloads, keycloak_url=keycloak_url):
        # Mount this run's policy.md BEFORE deploying.
        ensure_agent_policy(CONTROLLER_NAMESPACE, policy_md=policy_md)

        # Minimal probe ctx for the per-workload agent convergence gate: the inbound leg reaches the
        # agent through its pod-agnostic Service, so no ``agent_pod`` is needed yet (it is resolved after
        # Part B for the outbound leg). The full ``ctx`` is assembled below once ``agent_pod`` is known.
        probe_ctx = {"admin": admin, "namespace": NAMESPACE, "keycloak_url": keycloak_url, "realm": TEST_REALM}

        # Fulfill the images precondition BEFORE any deploy: build-if-absent + ``kind load`` the demo
        # image(s) for exactly the workloads this rung deploys. Loading is order-independent, so it is
        # done once here rather than per-iteration; the loop below then only ``kubectl apply``s.
        load_workload_images(workloads)

        # The operator's identity now: each gate failure says when it restarted or was replaced since.
        # The trust domain (``require_pipeline``): the probes and the diagnosis both use it.
        context = {"operator": read_operator_identity(), "trust_domain": trust_domain}
        default_policy = policy_md == scn.POLICY_ABSTRACT  # the CR content checks assume Policy A's names

        # Deploy in the rung's ``workloads`` order, one at a time, onboarded before the next — each
        # ``deploy_workload`` fires the event-driven trigger (deploy -> operator -> CLIENT_CREATED ->
        # SPI -> NATS -> consumer). The order is the rung's ordering proof. Each gate ends on a positive
        # fact, in the order the platform makes them, and names the step that is stuck.
        for workload in workloads:
            deployed_at = datetime.now(timezone.utc)  # the log window of the race hint
            deploy_workload(workload)
            if not wait_for_registration(admin, workload):
                raise RuntimeError(
                    f"the rossoctl operator did not register Keycloak client {NAMESPACE}/{workload!r} within "
                    f"{DEPLOY_TIMEOUT:.0f}s of deploying it: it registers the client after its AgentRuntime "
                    f"controller labels the template ({TYPE_LABEL}); see the operator state and its log. "
                    "(The rollout already passed, so the image is loaded.) See "
                    "docs/testing/uc1-onboarding-pipeline.md Preconditions. "
                    + stack_diagnosis(admin, workload, context=context)
                )
            # The final template, rolled out, the sidecar on every pod: before it, a probe can reach the
            # first ReplicaSet's pod, which has no AuthBridge, and its app answers 200 ("allow").
            await_final_rollout(admin, workload, context=context)
            # Provision ended (client.type) and the SPM is stored (the PRB and the PCE ran).
            await_onboarded(admin, workload, context=context, deployed_at=deployed_at)

            # The workload is onboarded, so its Provision ran and linked the subject scope (D31). Fail fast
            # (not skip) when it did not: a missing link is AIAC's own fault, and without it the exchanged
            # token keeps sub = the user ID, so every tool call would be denied later with no clear cause.
            require_subject_scope(admin, workload)

            if workload == scn.AGENT_WORKLOAD:
                # One ENFORCED decision proves OPA loaded the agent's bundle: a CR proves only that the PCE
                # wrote it. dev-user inbound is allow on every rung. Every pod behind the Service has the
                # sidecar (``await_final_rollout``), and the changed combiner denies such a pod until its own
                # CR is loaded (D20), so this allow cannot come from a missing CR or from a pod with no OPA.
                gate = ReadySignal("inbound", "dev-user", "allow")
                reached, last = poll_signals([gate], probe_ctx, timeout=ENFORCED_TIMEOUT, interval=BUNDLE_POLL_INTERVAL)
                if not reached:
                    raise RuntimeError(
                        f"{NAMESPACE}/{workload} is onboarded, but OPA does not enforce its CR within "
                        f"{ENFORCED_TIMEOUT:.0f}s: {signals_report([gate], last)} "
                        + stack_diagnosis(admin, workload, context=context)
                    )
                problems = agent_cr_content_problems(authpolicy_policies(workload)) if default_policy else []
                if problems:
                    raise RuntimeError(
                        f"the agent CR {cr_key(workload)} does not have the agent's per-skill scopes: "
                        + "; ".join(problems)
                        + ". "
                        + stack_diagnosis(admin, workload, context=context)
                    )

        # The tool's calling-agent gate is filled only once both workloads are onboarded: with the tool
        # alone it is ``{}`` (rung 3), and the agent's onboarding re-renders the tool's CR.
        if scn.AGENT_WORKLOAD in workloads and tool_onboarded and default_policy:
            seen = {"problems": ["not checked"]}

            def _tool_cr_ok() -> bool:
                seen["problems"] = tool_cr_content_problems(authpolicy_policies(scn.TOOL_WORKLOAD))
                return not seen["problems"]

            if not poll_until(_tool_cr_ok, timeout=CR_CONTENT_TIMEOUT, interval=5):
                raise RuntimeError(
                    f"the tool CR {cr_key(scn.TOOL_WORKLOAD)} does not let the agent reach a tool within "
                    f"{CR_CONTENT_TIMEOUT:.0f}s of both onboardings: "
                    + "; ".join(seen["problems"])
                    + ". "
                    + stack_diagnosis(admin, scn.AGENT_WORKLOAD, context=context)
                )

        # Part B — make the outbound exchange succeed so the tool check is actually reached
        # (github-tool's inbound OPA, which accepts only a token with its audience). Done after
        # onboarding so the restarted agent (and its OPA sidecar) starts with empty exchange caches
        # and, on its next poll, the recomposed bundle.
        #
        # Prepared ONLY when this run actually probes outbound (``has_outbound``). The agent-only rung
        # (rung 1) has no tool onboarded, so there is no real ``agent -> tool`` call to make and no
        # outbound signal in its set — its outbound leg has no real-life counterpart, and the exchange
        # never reaches OPA anyway (no ``github-tool`` client, since the operator registers it and
        # creates ``agent-{ns}-github-tool-aud`` only on TOOL deploy). So on a tool-less rung Part B is
        # skipped entirely: no grant, no restart. Its inbound gate already converged in the
        # per-workload loop above, and skipping the restart means rung 1 asserts the exact bundle the
        # live event-driven onboard produced (no restart papering over a bad compose).
        #
        # When there IS an outbound leg: grant the agent client the ``*-aud`` scope as a default scope
        # (only ever present once the tool is deployed) so ``token-exchange-aiac`` mints the github-tool
        # token and OPA is reached, then restart the agent. No route: the plugin derives the audience.
        has_outbound = any(sig.kind == "outbound" for sig in signals)
        if has_outbound:
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
            # The trust domain the live outbound leg exchanges for, read once per stack by the skip gate,
            # so a probe asks for the audience AuthBridge asks for (``exchanged_subject``).
            "trust_domain": trust_domain,
        }

        # Wait for bundle-service + OPA to reflect THIS run's CR (and token-exchange to settle) before
        # any assertion. The ``signals`` set (this policy's ``ready_signals``, or the Policy-A default)
        # is polled until every probe reaches its terminal verdict — each deterministic for its
        # scenario regardless of a stale CR (which the run replaced), and each polled to a *definitive*
        # allow/deny (not ``error``) so we also wait out the post-restart token-exchange 503 window.
        reached, last = poll_signals(signals, ctx, timeout=BUNDLE_TIMEOUT, interval=BUNDLE_POLL_INTERVAL)
        if not reached:
            # The message prints what the poll saw last, with each raw ``(code, body)``: the classifier
            # collapses very different failures into ``"error"``, and the raw answer tells them apart.
            # On the outbound leg: ``code=None`` + ``"outbound probe exec failed: ..."`` is the probe's own
            # ``kubectl exec`` (a replaced agent pod); 503 or an exchange error frame is the
            # ``token-exchange-aiac`` leg (OPA not reached);
            # a real policy stall reads ``"deny"`` (github-tool's inbound 403 with an OPA body), never
            # ``"error"``, because the generated Rego carries ``default allow := false``.
            raise RuntimeError(
                f"live pipeline did not converge within {BUNDLE_TIMEOUT:.0f}s after onboarding "
                f"{workloads} + Part B: {signals_report(signals, last)}. Outbound: code=None + 'exec failed' "
                "body = a stale/gone agent pod (harness); 503 / plugin=token-exchange-aiac = the exchange failed "
                "(OPA not reached); "
                "a real policy stall reads 'deny', never 'error' — see k8s/opa-kind-runbook.md. "
                + stack_diagnosis(admin, workloads[-1], context=context)
            )
        yield ctx


# ======================================================================================
# AuthorizationPolicy CRs and stored SPMs — read-only views for every rung
# ======================================================================================
#
# Every managed service has its own CR (D20) with exactly the two request packages
# (``aiac.pdp.service.policy.opa.main._build_cr``); there is no response package. A **rules-based**
# package carries ``default allow := false`` (D25); a **pass-through** package is only
# ``allow := true`` (D24). The CR shapes (PRD D34):
#
#   github-agent CR   inbound: rules + grants (D26a); outbound: pass
#   github-tool CR    inbound: rules + grants (D26);  outbound: pass
#
# A service with no stored SPM (for example after a quarantine) has no CR, and the combiner denies it.

CR_INBOUND_PATH = "inbound/request.rego"
CR_OUTBOUND_PATH = "outbound/request.rego"
CR_REQUEST_PATHS = frozenset({CR_INBOUND_PATH, CR_OUTBOUND_PATH})

# The Rego bindings that carry the grants of each rules-based package. An empty one renders as ``[]`` /
# ``{}`` (``rego._render_list`` / ``_render_map``).
#   * agent inbound (agent-level, D26a): the agent's own scopes + the user gate;
#   * tool inbound (D26): the user gate + the calling-agent gate, keyed by the bare tool.
AGENT_INBOUND_GRANT_BINDINGS = ("agent_scopes", "subject_role_allow_scopes")
TOOL_INBOUND_GRANT_BINDINGS = ("subject_role_allow_scopes", "source_role_allow_scopes")

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
    form ``rego._render_list`` / ``_render_map`` emit for no entries.
    ``None`` when ``var`` is not bound at all (a CR format change, surfaced by the caller rather
    than read as empty)."""
    if not re.search(rf"^{re.escape(var)}\s*:=", rego, re.M):
        return None
    return re.search(rf"^{re.escape(var)}\s*:=\s*(\[\s*\]|\{{\s*\}})", rego, re.M) is not None


def _rego_lines(rego: str) -> list[str]:
    """The non-blank, non-comment lines of ``rego``, stripped."""
    return [ln.strip() for ln in rego.splitlines() if ln.strip() and not ln.strip().startswith("#")]


# A top-level data binding as ``rego._render_list`` / ``_render_map`` emit it:
# ``var := [...]`` on one line, or ``var := {`` … a ``}`` line in column 0.
_REGO_DATA_BINDING = re.compile(r"^([A-Za-z_]\w*) := ([\[{].*)$")


def _canonical_data(value):
    """``value`` with every list sorted and every map key sorted, at each depth."""
    if isinstance(value, dict):
        return {k: _canonical_data(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return sorted((_canonical_data(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


_UNPARSED = object()  # a data binding whose text does not parse as JSON


def _rego_data_bindings(rego: str) -> Iterator[tuple[str | None, object, list[str]]]:
    """Each piece of ``rego`` in order, as ``(name, value, lines)``: a top-level data binding (as
    ``rego._render_list`` / ``_render_map`` emit it) read as JSON, or ``_UNPARSED`` when it does not
    parse; every other line as ``(None, None, [line])``."""
    lines = rego.splitlines()
    i = 0
    while i < len(lines):
        m = _REGO_DATA_BINDING.match(lines[i])
        if not m:
            yield None, None, [lines[i]]
            i += 1
            continue
        name, text = m.groups()
        end = i
        if text == "{":
            while end + 1 < len(lines) and lines[end] != "}":
                end += 1
            text = "\n".join(["{", *lines[i + 1 : end + 1]])
        try:
            # The renderers end each map entry with a comma; JSON does not accept a trailing comma.
            # Remove only a comma at the end of a line: json.dumps escapes a newline in a string,
            # so a comma in a string value stays.
            value = json.loads(re.sub(r",\n(\s*[}\]])", "\n\\1", text))
        except json.JSONDecodeError:
            value = _UNPARSED
        yield name, value, lines[i : end + 1]
        i = end + 1


def rego_binding_value(rego: str, var: str):
    """The value of the top-level data binding ``var`` in ``rego`` (a list or a map), or ``None`` when
    ``var`` is not bound or does not parse (a CR format change, which the caller reports)."""
    for name, value, _ in _rego_data_bindings(rego):
        if name == var:
            return None if value is _UNPARSED else value
    return None


def rego_canonical(rego: str) -> str:
    """``rego`` in an order-agnostic form, for an equality check of two CRs.

    The order of a scope or role list, and of map keys, has no meaning in the rendered packages
    (each read is ``x in list`` or a key lookup), and the renderer keeps the order the IdP returns.
    So each top-level data binding is read as JSON and written again with every list and map key
    sorted. Each other line (rule bodies, ``default``, ``allow := true``) stays as it is. A binding
    that does not parse as JSON also stays as it is, so a format change shows as a difference."""
    out: list[str] = []
    for name, value, lines in _rego_data_bindings(rego):
        if name is None or value is _UNPARSED:
            out.extend(lines)
        else:
            out.append(f"{name} := {json.dumps(_canonical_data(value), sort_keys=True)}")
    return "\n".join(out)


def cr_canonical(policies: dict[str, str] | None) -> dict[str, str] | None:
    """``policies`` (``{path: rego}``, as ``aiac_crs`` gives it) with each package in the
    order-agnostic form of ``rego_canonical``. ``None`` (no CR) stays ``None``."""
    if policies is None:
        return None
    return {path: rego_canonical(rego) for path, rego in policies.items()}


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
      ``agent_scopes`` + ``subject_role_allow_scopes``);
    * ``kind="tool"`` — the tool inbound (D26): the user gate and the calling-agent gate
      (non-empty ``subject_role_allow_scopes`` + ``source_role_allow_scopes``)."""
    if not policies:
        return False
    inbound = policies.get(CR_INBOUND_PATH, "")
    bindings = AGENT_INBOUND_GRANT_BINDINGS if kind == AGENT_KIND else TOOL_INBOUND_GRANT_BINDINGS
    return all(rego_binding_empty(inbound, v) is False for v in bindings)


def cr_mismatches(policies: dict[str, str] | None, kind: str) -> list[str]:
    """Each way the CR ``policies`` of a service of ``kind`` (``"agent"`` / ``"tool"``) differs from
    its shape (the table above: the inbound is rules-based with grants, the outbound is a
    pass-through); an empty list means the CR matches. A missing CR is one mismatch (every managed
    service has a CR, D20)."""
    if not policies:
        return ["no CR"]
    problems: list[str] = []
    if not cr_has_request_packages(policies):
        problems.append(f"packages {sorted(policies)} (want exactly {sorted(CR_REQUEST_PATHS)})")
    inbound, outbound = policies.get(CR_INBOUND_PATH), policies.get(CR_OUTBOUND_PATH)
    if not rego_is_rules_based(inbound):
        problems.append("inbound is not rules-based (default allow := false)")
    elif not cr_has_grants(policies, kind):
        problems.append(f"inbound has no grants ({kind})")
    if not rego_is_pass_through(outbound):  # the callee decides (D24)
        problems.append("outbound is not a pass-through")
    return problems


def cr_matches(policies: dict[str, str] | None, kind: str) -> bool:
    """True when the CR ``policies`` of a service of ``kind`` has its shape (``cr_mismatches`` is
    empty)."""
    return not cr_mismatches(policies, kind)


# The analyze_agent fallback role and scope for an agent whose card has no skills: with it,
# the PRB has no agent role to match a tool scope, so every agent -> tool call is denied.
def default_access_scope(workload: str) -> str:
    return f"{workload}.access"


def agent_cr_content_problems(policies: dict[str, str] | None) -> list[str]:
    """Each way the agent CR's inbound ``agent_scopes`` differs from the per-skill scopes of
    ``scenario_uc1.AGENT_SCOPES``; an empty list means it matches. The PCE seeds ``agent_scopes`` from
    the agent's managed scopes (from its AgentCard), so the check does not depend on the PRB, the
    policy or the deploy order. **Pure.**"""
    if not policies:
        return ["no CR"]
    scopes = rego_binding_value(policies.get(CR_INBOUND_PATH, ""), "agent_scopes")
    if not isinstance(scopes, list):
        return ["the inbound has no agent_scopes list"]
    problems = []
    fallback = default_access_scope(scn.AGENT_WORKLOAD)
    if fallback in scopes:
        problems.append(
            f"agent_scopes has the default {fallback!r}: the agent was onboarded with no AgentCard skills "
            "(the analyze_agent fallback)"
        )
    if set(scopes) != set(scn.AGENT_SCOPES):
        problems.append(f"agent_scopes is {sorted(scopes)} (want {sorted(scn.AGENT_SCOPES)})")
    return problems


def tool_cr_content_problems(policies: dict[str, str] | None) -> list[str]:
    """Each way the tool CR's inbound differs from a tool onboarded after the agent; an empty list means
    it matches. ``owned_tools`` must be the bare names of ``scenario_uc1.TOOL_SCOPES`` (fixed by the
    tool's own scopes). The calling-agent gate ``source_role_allow_scopes`` must name at least one of the
    agent's per-skill roles and no other role: its edges come from the PRB, so the exact pairs depend on
    the policy, but a role that is not the agent's (for example the default ``<workload>.access``) is a
    fault. Check it only once both workloads are onboarded: with the tool alone it is ``{}``. **Pure.**"""
    if not policies:
        return ["no CR"]
    inbound = policies.get(CR_INBOUND_PATH, "")
    problems = []
    owned = rego_binding_value(inbound, "owned_tools")
    want_owned = {scn.bare(s) for s in scn.TOOL_SCOPES}
    if not isinstance(owned, list) or set(owned) != want_owned:
        problems.append(f"owned_tools is {owned!r} (want {sorted(want_owned)})")
    source = rego_binding_value(inbound, "source_role_allow_scopes")
    if not isinstance(source, dict):
        problems.append("the inbound has no source_role_allow_scopes map")
    elif not source:
        problems.append(
            "source_role_allow_scopes is empty: no agent role reaches a tool (the PRB made no agent -> tool "
            "edge; see the agent CR's agent_scopes)"
        )
    else:
        others = sorted(set(source) - set(scn.AGENT_ROLES))
        if others:
            problems.append(f"source_role_allow_scopes has roles that are not the agent's per-skill roles: {others}")
    return problems


# ======================================================================================
# CR capture — every AIAC CR and the global combiner to the pytest host, before a teardown
# ======================================================================================
#
# The teardown deletes the CRs (``_scrub_to_pristine``) and a Controller restore rewrites them (the
# resync), so without a capture a failed run keeps no record of the CR that made a wrong allow/deny.
# ``capture_aiac_crs`` runs FIRST in each teardown and restore, and before the pre-run slate (the
# leftovers of an earlier run are evidence too). It only reads (``kubectl get``) and it never raises.
#
# Layout, under ``CR_CAPTURE_DIR`` (``AIAC_CR_CAPTURE_DIR``; default ``test/system/artifacts/cr-captures``):
#
#   <UTC time>__<test module>__<phase>/   e.g. 20261005T143012.482913Z__test_uc1_onboard_resync__teardown
#       index.yaml                        the label, the phase, the time, one entry per CR, the read errors
#       <namespace>__<name>.yaml          one full CR, without metadata.managedFields
#
# The phases: ``pre-run-slate`` (before the pre-run cleanup), ``teardown`` (the first teardown step),
# ``pre-env-restore`` (before a Controller restore) and ``pre-cr-delete`` (rung 6, before it deletes
# github-tool's CR by hand).

CAPTURE_INDEX_FILE = "index.yaml"


def _name_part(text: str, fallback: str) -> str:
    """``text`` as one safe part of a file name: each run of characters other than ``[A-Za-z0-9._-]``
    becomes ``-`` (a Kubernetes name or a module stem stays as it is); ``fallback`` when nothing is left."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.") or fallback


def _capture_label() -> str:
    """The default label of a capture: the file stem of the running test module, from
    ``PYTEST_CURRENT_TEST`` (``<path>::<name> (<when>)``), for example ``test_uc1_onboard_resync``;
    ``"no-test"`` outside a test. A stack reads it once at its start: pytest tears a session-scoped
    fixture down after the last test of the session, which can be in another module."""
    current = os.environ.get("PYTEST_CURRENT_TEST", "")
    return _name_part(Path(current.split("::", 1)[0]).stem, "no-test")


def _capture_dir_name(stamp: datetime, label: str, phase: str) -> str:
    """The directory name of one capture: ``<UTC time>__<label>__<phase>``, for example
    ``20261005T143012.482913Z__test_uc1_onboard_resync__teardown``. The UTC time has a fixed width and
    comes first, so the names sort in time order."""
    utc = stamp.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{utc}__{_name_part(label, 'no-test')}__{_name_part(phase, 'capture')}"


def _cr_file_name(item: dict) -> str:
    """The file of the CR ``item`` in a capture: ``<namespace>__<name>.yaml``. Unique in a capture,
    which holds one kind with one object per ``_cr_key``."""
    meta = item.get("metadata") or {}
    namespace = _name_part(meta.get("namespace", ""), "no-namespace")
    return f"{namespace}__{_name_part(meta.get('name', ''), 'no-name')}.yaml"


def _strip_managed_fields(item: dict) -> dict:
    """A copy of the CR ``item`` without ``metadata.managedFields`` (the server-side-apply field owners:
    noise for a post-mortem). Everything else is kept, ``spec.policies[*].content`` (the Rego) included;
    ``item`` is not changed."""
    stripped = dict(item)
    if isinstance(item.get("metadata"), dict):
        stripped["metadata"] = {k: v for k, v in item["metadata"].items() if k != "managedFields"}
    return stripped


def _to_yaml(doc: dict) -> str:
    """``doc`` as YAML, with the keys in their order and each multi-line string (the Rego in
    ``spec.policies[*].content``) as a ``|`` block, as ``kubectl get -o yaml`` prints it. PyYAML (a
    dependency of ``kubernetes``) is imported here, so the module keeps its stdlib + ``requests`` imports."""
    import yaml

    class _BlockDumper(yaml.SafeDumper):
        pass

    def _str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)

    _BlockDumper.add_representer(str, _str)
    return yaml.dump(doc, Dumper=_BlockDumper, sort_keys=False, allow_unicode=True)


def _combiner_cr_items() -> list[dict]:
    """The global combiner (``COMBINER_CR_NAME`` in ``BUNDLE_SERVICE_NAMESPACE``) as a list of one, or an
    empty list when it is absent. Raises when the API is unreachable."""
    out = kubectl(
        "get",
        "authorizationpolicy",
        COMBINER_CR_NAME,
        "-n",
        BUNDLE_SERVICE_NAMESPACE,
        "-o",
        "json",
        "--ignore-not-found",
        timeout=30,
    )
    return [json.loads(out)] if out.strip() else []


def _new_capture_dir(root: Path, name: str) -> Path:
    """Make and return the new directory ``root/name``; when it exists (two captures in the same
    microsecond with the same label and phase), ``root/name-2``, ``root/name-3``, … — never an old one."""
    root.mkdir(parents=True, exist_ok=True)
    suffix = 1
    while True:
        target = root / (name if suffix == 1 else f"{name}-{suffix}")
        try:
            target.mkdir()
            return target
        except FileExistsError:
            suffix += 1


def _write_cr_capture(
    items: Sequence[dict],
    root: Path,
    *,
    label: str,
    phase: str,
    errors: Sequence[str] = (),
    now: datetime | None = None,
) -> Path:
    """Write the CR objects ``items`` as one capture (the layout above) into a new directory under
    ``root``, and return that directory (absolute). A CR that is in ``items`` two times (same
    ``_cr_key``) is written once. ``errors`` (the sources that could not be read) go into the index.
    Raises on a file-system error."""
    stamp = now or datetime.now(timezone.utc)
    target = _new_capture_dir(root.resolve(), _capture_dir_name(stamp, label, phase))
    crs = {_cr_key(item): _strip_managed_fields(item) for item in items}
    index: list[dict] = []
    for key in sorted(crs):
        item = crs[key]
        meta = item.get("metadata") or {}
        file_name = _cr_file_name(item)
        (target / file_name).write_text(_to_yaml(item), encoding="utf-8")
        index.append(
            {
                "file": file_name,
                "namespace": meta.get("namespace"),
                "name": meta.get("name"),
                "scope": (item.get("spec") or {}).get("scope"),
                "uid": meta.get("uid"),
                "resourceVersion": meta.get("resourceVersion"),
            }
        )
    summary = {
        "label": label,
        "phase": phase,
        "captured_at": stamp.astimezone(timezone.utc).isoformat(),
        "crs": index,
        "errors": list(errors),
    }
    (target / CAPTURE_INDEX_FILE).write_text(_to_yaml(summary), encoding="utf-8")
    return target


def capture_aiac_crs(phase: str, *, label: str | None = None, root: Path | None = None) -> Path | None:
    """Capture every AIAC CR (``_aiac_cr_items``: the managed-by label, all namespaces) and the global
    combiner (``_combiner_cr_items``) to the pytest host, in a new directory under ``root`` (default
    ``CR_CAPTURE_DIR``) named for the UTC time, ``label`` (default ``_capture_label``: the running test
    module) and ``phase`` (the layout above). Call it FIRST in a teardown or restore, before anything
    deletes or changes a CR, for post-mortem debugging of a wrong allow/deny.

    Read-only (``kubectl get`` only) and best-effort: it never raises, so a caller in a ``finally``
    neither masks the test failure nor stops its teardown. A source that cannot be read is logged and
    put in the index (``errors``), and the capture goes on with the other source; no CR at all is a
    valid capture (``crs: []``). Any other error is logged and gives ``None``. The absolute directory is
    logged at WARNING, the level that a pytest failure report shows by default (``pyproject.toml`` sets
    no ``log_level``). Returns the directory, or ``None`` when nothing was written."""
    try:
        label = label or _capture_label()
        items: list[dict] = []
        errors: list[str] = []
        sources = (
            (f"AIAC CRs ({MANAGED_BY_SELECTOR})", _aiac_cr_items),
            (f"global combiner ({BUNDLE_SERVICE_NAMESPACE}/{COMBINER_CR_NAME})", _combiner_cr_items),
        )
        for source, read in sources:
            try:
                items += read()
            except Exception as exc:  # a failed read must not stop the capture or the teardown
                detail = _exc_text(exc, 300)
                errors.append(f"{source}: {detail}")
                log.warning("CR capture (%s): cannot read the %s: %s", phase, source, detail)
        target = _write_cr_capture(items, root or CR_CAPTURE_DIR, label=label, phase=phase, errors=errors)
    except Exception as exc:  # best-effort: never mask the test failure or stop the teardown
        log.warning("CR capture (%s) failed, nothing written; the teardown goes on: %s", phase, exc)
        return None
    count = len({_cr_key(item) for item in items})
    log.warning("CR capture (%s): %d CR(s) written to %s", phase, count, target)
    return target


# --- Pod log capture — the Controller's log before each roll, and at teardown ---------------------
# The Controller is ``Recreate`` (``k8s/agent-deployment.yaml``), so a roll deletes its pod and its log:
# ``kubectl logs`` cannot read a deleted pod, and ``--previous`` covers only a container restart in the
# same pod. So the harness saves the log BEFORE each Controller roll (``ensure_agent_policy``,
# ``controller_env``, ``restart_controller``) and at teardown, next to the CR captures. Default root: the
# gitignored ``test/system/artifacts/pod-logs/`` (``AIAC_POD_LOG_DIR``).
POD_LOG_DIR = Path(os.environ.get("AIAC_POD_LOG_DIR") or HERE / "artifacts" / "pod-logs").expanduser()


def capture_pod_logs(
    phase: str,
    *,
    namespace: str = CONTROLLER_NAMESPACE,
    selector: str | None = None,
    container: str | None = None,
    label: str | None = None,
) -> Path | None:
    """Write the log of each pod that matches ``selector`` (default: the Controller's) in
    ``namespace`` to a new directory under ``POD_LOG_DIR``, named like a CR capture
    (the UTC time, ``label``, ``phase``): ``<pod>.log`` with ``--timestamps``, and ``<pod>.previous.log``
    when the container has restarted in the same pod. Read-only and best-effort: it never raises.
    Returns the directory, or ``None`` when nothing was written."""
    selector = selector or CONTROLLER_SELECTOR
    container = container or CONTROLLER_DEPLOYMENT
    try:
        ok, out, err = _kubectl_try("get", "pods", "-n", namespace, "-l", selector, "-o", "json")
        if not ok:
            log.warning("pod log capture (%s): cannot list %s in %s: %s", phase, selector, namespace, err)
            return None
        pods = json.loads(out).get("items", [])
        target = _new_capture_dir(
            POD_LOG_DIR, _capture_dir_name(datetime.now(timezone.utc), label or _capture_label(), phase)
        )
        for pod in pods:
            name = pod.get("metadata", {}).get("name", "")
            status = next(
                (c for c in pod.get("status", {}).get("containerStatuses", []) if c.get("name") == container), {}
            )
            runs = [("log", [])] + ([("previous.log", ["--previous"])] if status.get("restartCount") else [])
            for suffix, extra in runs:
                ok, text, err = _kubectl_try(
                    "logs", "-n", namespace, name, "-c", container, "--timestamps", *extra, timeout=60
                )
                (target / f"{_name_part(name, 'pod')}.{suffix}").write_text(text if ok else f"(not read: {err})\n")
    except Exception as exc:  # best-effort: never mask the test failure or stop a roll
        log.warning("pod log capture (%s) failed: %s", phase, exc)
        return None
    log.warning("pod log capture (%s): %d pod(s) of %s written to %s", phase, len(pods), selector, target)
    return target


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
# leaves (the quarantine deletes the CR, D20). Every Controller rollout runs the
# resync at start (D28) before the new pod is Ready; ``restart_controller`` is that rollout.

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
    start sequence (start check #4, the resync) ends, so the resync has run on return."""
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
    under the PCE lock before it serves: ``PUT /policy`` with the full policy model,
    then a teardown of each disabled service that still has an SPM. Changes no env and no ConfigMap."""
    capture_pod_logs("pre-controller-restart")  # the roll deletes the pod and its log
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
    be gone (``_wait_controller_rolled``). The restore rolls the Controller, and its resync can rewrite
    or delete AIAC CRs, so the ``finally`` first captures them (``capture_aiac_crs``, phase
    ``pre-env-restore``). Like ``ensure_agent_policy``, a test-owned mutation of the running Controller,
    never written into a committed manifest."""
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

    capture_pod_logs("pre-env-set")  # each patch rolls the pod and deletes its log
    _patch([{"op": "add", "path": path, "value": patched}])  # JSON-patch "add" replaces an existing member
    try:
        _wait_controller_rolled()
        yield
    finally:
        # The restore rolls the Controller, and its resync rewrites the AIAC CRs: capture them first.
        capture_aiac_crs("pre-env-restore")
        capture_pod_logs("pre-env-restore")
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


def controller_logs(*, since: datetime | None = None, tail: int | None = None) -> str:
    """The current Controller pod's log (the app container): the full log, or with ``since`` only the
    lines from that time (``--since-time``, RFC 3339 in UTC) and with ``tail`` at most the last ``tail``
    lines. The consumer logs each PRB failure (``log_by_type``) and each dead-letter move at ERROR, so
    both reach the pod's stderr."""
    args = ["logs", "-n", CONTROLLER_NAMESPACE, resolve_controller_pod(), "-c", CONTROLLER_DEPLOYMENT]
    if since is not None:
        args.append(f"--since-time={since.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    if tail is not None:
        args.append(f"--tail={tail}")
    return kubectl(*args, timeout=60)


# --- The event-before-commit race (D33) — the hint for a deploy gate that times out ----------------
# Before the D33 fix the ``aiac-event-listener`` SPI published ``CLIENT_CREATED`` inside Keycloak's admin
# request, before the commit. The Controller's first IdP read could then get Keycloak's 404 "Could not
# find client", and the onboarding started only with the NATS redelivery after ``ACK_WAIT`` (600 s).
# Now the SPI publishes after the commit and the Controller reads a new client again for a bounded time
# (``ONBOARD_CLIENT_WAIT_*``). A deploy gate that still times out appends the hint to its message.

# A Controller line of the race: Keycloak's 404 text (not ``client scope`` or a longer word), or the
# Controller's own error for a client that is still not visible after the bounded wait.
_COMMIT_RACE_LINE = re.compile(r"Could not find client(?![A-Za-z]| scope)|ServiceNotVisibleError")
# The live read is bounded: from this slack (seconds) before the deploy (the host and the cluster clocks
# can differ a little), and at most the last ``CONTROLLER_LOG_TAIL`` lines.
CONTROLLER_LOG_SLACK_SECONDS = 30.0
CONTROLLER_LOG_TAIL = 5000
# The hint quotes the first matching line, cut to this length.
_HINT_LINE_CHARS = 400


def commit_race_hint(log_text: str, *, service_uuid: str | None = None) -> str:
    """The gate-message hint for the event-before-commit race (D33), from the Controller log
    text ``log_text``: ``""`` when no line shows the race, else one paragraph with the number of
    matching lines, the first one (cut to ``_HINT_LINE_CHARS``), the probable cause and what to check.

    A matching line has Keycloak's ``Could not find client`` (not ``Could not find client scope``) or the
    Controller's ``ServiceNotVisibleError``. With ``service_uuid`` only the lines that name that client
    UUID count (the Controller's error line names the service it read), so a redelivery for a client
    that an earlier run deleted gives no hint. Pure — no I/O."""
    lines = [
        line.strip()
        for line in log_text.splitlines()
        if _COMMIT_RACE_LINE.search(line) and (service_uuid is None or service_uuid in line)
    ]
    if not lines:
        return ""
    first = lines[0] if len(lines[0]) <= _HINT_LINE_CHARS else lines[0][: _HINT_LINE_CHARS - 3] + "..."
    which = "for this client" if service_uuid is not None else "(any client)"
    return (
        f"The Controller log has {len(lines)} line(s) that show Keycloak's 404 'Could not find client' "
        f"(or ServiceNotVisibleError) {which}, first: {first!r}. The onboarding event probably "
        "came before Keycloak committed the new client (the event-before-commit race, D33): "
        "the first IdP read got 404, so the onboarding waited for a NATS redelivery. Check that the "
        "Keycloak image has the aiac-event-listener SPI that publishes after the commit, and that the "
        "Controller has the bounded wait on its first read (ONBOARD_CLIENT_WAIT_ATTEMPTS / "
        "ONBOARD_CLIENT_WAIT_BACKOFF, about 30 s by default)."
    )


def append_hint(message: str, hint: str) -> str:
    """``message`` with ``hint`` after it (one space), or ``message`` alone when there is no hint."""
    return f"{message} {hint}" if hint else message


def controller_commit_race_hint(since: datetime | None = None, *, admin=None, workload: str | None = None) -> str:
    """``commit_race_hint`` over the live Controller log, for the failure message of a deploy gate.

    Reads only a bounded part of the log: the lines from ``CONTROLLER_LOG_SLACK_SECONDS`` before
    ``since`` (the deploy start; ``None`` = no time window), at most the last ``CONTROLLER_LOG_TAIL``.
    With ``admin`` and ``workload`` only the lines of that workload's client (its UUID) count; a client
    that is gone, or a failed lookup, counts every line. Call it while the Controller pod that ran the
    onboarding still runs: a restarted pod has a new log. Read-only and best-effort: a failure is logged
    at WARNING and gives ``""``, never an exception, so the hint cannot replace the gate's own error."""
    uuid = None
    if admin is not None and workload is not None:
        try:
            client = workload_client(admin, workload)
            uuid = client.get("id") if client else None
        except Exception as exc:  # best-effort: without the UUID every line counts
            log.warning("race hint: the client lookup of %r failed, so every line counts: %s", workload, exc)
    start = since - timedelta(seconds=CONTROLLER_LOG_SLACK_SECONDS) if since is not None else None
    try:
        return commit_race_hint(controller_logs(since=start, tail=CONTROLLER_LOG_TAIL), service_uuid=uuid)
    except Exception as exc:  # best-effort: a hint never replaces the gate's own error
        detail = (getattr(exc, "stderr", "") or str(exc)).strip()[:300]
        log.warning("race hint: could not read the Controller log: %s", detail)
        return ""


def publish_service_event(service_uuid: str) -> None:
    """Re-fire the onboarding trigger for an EXISTING Keycloak client: publish on
    ``aiac.apply.service.<uuid>`` (the subject + ``{"id": ...}`` payload the ``aiac-event-listener`` SPI
    publishes on ``CLIENT_CREATED``), so the agent consumer runs the same ``onboard_and_apply`` path
    that a deploy fires (the build, then ``compute_and_apply(focus_service=client_id)`` with the
    re-enable as ``on_applied``).

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
    outbound (token-exchange-aiac, then the tool check in github-tool's inbound OPA), and return
    ``{method: (decision, http_code, body)}``. A request frame is classified by its body
    (``outbound_outcome``: a ``result`` frame = allow, an OPA 403 or OPA error frame = deny); the
    notification by its status and body (``notification_outcome``: 202 = allow, an OPA 403 = deny)."""
    token = mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    frames = mcp_session_frames(tool_bare)
    raw = outbound_session_probe(token, frames, namespace=ctx["namespace"], agent_pod=resolve_agent_pod())
    return {
        frame["method"]: (
            (outbound_outcome(code, body) if "id" in frame else notification_outcome(code, body)),
            code,
            body,
        )
        for frame, (code, body) in zip(frames, raw)
    }


@contextmanager
def pristine_stack(workloads: Sequence[str], *, policy_md: str = scn.POLICY_ABSTRACT) -> Iterator[dict]:
    """The slate + teardown half of ``onboarded_stack`` with NO deploy and NO convergence poll, for a
    flow whose onboarding is meant to fail (``onboarded_stack`` would wait for a happy-path allow that
    never comes). Yields ``ctx = {"admin", "namespace", "keycloak_url", "realm", "trust_domain"}``, the keys
    of ``onboarded_stack`` that need no deploy; the caller deploys.

    Same skip gates (pipeline wiring, env, event path), the same slate and teardown (``_clean_slate``:
    Direct Access Grants on the login client, the no-workloads slate, realm users and roles, the ``sub``
    check; at exit full-to-pristine, verified), then the ``policy.md`` mount and the image load for
    ``workloads``."""
    trust_domain = require_pipeline(namespace=NAMESPACE, workloads=[])
    creds = require_env_or_skip("KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    keycloak_url = creds["KEYCLOAK_URL"]
    admin = connect_admin()
    require_event_path(admin=admin, realm=TEST_REALM)
    with _clean_slate(admin, workloads, keycloak_url=keycloak_url):
        ensure_agent_policy(CONTROLLER_NAMESPACE, policy_md=policy_md)
        load_workload_images(list(workloads))
        yield {
            "admin": admin,
            "namespace": NAMESPACE,
            "keycloak_url": keycloak_url,
            "realm": TEST_REALM,
            "trust_domain": trust_domain,
        }
