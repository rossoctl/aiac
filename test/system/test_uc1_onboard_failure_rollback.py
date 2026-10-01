"""Rung 5 of the UC-1 onboarding ladder — a **failed** onboarding: compensating rollback + PCE quarantine.

Spec ``docs/testing/uc1-onboarding-pipeline.md`` (§ Failure path); plan
``docs/handoffs/04-uc1-onboarding-prb-failure-rollback-coverage.md``, with the assertions of handoff 11
(Group 8 — its no-rules CR supersedes handoff 04's "no CR for a failed agent"). Rungs 1–3 prove the happy path;
this rung proves what a build failure leaves behind. Service Provision succeeds and writes the service's
roles/scopes, then ``ServicePolicyBuilder.build`` raises one of ``orchestrator._ROLLBACK_ERRORS``. The
Orchestrator runs ``_rollback`` (delete only this run's roles/scopes, **keep** ``client.type``, disable
the client last), then the PCE ``quarantine`` (delete the SPM, remove the service's roles from the other
SPMs, replace an **agent's** CR with a **no-rules CR**, re-derive the affected agents), and re-raises.
Under the event model there is no HTTP status to assert, so the rung asserts only observable end state:
Keycloak, the ``AuthorizationPolicy`` CRs, the Policy Store, the Controller log, and real requests
through AuthBridge + the deployed OPA plugin.

One shared stack, four phases in order (``_run_phases``); each records what it observed and the tests
assert on the record, so a failed phase reports its own facts and the later phases report "not reached":

1. **Failed agent** — deploy the agent with the LLM seam broken. Assert: the client is disabled and its
   ``client.type`` is kept; the ``github-agent.*`` roles/scopes Provision created are gone; the no-rules
   CR is **present** (every grant binding empty, ``default allow := false`` — a deleted CR would open the
   agent through the bundle-service allow-fallback); a real inbound ``dev-user`` request (allowed on the
   happy path) is **denied**; no SPM; the failure and the dead-letter move are logged.
2. **Lift** — restore the seam and re-fire the trigger. Assert: the real CR (with grants) is back, the
   client is enabled, and ``dev-user`` inbound is allowed again.
3. **Tool onboarded + MCP session** — deploy the tool on the happy path, prepare the outbound leg (Part
   B), converge. Assert: one MCP session (``initialize``, ``notifications/initialized``, ``tools/list``,
   ``tools/call``) through the agent's outbound is allowed for ``dev-user`` (a grant on some tool of the
   target), and the session methods are denied for ``devops-user`` (no grant — the negative control that
   keeps the session rule from passing as allow-all).
4. **Failed tool** — break the seam again and re-fire the tool's trigger. Assert: the client is disabled
   and ``Tool`` is kept; no CR for the tool; its SPM (written in phase 3) is gone; the agent's outbound
   Rego lost every grant to it; the ``dev-user`` outbound call that phase 3 allowed is now blocked.

**Failure injection — a permanent error, on purpose.** ``controller_llm_unusable`` points the in-cluster
Controller's ``LLM_BASE_URL`` (an explicit container env over the ``aiac-agent-config`` ``envFrom``; the
exact original env is restored in ``finally`` and the Controller rolled back) at a path of the
Controller's own FastAPI app that answers **HTTP 404**. Provision uses no LLM, so it still runs; the
PRB's first chat-completions call gets the 404, which is not transient (no retry) and surfaces as
``UnparseableLLMResponseError`` — a **permanent** consumer error, dead-lettered on the **first**
delivery. An *unreachable* host was rejected: it raises the **retryable** ``LLMAccessError``, which the
consumer leaves un-acked (no ``nak``), so each of the ``MAX_DELIVER=5`` redeliveries waits the full
``ACK_WAIT_SECONDS=600`` — ~40 min to the terminal state — and a still-pending redelivery would re-run
the onboarding after the seam is restored, racing the lift (and the teardown). The 404 is also
independent of the real LLM provider (no bad-key / bad-model behaviour to depend on). The rest of the
path is the same: both errors are in ``_ROLLBACK_ERRORS``, so the rollback and quarantine are identical.

**Re-onboarding trigger — the NATS subject.** ``publish_service_event`` publishes
``aiac.apply.service.<uuid>`` (the subject + payload the ``aiac-event-listener`` SPI emits on
``CLIENT_CREATED``) from inside the Controller pod. A redeploy cannot lift a quarantine: the SPI
publishes only on client CREATE, and a re-created client has a new UUID — a new service.

**Why the failed tool is a re-onboarding.** A quarantined tool cannot be lifted by re-onboarding today:
tool Provision mints its discovery token *as the tool's own client* (``client_credentials``), which a
disabled client cannot do, so Provision fails before the build (see ``reenable_provisioned_clients``).
So the tool phase runs last and the lift is proven on the agent. Failing an onboarded tool is also the
stronger check: its SPM existed and ``dev-user``'s call to it was allowed, so "no SPM" and "blocked"
are real transitions, not an empty start.

**Outbound "blocked".** After the quarantine the agent's outbound Rego has no grant to the tool, so OPA
denies (a JSON-RPC error frame, ``plugin: opa``). The tool's client is also disabled, so Keycloak may
instead refuse the token exchange to its audience before OPA is consulted (a ``token-exchange`` error
frame). Both mean the call never reaches the tool, so both count as blocked; the OPA-side proof is the
CR assertion. Any other outcome (``allow``, a transport error) fails.

Run (a live rossoctl/Kind cluster with the AIAC stack + AuthBridge OPA pipeline wired in — see
``k8s/opa-kind-runbook.md`` / ``k8s/opa-kind-enable.sh`` — the event path wired (NATS broker +
``aiac-event-listener`` SPI), the demo images built + ``kind load``ed, a real LLM in-pod for phases 2–3,
and ``.env`` sourced). The flow rolls the Controller four times and takes tens of minutes:

    .venv/bin/pytest -m system -k failure_rollback -v

Without ``-m system`` the suite is not collected; without a wired cluster / env it skips cleanly.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Callable, Iterator

import pytest

pytestmark = pytest.mark.system

HERE = Path(__file__).resolve().parent  # test/system/
REPO_ROOT = HERE.parents[1]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

AGENT = scn.AGENT_WORKLOAD
TOOL = scn.TOOL_WORKLOAD
PROBE_TOOL = "source-read"  # dev-user ✅ on the happy path (rung 2 outbound table), devops-user ❌

# A failed onboarding (Provision + one immediate 404) settles in one delivery; the lift runs the real
# PRB (tens of seconds to minutes) and then waits for bundle-service + OPA to reflect the new CR.
SETTLE_TIMEOUT = float(os.environ.get("AIAC_ROLLBACK_SETTLE_TIMEOUT", "300"))
LIFT_TIMEOUT = float(os.environ.get("AIAC_ROLLBACK_LIFT_TIMEOUT", "600"))

# What the injection makes the consumer log (``log_by_type`` + the dead-letter move, both at ERROR).
INJECTED_ERROR = "UnparseableLLMResponseError"
DLQ_SUBJECT = "aiac.apply.dlq"


def _dlq_line(uuid: str) -> str:
    """The consumer's dead-letter log line for ``uuid`` (``consumer._dispatch``), up to its cause."""
    return f"moved aiac.apply.service.{uuid} to {DLQ_SUBJECT} (permanent failure"


# ======================================================================================
# Phase helpers — each one polls to a terminal state and returns what it saw (never asserts)
# ======================================================================================


def _registered_client(admin, workload: str) -> dict:
    """Wait for the operator to register ``{ns}/{workload}`` after its deploy; return the client."""
    client = uc1.workload_client(admin, workload) if uc1.wait_for_registration(admin, workload) else None
    if client is None:
        raise RuntimeError(
            f"operator did not register Keycloak client {uc1.NAMESPACE}/{workload!r} within "
            f"{uc1.DEPLOY_TIMEOUT:.0f}s — is the event path wired? See k8s/opa-kind-runbook.md."
        )
    return client


def _poll_decision(decide: Callable[[], str], want: str, timeout: float = uc1.BUNDLE_TIMEOUT) -> str:
    """Poll a live decision until it equals ``want``; return the last one observed (the test asserts)."""
    seen = {"decision": "unobserved"}

    def _reached() -> bool:
        seen["decision"] = decide()
        return seen["decision"] == want

    uc1.poll_until(_reached, timeout=timeout, interval=uc1.BUNDLE_POLL_INTERVAL)
    return seen["decision"]


def _settle_failed(admin, workload: str, settled: Callable[[dict], bool]) -> dict:
    """Wait for a failed onboarding of ``workload`` to reach its terminal state — the client disabled
    (the rollback's last step) AND ``settled(client)`` (the quarantine's observable end) — then give the
    consumer a short window to log the dead-letter move. Returns ``{"settled", "client", "logs"}``, read
    while the injected Controller pod (the one that holds the failure log) is still running."""
    seen: dict = {"client": None}

    def _terminal() -> bool:
        seen["client"] = uc1.workload_client(admin, workload)
        client = seen["client"]
        return client is not None and client.get("enabled") is False and settled(client)

    done = uc1.poll_until(_terminal, timeout=SETTLE_TIMEOUT, interval=5)
    logs = {"text": ""}
    if done and seen["client"] is not None:
        uuid = seen["client"]["id"]

        def _logged() -> bool:
            logs["text"] = uc1.controller_logs()
            return _dlq_line(uuid) in logs["text"]

        uc1.poll_until(_logged, timeout=60, interval=5)
    return {"settled": done, "client": seen["client"], "logs": logs["text"]}


def _prefixed(admin, prefix: str) -> dict[str, list[str]]:
    """The realm roles and client scopes whose name starts with ``prefix`` (what Provision creates)."""
    admin.change_current_realm(uc1.TEST_REALM)
    return {
        "roles": sorted(r["name"] for r in admin.get_realm_roles() if r.get("name", "").startswith(prefix)),
        "scopes": sorted(s["name"] for s in admin.get_client_scopes() if s.get("name", "").startswith(prefix)),
    }


def _outbound_block(ctx: dict, user: str, tool_bare: str) -> tuple[str, int | None, str]:
    """One live outbound ``tools/call``; classify it as ``"deny"`` (OPA error frame), ``"refused"``
    (a token-exchange error frame — Keycloak refused the exchange before OPA, see the module
    docstring), ``"allow"``, or ``"error"``. Returns ``(class, http_code, body)``."""
    token = uc1.mint_token(user, scn.USER_PASSWORD, keycloak_url=ctx["keycloak_url"], realm=ctx["realm"])
    code, body = uc1.outbound_probe(token, tool_bare, namespace=ctx["namespace"], agent_pod=uc1.resolve_agent_pod())
    decision = uc1.outbound_outcome(code, body)
    if decision == "error" and code == 200:
        try:
            data = (json.loads(body).get("error") or {}).get("data") or {}
        except (ValueError, AttributeError):
            data = {}
        if data.get("plugin") == "token-exchange" or data.get("error") == "upstream.token-exchange-failed":
            return "refused", code, body
    return decision, code, body


def _poll_blocked(ctx: dict, user: str, tool_bare: str) -> tuple[str, int | None, str]:
    """Poll the outbound call until it is blocked (``deny`` / ``refused``) on two probes in a row — the
    old bundle may still allow it until bundle-service + OPA pick up the re-derived CR, and two in a
    row keeps a one-off exchange blip from ending the wait. Returns the last observation."""
    seen = {"last": ("unobserved", None, ""), "streak": 0}

    def _blocked() -> bool:
        seen["last"] = _outbound_block(ctx, user, tool_bare)
        seen["streak"] = seen["streak"] + 1 if seen["last"][0] in ("deny", "refused") else 0
        return seen["streak"] >= 2

    uc1.poll_until(_blocked, timeout=uc1.BUNDLE_TIMEOUT, interval=uc1.BUNDLE_POLL_INTERVAL)
    return seen["last"]


def _run_phases(ctx: dict, run: dict) -> None:
    """Drive the four phases (module docstring) in order on the shared stack, recording into ``run``.
    A phase whose outcome the next one needs sets ``run["stopped"]`` and returns early; a harness
    failure (a deploy that never registers) raises."""
    admin = ctx["admin"]

    # --- Phase 1 — a failed first onboarding of the agent ---------------------------------------
    with uc1.controller_llm_unusable():
        uc1.deploy_workload(AGENT)  # fires CLIENT_CREATED -> onboard_service -> build raises
        agent = _registered_client(admin, AGENT)
        # Terminal: disabled (rollback) AND the no-rules CR written (the quarantine's agent step).
        failed = _settle_failed(admin, AGENT, lambda _c: uc1.cr_has_no_grants(uc1.authpolicy_policies(AGENT)))
        failed.update(
            uuid=agent["id"],
            cr=uc1.authpolicy_policies(AGENT),
            spm=uc1.spm_present(agent["clientId"]),
            provisioned=_prefixed(admin, f"{AGENT}."),
        )
        run["agent_failed"] = failed
    # The CR is present; wait for bundle-service + OPA to enforce it (with no CR yet, the combiner
    # allowed the pod, so dev-user inbound flips from allow to deny).
    failed["inbound"] = _poll_decision(lambda: uc1.inbound_decision(ctx, "dev-user"), "deny")
    if not failed["settled"]:
        run["stopped"] = "the failed agent onboarding did not settle (phase 1)"
        return

    # --- Phase 2 — lift: the seam is restored (context exited); re-fire the agent's trigger ------
    uc1.publish_service_event(agent["id"])

    def _agent_lifted() -> bool:
        client = uc1.workload_client(admin, AGENT)
        return (
            bool(client and client.get("enabled"))
            and uc1.cr_has_grants(uc1.authpolicy_policies(AGENT))
            and uc1.inbound_decision(ctx, "dev-user") == "allow"
        )

    lifted = uc1.poll_until(_agent_lifted, timeout=LIFT_TIMEOUT, interval=uc1.BUNDLE_POLL_INTERVAL)
    run["agent_lifted"] = {
        "client": uc1.workload_client(admin, AGENT),
        "cr": uc1.authpolicy_policies(AGENT),
        "inbound": uc1.inbound_decision(ctx, "dev-user"),
    }
    if not lifted:
        run["stopped"] = f"the agent's re-onboarding did not lift its quarantine within {LIFT_TIMEOUT:.0f}s (phase 2)"
        return

    # --- Phase 3 — onboard the tool on the happy path, prepare Part B, then one MCP session -------
    uc1.deploy_workload(TOOL)
    tool = _registered_client(admin, TOOL)
    uc1.ensure_github_tool_route(uc1.NAMESPACE)
    uc1.grant_exchange_scope(admin)
    uc1.restart_agent(uc1.NAMESPACE)
    outbound = _poll_decision(lambda: uc1.outbound_decision(ctx, "dev-user", PROBE_TOOL), "allow", LIFT_TIMEOUT)
    if outbound != "allow":
        run["stopped"] = f"the tool did not converge on the happy path: dev-user outbound {PROBE_TOOL}={outbound!r}"
        return
    run["session"] = {user: uc1.mcp_session_decisions(ctx, user, PROBE_TOOL) for user in ("dev-user", "devops-user")}

    # --- Phase 4 — a failed re-onboarding of the (onboarded) tool --------------------------------
    with uc1.controller_llm_unusable():
        uc1.publish_service_event(tool["id"])
        # Terminal: disabled (rollback) AND its phase-3 SPM gone (the quarantine's first step).
        failed = _settle_failed(admin, TOOL, lambda c: not uc1.spm_present(c["clientId"]))
        failed.update(
            uuid=tool["id"],
            cr=uc1.authpolicy_policies(TOOL),
            spm=uc1.spm_present(tool["clientId"]),
            agent_cr=uc1.authpolicy_policies(AGENT),  # re-derived in the quarantine, before it returns
        )
        run["tool_failed"] = failed
    failed["outbound"] = _poll_blocked(ctx, "dev-user", PROBE_TOOL)


# ======================================================================================
# Module fixture — pristine slate → the four phases → teardown to pristine
# ======================================================================================


@pytest.fixture(scope="module")
def run() -> Iterator[dict]:
    """Run the four phases once on a pristine stack and yield what each observed. Module-scoped (not
    session, unlike rungs 1–3), so this rung's stack is torn down as soon as its tests end. The
    harness restores the Controller's env on every exit path; teardown undeploys both workloads and
    scrubs every registration + CR back to pristine, verified."""
    with uc1.pristine_stack([AGENT, TOOL]) as ctx:
        observed: dict = {}
        _run_phases(ctx, observed)
        yield observed


def _phase(run: dict, key: str) -> dict:
    """The record of phase ``key``, or fail naming why the flow stopped before it."""
    if key not in run:
        pytest.fail(f"phase {key!r} not reached — {run.get('stopped', 'an earlier phase failed')}")
    return run[key]


def _failed(run: dict, key: str) -> dict:
    """The record of a failed-onboarding phase, failing first if it never reached its terminal state."""
    obs = _phase(run, key)
    client = obs["client"] or {}
    assert obs["settled"], (
        f"{key}: no rolled-back + quarantined terminal state within {SETTLE_TIMEOUT:.0f}s — client "
        f"enabled={client.get('enabled')!r}. Did the injection reach the Controller (onboarding may have "
        "succeeded), or did the build fail with an error outside _ROLLBACK_ERRORS?"
    )
    return obs


# ======================================================================================
# Phase 1 — failed agent
# ======================================================================================


@pytest.mark.parametrize(("key", "service_type"), [("agent_failed", "Agent"), ("tool_failed", "Tool")])
def test_failed_service_client_disabled_and_type_kept(run: dict, key: str, service_type: str) -> None:
    """The rollback disables the Keycloak client last (the failed-service marker — disabled, not
    deleted) and keeps its ``client.type``: the type was not created by the failed run."""
    client = _failed(run, key)["client"]
    assert client.get("enabled") is False, f"{key}: client is not disabled: enabled={client.get('enabled')!r}"
    attr = (client.get("attributes") or {}).get("client.type")
    assert attr == service_type, f"{key}: client.type not kept: {attr!r} (want {service_type!r})"


def test_failed_agent_provisioned_entities_removed(run: dict) -> None:
    """No partial footprint: every ``github-agent.*`` role and scope Provision created on the failed
    run is deleted (the run started from a clean slate, so all of them were created by it)."""
    left = _failed(run, "agent_failed")["provisioned"]
    assert left == {"roles": [], "scopes": []}, f"roles/scopes the rollback should have deleted: {left}"


def test_failed_agent_has_no_rules_cr(run: dict) -> None:
    """The agent's ``AuthorizationPolicy`` CR is PRESENT and is the no-rules CR: both packages keep
    ``default allow := false`` and every grant binding is empty. Present, not deleted — the
    bundle-service combiner allows a pod that has no CR."""
    policies = _failed(run, "agent_failed")["cr"]
    assert policies is not None, f"no AuthorizationPolicy CR {AGENT!r} — a missing CR opens the agent"
    assert uc1.cr_has_no_grants(policies), f"the agent's CR still carries grants: {policies}"


def test_failed_agent_inbound_denied(run: dict) -> None:
    """A real inbound request as ``dev-user`` (allowed on the happy path) through AuthBridge + the
    deployed OPA plugin is denied once the no-rules CR is in force."""
    decision = _failed(run, "agent_failed")["inbound"]
    assert decision == "deny", f"dev-user inbound to the quarantined agent: {decision!r} (want 'deny')"


@pytest.mark.parametrize("key", ["agent_failed", "tool_failed"])
def test_failed_service_has_no_spm(run: dict, key: str) -> None:
    """The quarantine leaves no SPM for the failed service in the Policy Store (for the tool, the SPM
    its phase-3 onboarding wrote is deleted)."""
    assert _failed(run, key)["spm"] is False, f"{key}: the Policy Store still holds an SPM for the service"


@pytest.mark.parametrize("key", ["agent_failed", "tool_failed"])
def test_failure_logged_and_dead_lettered(run: dict, key: str) -> None:
    """The Controller logs the build failure (its type) and moves the event to the DLQ as a
    **permanent** failure on the first delivery — the injection's error, never a redelivery loop."""
    obs = _failed(run, key)
    assert INJECTED_ERROR in obs["logs"], f"{key}: no {INJECTED_ERROR!r} in the Controller log"
    assert _dlq_line(obs["uuid"]) in obs["logs"], f"{key}: no dead-letter line {_dlq_line(obs['uuid'])!r}"


# ======================================================================================
# Phase 2 — lift
# ======================================================================================


def test_reonboarding_lifts_agent_quarantine(run: dict) -> None:
    """A successful re-onboarding (the seam restored, the trigger re-fired) writes the real CR over the
    no-rules CR and re-enables the client, so ``dev-user`` reaches the agent again."""
    lifted = _phase(run, "agent_lifted")
    assert uc1.cr_has_grants(lifted["cr"]), f"the agent's CR has no grants after the lift: {lifted['cr']}"
    assert (lifted["client"] or {}).get("enabled") is True, "the agent's client was not re-enabled"
    assert lifted["inbound"] == "allow", f"dev-user inbound after the lift: {lifted['inbound']!r}"


# ======================================================================================
# Phase 3 — outbound MCP session (happy path)
# ======================================================================================


def _result(body: str) -> dict | None:
    """The JSON-RPC ``result`` object of a response body, or ``None``."""
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    return doc.get("result") if isinstance(doc, dict) and isinstance(doc.get("result"), dict) else None


def test_mcp_session_allowed_for_granted_user(run: dict) -> None:
    """For ``dev-user`` (a grant on some tool of the target) the whole MCP session passes the agent's
    outbound: ``initialize`` and ``tools/list`` return a ``result`` frame (``tools/list`` names every
    tool), the ``notifications/initialized`` notification is accepted, and the ``tools/call`` reaches
    the tool."""
    session = _phase(run, "session")["dev-user"]
    for method in ("initialize", "notifications/initialized", "tools/list", "tools/call"):
        decision, code, body = session[method]
        assert decision == "allow", f"dev-user {method}: {decision!r} (HTTP {code}, body={body[:300]!r})"
    for method in ("initialize", "tools/list"):
        assert _result(session[method][2]) is not None, f"dev-user {method}: no result frame"
    names = {t.get("name") for t in (_result(session["tools/list"][2]) or {}).get("tools", [])}
    assert set(scn.TOOL_REQUEST_NAMES) <= names, f"tools/list did not name every tool: {sorted(names)}"


def test_mcp_session_denied_for_ungranted_user(run: dict) -> None:
    """For ``devops-user`` (no grant on any tool) the session methods are denied: no tool of the target
    passes the per-tool check, so the session rule does not fire (it is not an allow-all)."""
    session = _phase(run, "session")["devops-user"]
    for method in ("initialize", "tools/list", "tools/call"):
        decision, code, body = session[method]
        assert decision == "deny", f"devops-user {method}: {decision!r} (HTTP {code}, body={body[:300]!r})"


# ======================================================================================
# Phase 4 — failed tool
# ======================================================================================


def test_failed_tool_has_no_cr(run: dict) -> None:
    """A tool never has an ``AuthorizationPolicy`` CR, and the quarantine does not write one for it."""
    assert _failed(run, "tool_failed")["cr"] is None, f"unexpected AuthorizationPolicy CR {TOOL!r}"


def test_failed_tool_removed_from_agent_outbound_cr(run: dict) -> None:
    """The quarantine re-derives the agent that targeted the tool: its outbound Rego no longer grants
    any user or the agent a tool of the failed tool (every outbound grant binding is empty — the tool
    was its only target), while the agent's own inbound grants stay."""
    policies = _failed(run, "tool_failed")["agent_cr"]
    assert policies is not None, f"the agent's CR {AGENT!r} is missing"
    outbound = policies.get(uc1.CR_OUTBOUND_PATH, "")
    for var in uc1.OUTBOUND_GRANT_BINDINGS:
        assert uc1.rego_binding_empty(outbound, var) is True, f"agent outbound {var} still grants: {outbound}"
    assert uc1.cr_has_grants(policies), "the agent lost its inbound grants in the tool's quarantine"


def test_failed_tool_outbound_call_denied(run: dict) -> None:
    """The ``dev-user`` call to the tool that phase 3 allowed is now blocked through the agent's
    outbound — an OPA deny, or a token-exchange refusal to the disabled tool's audience (module
    docstring); never ``allow``, never a transport error."""
    decision, code, body = _failed(run, "tool_failed")["outbound"]
    assert decision in ("deny", "refused"), (
        f"dev-user outbound {PROBE_TOOL} to the quarantined tool: {decision!r} (HTTP {code}, body={body[:300]!r})"
    )
