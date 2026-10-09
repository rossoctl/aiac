"""Rung 2 of the UC-1 onboarding ladder — onboard the **agent, then the tool**.

Issue ``testing/5.4.2-uc1-onboard-agent-then-tool.md``; spec
``docs/testing/uc1-onboarding-pipeline.md``. Onboard **event-driven** by deploying the ``github-agent``
workload **first** and the ``github-tool`` workload **second** (each deploy → operator registers a
Keycloak client → ``CLIENT_CREATED`` → ``aiac-event-listener`` SPI → NATS → the agent consumer runs
``onboard_service``), then assert the **full** truth table at the end by driving **real HTTP requests
through AuthBridge** and reading the **real OPA plugin's** allow/deny (handoff 08; live loop shape in
``k8s/opa-kind-runbook.md``).

This rung proves the key reconciliation property: onboarding the tool **after** the agent completes
the tool check. When the agent is onboarded alone there is no tool check (rung 1); when the tool is
then onboarded, its Service Policy Builder pairs the tool's scopes against the existing role universe
(agent roles + user roles) and the PCE **routes** those ``(role, tool-scope)`` rules onto the **tool's**
persistent ``ServicePolicyModel`` via ``compute_and_apply(override=False)``. Then the PCE deploys the
affected services of the live **enforcement side** (D23):

* **target side** (default) — the affected set is the ``changed`` set: only ``SPM(github-tool)``
  changed, so the PCE writes **github-tool's own CR**, whose inbound has both gates (the user gate and
  the calling-agent gate, D26). The agent's CR does not change; its outbound is a pass-through (D24).
* **agent side** — the agent's role targets a tool scope, so the agent is affected: its
  ``AgentPolicyModel`` is **re-derived from the SPMs** and its outbound package is (re)written with the
  full user→tool gate; github-tool gets a pass-through CR.

The live probes below observe the result as real allow/deny decisions once ``bundle-service``
recomposes the bundles; the verdicts are the same under each side. Two side-aware nodes check where
the deny of an ungranted call comes from (``deny_origin``) and the shape of both CRs
(``cr_matches_side``).

**The subject on every leg (D31).** The tool's inbound keys users by username, and it reads the
subject from the ``sub`` of the token that the agent exchanged. Keycloak's standard token exchange
builds that token from the agent client's scopes only, so AIAC links the client scope
``aiac-username-sub`` to each onboarded client, and also to the login client ``rossoctl`` for the login
token. ``test_subject_scope_linked`` checks this in Keycloak (the scope, its mapper, no marker, the three
default links, no ``sub`` client mapper on ``rossoctl``, and the ``rossoctl`` login token), and ``test_exchanged_token_subject_is_username`` decodes a real exchanged token (as the
agent client, with its client secret — the identity that ``k8s/opa-kind-enable.sh`` gives AuthBridge's
``token-exchange``; it skips cleanly only when the agent client uses another authenticator). The shared fixture also fails fast when a link is missing
(``require_subject_scope`` right after each workload converges).

There is **no agent re-onboard** and **no intermediate validation** — only the end state is checked
(apart from the subject-scope check of the fixture).
This is order 1 of the order-independence pair; rung 3 (tool then agent) asserts its final live
outbound matrix is **identical** to this rung's.

Reuses the shared harness (``uc1_onboard.py`` — config, Keycloak provisioning/cleanup, event-driven
deploy/undeploy trigger, Part-B outbound-leg prep, bundle convergence poll, per-rung fixture flow) and
``scenario_uc1.py`` (the truth tables — the oracle). The deployed OPA plugin is the evaluator (no
``.rego`` dump, no ``opa`` binary). The **only** rung-2-specific content here is the oracle (the full
tool check, keyed on the **bare** runtime tool names) and the live assertions; the onboarding order
— ``[agent, tool]`` — is the deploy order passed to the shared fixture flow.

Per-rung flow (spec § Per-rung flow): **pre-run no-workloads slate → provision realm/users →
deploy agent (fires the event) + converge → deploy tool (fires the event) + converge → Part B →
poll bundle → drive real requests + assert → tear workloads + registrations down to pristine**.
Deploying each workload is now the onboarding **trigger** (a test step, not a precondition); teardown
restores the cluster to its pre-test state.

Run (needs a live rossoctl/Kind cluster with the AIAC stack + AuthBridge OPA pipeline wired in — see
``k8s/opa-kind-runbook.md`` / ``k8s/opa-kind-enable.sh`` — the event path wired (NATS broker +
``aiac-event-listener`` SPI) and the demo images built + ``kind load``ed (``demo/assets/kind-load.sh``;
the fixture deploys the workloads itself), a real LLM in-pod, and ``.env`` sourced):

    .venv/bin/pytest test/system/test_uc1_onboard_agent_then_tool.py -m system -v

Without ``-m system`` the suite is not collected; without a wired cluster / env it skips cleanly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.system

HERE = Path(__file__).resolve().parent  # test/system/
REPO_ROOT = HERE.parents[1]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

TEST_REALM = uc1.TEST_REALM

# Rung 2's fixture-independent grant-set oracle (the full, non-empty user→tool gate the tool onboarding
# completes on the agent) lives at the unit level in
# ``test/unit/agent/uc/onboarding/test_uc1_grant_set_oracles.py``, alongside the rung-3 oracle it must
# equal. This suite keeps only the live, fixture-driven assertions against the real plugin.


# ======================================================================================
# Session fixture — no-workloads slate → deploy agent → deploy tool → Part B → poll bundle → yield → teardown
# ======================================================================================


@pytest.fixture(scope="session")
def onboarded() -> dict:
    """Onboard the agent **then** the tool — event-driven — by deploying them in that order via the
    shared harness (order is this rung's identity — tool onboarding completes the tool check), and
    yield the live probe context (``admin`` handle, ``agent_pod``, Keycloak URL/realm,
    ``tool_onboarded=True``, the live ``side``). The harness starts from a no-workloads slate and, on teardown,
    tears both workloads + all their Keycloak registrations and ``AuthorizationPolicy`` CRs back down
    to pristine (spec § Per-rung flow). No agent re-onboard, no intermediate validation — only the end
    state is asserted below."""
    with uc1.onboarded_stack([scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD]) as ctx:
        yield ctx


# ======================================================================================
# Live tests — Keycloak entities + real-plugin decisions (verdicts computed from scenario_uc1)
# ======================================================================================


def test_agent_role_and_scopes_provisioned(onboarded: dict) -> None:
    """Keycloak holds the agent's per-skill operator roles + the two AgentCard scopes, all with
    their descriptions."""
    admin = onboarded["admin"]
    admin.change_current_realm(TEST_REALM)

    for name, description in scn.AGENT_ROLES.items():
        role = admin.get_realm_role(name)
        assert role and role.get("name") == name, f"missing realm role {name!r}"
        assert (role.get("description") or "") == description, (
            f"agent role {name!r} description mismatch: {role.get('description')!r} != {description!r}"
        )

    scopes = {s["name"]: (s.get("description") or "") for s in admin.get_client_scopes()}
    for name, description in scn.AGENT_SCOPES.items():
        assert name in scopes, f"missing agent scope {name!r}"
        assert scopes[name] == description, (
            f"agent scope {name!r} description mismatch: {scopes[name]!r} != {description!r}"
        )


def test_tool_scopes_provisioned(onboarded: dict) -> None:
    """The tool was onboarded, so all four ``github-tool.*`` scopes exist with their MCP
    ``tools/list`` descriptions (the discovered tool boundary)."""
    admin = onboarded["admin"]
    admin.change_current_realm(TEST_REALM)

    scopes = {s["name"]: (s.get("description") or "") for s in admin.get_client_scopes()}
    for name, description in scn.TOOL_SCOPES.items():
        assert name in scopes, f"missing tool scope {name!r}"
        assert scopes[name] == description, (
            f"tool scope {name!r} description mismatch: {scopes[name]!r} != {description!r}"
        )


@pytest.mark.parametrize("subject", list(scn.USERS))
def test_inbound(onboarded: dict, subject: str) -> None:
    """Inbound gate — a real request through AuthBridge as ``subject`` is allowed iff their role may
    reach some discovered agent scope (dev-user ✅, test-user ✅, devops-user ❌) — unchanged by the
    tool onboarding. The real OPA plugin decides."""
    assert uc1.inbound_decision(onboarded, subject) == uc1.expected_inbound_decision(subject), subject


@pytest.mark.parametrize("subject", list(scn.USERS))
@pytest.mark.parametrize("tool_bare", scn.TOOL_REQUEST_NAMES)
def test_outbound(onboarded: dict, subject: str, tool_bare: str) -> None:
    """Tool check — a real MCP ``tools/call`` for the **bare** tool through AuthBridge's forward proxy
    (token-exchange → the tool check) decides each ``(subject, tool)`` per the full
    ``OUTBOUND_SUBJECT_BARE`` table — the check tool onboarding completed. AuthBridge's ``mcp-parser``
    surfaces ``input.mcp.params.name`` (no hand-built input). Under target side github-tool's inbound
    OPA decides (a deny is its HTTP 403, relayed by the agent's pass-through outbound); under agent side
    the agent's outbound OPA decides (a deny is a JSON-RPC error frame). The harness classifies both."""
    assert uc1.outbound_decision(onboarded, subject, tool_bare) == uc1.expected_outbound_decision(subject, tool_bare), (
        f"{subject} / {tool_bare}"
    )


def test_deny_comes_from_enforcement_point(onboarded: dict) -> None:
    """The deny of an ungranted call (``test-user`` × ``source-read``) comes from the enforcement point
    of the live side: from github-tool's inbound under target side — so the agent's outbound let the
    call through and the tool check moved to the callee — and from the agent's outbound under agent
    side (``deny_origin`` reads the raw response)."""
    probe = uc1.outbound_deny_probe(onboarded, "test-user", "source-read")
    want = uc1.SIDE_ENFORCEMENT_POINT[onboarded["side"]]
    assert probe["decision"] == "deny" and probe["origin"] == want, (
        f"{onboarded['side']}: test-user / source-read decision={probe['decision']!r} origin={probe['origin']!r} "
        f"(want 'deny' from {want!r}); HTTP {probe['code']}, body={probe['body'][:300]!r}"
    )


def test_crs_match_live_side(onboarded: dict) -> None:
    """github-agent's and github-tool's CRs both exist (every managed service has a CR, D20), each with
    exactly the two request packages, in the shape of the live side (``cr_matches_side``): under target
    side both inbounds are rules-based with grants and both outbounds are pass-throughs; under agent
    side the agent's outbound is rules-based and github-tool has a pass-through CR."""
    side = onboarded["side"]
    problems = {
        workload: uc1.cr_side_mismatches(uc1.authpolicy_policies(workload), kind, side)
        for workload, kind in uc1.WORKLOAD_KIND.items()
    }
    assert not any(problems.values()), f"CRs do not match {side}: {problems}"


# ======================================================================================
# The subject on every leg (D31) — both sources of sub = username
# ======================================================================================


def test_subject_scope_linked(onboarded: dict) -> None:
    """The one source of ``sub`` = username is in place (D31):

    * ``aiac-username-sub`` exists with the ``username → sub`` mapper and no ``aiac.managed`` marker,
      and the login client ``rossoctl``, github-agent and github-tool each link it as a **default**
      scope (``subject_scope_link_problems``);
    * ``rossoctl`` has no client mapper of its own that writes ``sub`` (no AIAC step adds one), and a
      ``rossoctl`` password-grant token for ``dev-user`` has ``sub`` = ``dev-user``."""
    admin = onboarded["admin"]
    problems = uc1.subject_scope_link_problems(admin, [scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD])
    assert not problems, f"the subject scope {uc1.SUBJECT_SCOPE!r} is not in place: {problems}"

    login = uc1.login_client(admin)
    assert login is not None, f"no login client {uc1.KEYCLOAK_CLIENT_ID!r} in realm {TEST_REALM!r}"
    mappers = admin.get_mappers_from_client(login["id"])
    assert not any(uc1.is_login_subject_mapper(m) for m in mappers), (
        f"the login client {uc1.KEYCLOAK_CLIENT_ID!r} has a client mapper that writes sub (the scope "
        f"{uc1.SUBJECT_SCOPE!r} must be the one source): "
        f"{[(m.get('name'), (m.get('config') or {}).get('claim.name')) for m in mappers]}"
    )
    sub = uc1.login_subject(onboarded, "dev-user")
    assert sub == "dev-user", f"a {uc1.KEYCLOAK_CLIENT_ID!r} login token for dev-user has sub={sub!r}"


@pytest.mark.parametrize("subject", list(scn.USERS))
def test_exchanged_token_subject_is_username(onboarded: dict, subject: str) -> None:
    """A standard token exchange of ``subject``'s login token, as the agent client to the tool audience
    (the request AuthBridge's route sends), gives a token with ``sub`` = the username — the subject
    that the tool's inbound reads. It comes from the agent's default scope ``aiac-username-sub``: the
    exchange applies only the agent client's scopes. The harness authenticates with the agent's client
    secret; it skips cleanly only when the agent client uses another authenticator (for example a SPIFFE
    JWT-SVID through ``federated-jwt``), and a refused secret is a failure. This is the one direct check
    of the exchanged ``sub``: under agent side no one-hop decision reads it."""
    sub = uc1.exchanged_subject(onboarded, subject)
    assert sub == subject, (
        f"the exchanged token for {subject!r} has sub={sub!r} (want the username) — is {uc1.SUBJECT_SCOPE!r} "
        "a default scope of the agent client?"
    )
