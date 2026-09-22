"""Rung 2 of the UC-1 onboarding ladder — onboard the **agent, then the tool**.

Issue ``testing/5.4.2-uc1-onboard-agent-then-tool.md``; spec
``docs/testing/uc1-onboarding-pipeline.md``. Onboard **event-driven** by deploying the ``github-agent``
workload **first** and the ``github-tool`` workload **second** (each deploy → operator registers a
Keycloak client → ``CLIENT_CREATED`` → ``aiac-event-listener`` SPI → NATS → the agent consumer runs
``onboard_service``), then assert the **full** truth table at the end by driving **real HTTP requests
through AuthBridge** and reading the **real OPA plugin's** allow/deny (handoff 08; live loop shape in
``k8s/opa-kind-runbook.md``).

This rung proves the key reconciliation property: onboarding the tool **after** the agent
retroactively completes the agent's outbound policy. When the agent is onboarded alone its outbound
gate is empty (rung 1); when the tool is then onboarded, its Service Policy Builder pairs the tool's
scopes against the existing role universe (agent role + user roles) and the PCE **routes** those
``(role, tool-scope)`` rules onto the **tool's** persistent ``ServicePolicyModel`` via
``compute_and_apply(override=False)``. Because the agent's role targets a tool scope, the agent is in
the affected set, so its ``AgentPolicyModel`` is **re-derived from the SPMs** and its outbound
``AuthorizationPolicy`` rule is (re)written with the full user→tool gate — which the live probes below
observe as real allow/deny decisions once ``bundle-service`` recomposes the bundle.

There is **no agent re-onboard** and **no intermediate validation** — only the end state is checked.
This is order 1 of the order-independence pair; rung 3 (tool then agent) asserts its final live
outbound matrix is **identical** to this rung's.

Reuses the shared harness (``uc1_onboard.py`` — config, Keycloak provisioning/cleanup, event-driven
deploy/undeploy trigger, Part-B outbound-leg prep, bundle convergence poll, per-rung fixture flow) and
``scenario_uc1.py`` (the truth tables — the oracle). The deployed OPA plugin is the evaluator (no
``.rego`` dump, no ``opa`` binary). The **only** rung-2-specific content here is the oracle (the full
outbound gate, keyed on the **bare** runtime tool names) and the live assertions; the onboarding order
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
    shared harness (order is this rung's identity — tool onboarding retroactively completes the agent's
    outbound gate), and yield the live probe context (``admin`` handle, ``agent_pod``, Keycloak
    URL/realm, ``tool_onboarded=True``). The harness starts from a no-workloads slate and, on teardown,
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
    """Outbound user gate — a real MCP ``tools/call`` for the **bare** tool through AuthBridge's
    forward proxy (token-exchange → OPA) decides each ``(subject, tool)`` per the full
    ``OUTBOUND_SUBJECT_BARE`` table — the gate tool onboarding completed on the agent. AuthBridge's
    ``mcp-parser`` surfaces ``input.mcp.params.name`` (no hand-built input); the real OPA plugin
    renders a denial as a JSON-RPC error frame the harness classifies."""
    assert uc1.outbound_decision(onboarded, subject, tool_bare) == uc1.expected_outbound_decision(subject, tool_bare), (
        f"{subject} / {tool_bare}"
    )
