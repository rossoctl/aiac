"""Rung 3 of the UC-1 onboarding ladder — onboard the **tool, then the agent**.

Issue ``testing/5.4.3-uc1-onboard-tool-then-agent.md``; spec
``docs/testing/uc1-onboarding-pipeline.md``. Drive the **real** in-cluster UC-1
Service Onboarding agent (``POST /apply/service/{id}``) for the ``github-tool`` **first** and the
``github-agent`` **second**, then assert the **full** truth table at the end by driving **real HTTP
requests through AuthBridge** and reading the **real OPA plugin's** allow/deny (handoff 08) — and,
crucially, that this live end state is **identical to rung 2's** (agent→tool).

This is the direct single-pass happy path: onboarding the tool first provisions the four
``github-tool.*`` scopes, and the ``(user role → tool scope)`` rules that pass produces are routed
**durably onto ``SPM(github-tool)``** (the tool gets an SPM, no APM; no agent APM is written yet — no
agent targets a tool scope at this point). When the agent is then onboarded, its Service Policy Builder
reads the universe (now including the tool scopes), the PCE routes the agent→tool rule to
``SPM(github-tool)``, marks the agent affected, and **derives** its APM from the SPMs — picking up the
durable user→tool rules already on ``SPM(github-tool)`` — so the agent's outbound
``AuthorizationPolicy`` rule is emitted with the full user→tool gate in one pass.

This rung is the **live counterpart of the PCE's order-independence unit test (8.11)** and the exact
repro of the original order-dependence bug: under the old APM-only design, tool-then-agent **lost** the
``user role → tool scope`` rule because no agent yet targeted the tool scope at tool onboarding. The
SPM redesign stores that rule durably on ``SPM(github-tool)`` and reconstructs it when the agent's APM
is derived. So this rung's live outbound matrix must **equal rung 2's** — the live proof is both rungs
driving the *same* bare user→tool matrix through the real plugin and getting the same decisions. A
divergence is an onboarding-order **bug** this rung exists to surface (spec § *Onboarding order is
irrelevant*).

Reuses the shared harness (``uc1_onboard.py`` — config, Keycloak provisioning/cleanup, onboard
trigger, Part-B outbound-leg prep, bundle convergence poll, per-rung fixture flow), the shared
tool-onboarded oracle (``uc1.expected_outbound_bare`` — the same gate rung 2 asserts), and
``scenario_uc1.py`` (the truth tables — the oracle). The deployed OPA plugin is the evaluator (no
``.rego`` dump, no ``opa`` binary). The **only** rung-3-specific content here is the onboarding order —
``[tool, agent]`` — and the order-independence check against **rung 2's** published expectations.

Per-rung flow (spec § Per-rung flow): **Keycloak cleanup → onboard tool → onboard agent → Part B →
poll bundle → drive real requests + assert → Keycloak cleanup**. Deployment + client registration are
**preconditions**, not test steps.

Run (needs a live rossoctl/Kind cluster with the AuthBridge OPA pipeline wired in — see
``k8s/opa-kind-runbook.md`` / ``k8s/opa-kind-enable.sh`` — the demo workloads deployed +
registered into ``AIAC_TEST_REALM``, a real LLM in-pod, and ``.env`` sourced):

    .venv/bin/pytest test/system/test_uc1_onboard_tool_then_agent.py -m system -v

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

# Rung 3's fixture-independent grant-set oracle — and the order-independence oracle that pins its end
# state as **identical to rung 2's** — live at the unit level in
# ``test/unit/agent/uc/onboarding/test_uc1_grant_set_oracles.py``. This suite keeps only the live,
# fixture-driven assertions against the real plugin; both rungs driving the same bare matrix through
# the real plugin is the live order-independence proof.


# ======================================================================================
# Session fixture — cleanup → onboard tool → onboard agent → Part B → poll bundle → yield → cleanup
# ======================================================================================


@pytest.fixture(scope="session")
def onboarded() -> dict:
    """Onboard the tool **then** the agent via the shared harness (order is this rung's identity —
    the tool's scopes already exist when the agent's Service Policy Builder reads the universe, so the
    agent's APM is derived with the full user→tool gate in one pass), and yield the live probe context
    (``admin`` handle, ``agent_pod``, Keycloak URL/realm, ``tool_onboarded=True``). Keycloak cleanup +
    CR delete run before and after; the clients are left registered as before (spec § Per-rung flow)."""
    with uc1.onboarded_stack([scn.TOOL_WORKLOAD, scn.AGENT_WORKLOAD]) as ctx:
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
    """The tool was onboarded (first), so all four ``github-tool.*`` scopes exist with their MCP
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
    reach some discovered agent scope (dev-user ✅, test-user ✅, devops-user ❌) — unaffected by
    onboarding order. The real OPA plugin decides."""
    assert uc1.inbound_decision(onboarded, subject) == uc1.expected_inbound_decision(subject), subject


@pytest.mark.parametrize("subject", list(scn.USERS))
@pytest.mark.parametrize("tool_bare", scn.TOOL_REQUEST_NAMES)
def test_outbound(onboarded: dict, subject: str, tool_bare: str) -> None:
    """Outbound user gate — a real MCP ``tools/call`` for the **bare** tool through AuthBridge's
    forward proxy (token-exchange → OPA) decides each ``(subject, tool)`` per the full
    ``OUTBOUND_SUBJECT_BARE`` table — reconstructed from the durable ``SPM(github-tool)`` rules when the
    agent's APM was derived. This is the same bare matrix rung 2 drives; **both rungs passing it is the
    live order-independence proof** (the exact cell the original order-dependence bug corrupted)."""
    assert uc1.outbound_decision(onboarded, subject, tool_bare) == uc1.expected_outbound_decision(subject, tool_bare), (
        f"{subject} / {tool_bare}"
    )
