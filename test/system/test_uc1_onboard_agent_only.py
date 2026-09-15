"""Rung 1 of the UC-1 onboarding ladder — onboard the **agent only**.

The simplest rung (issue ``testing/5.4.1-uc1-onboard-agent-only.md``; spec
``docs/testing/uc1-onboarding-pipeline.md``): onboard **only** the ``github-agent`` **event-driven**,
by deploying its workload (deploy → the rossoctl operator registers a Keycloak client → Keycloak
emits ``CLIENT_CREATED`` → the AIAC SPI ``aiac-event-listener`` publishes on NATS → the agent's
consumer runs ``onboard_service`` — the same handler the removed ``POST /apply`` once called). The
``github-tool`` is **not deployed** (deploying it would onboard it), so no tool is onboarded. Then
assert the agent-side outcome by driving **real HTTP requests through AuthBridge** and reading the
**real OPA plugin's** allow/deny (handoff 08; live loop shape in ``k8s/opa-kind-runbook.md``). Proves
agent discovery + inbound policy generation stand alone, and that the outbound user gate is correctly
**empty** (all deny) when no tool has been onboarded.

Single live rossoctl/Kind cluster with the AuthBridge OPA pipeline wired into both legs, plus the
event path (NATS broker + ``aiac-event-listener`` SPI); it skips cleanly when either is unwired. The
shared harness (config, Keycloak provisioning/cleanup, event-driven deploy/undeploy trigger, Part-B
outbound-leg prep, bundle convergence poll, and the per-rung fixture flow) lives in ``uc1_onboard.py``
and is reused by every rung; this module supplies only rung 1's oracle (verdicts computed from
``scenario_uc1.py``) and its live assertions. There is no ``.rego`` dump and no ``opa`` binary anymore
— the deployed plugin is the evaluator.

Per-rung flow (spec § Per-rung flow): **pre-run no-workloads slate → provision realm/users →
deploy agent (fires the event) + converge → Part B → poll bundle → drive real requests + assert →
tear workloads + registrations down to pristine**. Deploying the workload is now the onboarding
**trigger** (a test step, not a precondition); teardown restores the cluster to its pre-test state.

*Onboard + evaluate against the real plugin — no CrewAI flow is triggered* (the probes hit
``ping/nonexistent`` inbound and a bare ``tools/call`` outbound).

Run (needs a live rossoctl/Kind cluster with the AIAC stack + AuthBridge OPA pipeline wired in — see
``k8s/opa-kind-runbook.md`` / ``k8s/opa-kind-enable.sh`` — the event path wired (NATS broker +
``aiac-event-listener`` SPI) and the demo images built + ``kind load``ed (``demo/assets/kind-load.sh``;
the fixture deploys the workloads itself), a real LLM in-pod, and ``.env`` sourced):

    .venv/bin/pytest test/system/test_uc1_onboard_agent_only.py -m system -v

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

# Rung 1's fixture-independent grant-set oracle (inbound truth table; the outbound user gate is empty
# because no tool is onboarded) lives at the unit level in
# ``test/unit/agent/uc/onboarding/test_uc1_grant_set_oracles.py``. This suite keeps only the live,
# fixture-driven assertions against the real plugin.


# ======================================================================================
# Session fixture — no-workloads slate → deploy agent (fires event) → Part B → poll bundle → yield → teardown
# ======================================================================================


@pytest.fixture(scope="session")
def onboarded() -> dict:
    """Onboard **only** the agent — event-driven — by deploying its workload via the shared harness,
    and yield the live probe context (``admin`` handle, ``agent_pod``, Keycloak URL/realm,
    ``tool_onboarded=False``). The tool is **not** deployed, so it is not onboarded. The harness
    starts from a no-workloads slate and, on teardown, tears the workload + all its Keycloak
    registrations and ``AuthorizationPolicy`` CRs back down to pristine (spec § Per-rung flow)."""
    with uc1.onboarded_stack([scn.AGENT_WORKLOAD]) as ctx:
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


def test_no_tool_scopes_provisioned(onboarded: dict) -> None:
    """The tool was not onboarded, so no ``github-tool.*`` scope exists (UC-1-provisioned scopes are
    prefixed ``github-tool.``; the operator's ``*-aud`` audience scopes are not and don't count)."""
    admin = onboarded["admin"]
    admin.change_current_realm(TEST_REALM)
    tool_scopes = [
        s["name"] for s in admin.get_client_scopes() if s.get("name", "").startswith(f"{scn.TOOL_WORKLOAD}.")
    ]
    assert not tool_scopes, f"unexpected tool scopes provisioned: {tool_scopes}"


@pytest.mark.parametrize("subject", list(scn.USERS))
def test_inbound(onboarded: dict, subject: str) -> None:
    """Inbound gate — a real request through AuthBridge as ``subject`` is allowed iff their role may
    reach some discovered agent scope (dev-user ✅, test-user ✅, devops-user ❌). The real OPA plugin
    decides; AuthBridge's ``jwt-validation`` builds ``input.identity`` (no hand-built input)."""
    assert uc1.inbound_decision(onboarded, subject) == uc1.expected_inbound_decision(subject), subject


@pytest.mark.parametrize("subject", list(scn.USERS))
@pytest.mark.parametrize("tool_bare", scn.TOOL_REQUEST_NAMES)
def test_outbound_all_deny(onboarded: dict, subject: str, tool_bare: str) -> None:
    """Outbound user gate denies every ``(subject, tool)`` — the gate is empty because no tool was
    onboarded. A real MCP ``tools/call`` for the bare tool through AuthBridge's forward proxy
    (token-exchange → OPA) is denied for every user/tool pair (real-plugin decision)."""
    assert uc1.outbound_decision(onboarded, subject, tool_bare) == "deny", f"{subject} / {tool_bare}"
