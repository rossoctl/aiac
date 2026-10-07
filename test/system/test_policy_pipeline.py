"""End-to-end policy-pipeline integration test — the **enforced** decision is the artifact under test.

Umbrella full-matrix e2e for the fixed ``github-agent`` scenario (spec:
``docs/testing/policy-pipeline.md``; live loop shape: ``k8s/opa-kind-runbook.md``). A
single session fixture drives the whole identity→policy→**enforcement** pipeline with nothing mocked
or dumped: it onboards **both** the ``github-agent`` and the ``github-tool`` through the real
in-cluster UC-1 Controller by **deploying** them (the event-driven trigger; onboarding upserts one
``AuthorizationPolicy`` CR per onboarded service — the agent's and the tool's, D20), enables the
outbound token-exchange leg, waits for ``bundle-service`` + the AuthBridge OPA sidecars to
recompose and reload the bundle, then each test drives a **real HTTP request through AuthBridge** and
asserts the **real OPA plugin's** allow/deny against the scenario's role→access truth table
(``scenario_uc1.py``). A wrong LLM/PCE mapping fails the exact ``subject[ / tool]`` cell.

The evaluator is the **deployed plugin**, not a standalone OPA-CLI run over dumped ``.rego``: there is
no ``.rego`` dump and no ``opa`` binary here anymore (handoff 08). Both gates are exercised through AuthBridge's own parsers
— ``jwt-validation`` builds ``input.identity`` for the inbound gate; ``token-exchange`` + ``mcp-parser``
build the outbound ``input.identity`` + ``input.mcp.params.name`` (the **bare** tool name) — so the
test never hand-builds an input document.

**The enforcement side.** The run uses the live side (``AIAC_ENFORCEMENT_SIDE`` in the
``aiac-agent-config`` ConfigMap, default ``target-side``). Under target side the agent's outbound is a
pass-through (D24) and github-tool's own inbound OPA decides each tool call; under agent side the
agent's outbound OPA decides. The verdict tables are the same; only the enforcement-point node
(``test_deny_comes_from_enforcement_point``) depends on the side.

Where this sits vs. the UC-1 ladder: rungs 1–3 (``test_uc1_onboard_*``) isolate onboarding-order
properties; this module is the **full happy-path matrix + negative controls** over the fully onboarded
stack. It shares the harness's live stack (the ``rossoctl`` realm + the deployed ``team1`` workloads)
rather than a throwaway realm — there is exactly one deployed pipeline to enforce against — so the
former two-policy-variant equivalence check (explicit vs. abstract) is deferred to the two-policy rung
``testing/5.4.4`` (only one ``policy.md`` is mounted on the live stack; see ``scenario_uc1`` docstring).

Run (needs a live rossoctl/Kind cluster with the AuthBridge OPA pipeline wired in — see
``k8s/opa-kind-runbook.md`` / ``k8s/opa-kind-enable.sh`` — the demo workloads deployed +
registered into ``AIAC_TEST_REALM``, a real LLM in-pod, and ``.env`` sourced):

    .venv/bin/pytest test/system/test_policy_pipeline.py -m system -v

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

# The inbound + outbound oracles are the shared, tool-onboarded oracle in ``uc1_onboard`` (the full
# stack is onboarded here). Outbound decisions are keyed on the **bare** runtime tool names AuthBridge
# sends (``source-read``), matching what the live plugin compares against. The fixture-independent
# grant-set oracles that pin the intended matrix live at the unit level in
# ``test/unit/agent/uc/onboarding/test_uc1_grant_set_oracles.py``.


# ======================================================================================
# Session fixture — the one-time full-stack onboarding + bundle convergence
# ======================================================================================


@pytest.fixture(scope="session")
def pipeline() -> dict:
    """Onboard the **full** stack (agent + tool) via the shared harness, enable the outbound leg, and
    wait for the live pipeline to converge; yield the live probe context (``admin`` handle,
    ``agent_pod``, Keycloak URL/realm, ``tool_onboarded=True``). Keycloak cleanup + CR delete run
    before and after. Right after each workload converges, the harness checks that its client links
    the subject scope ``aiac-username-sub`` as a default scope (``require_subject_scope``, D31), so the
    exchanged token that github-tool's inbound reads has ``sub`` = the username; a missing link fails
    the fixture. Skips cleanly if the pipeline is not wired or the env is unset."""
    with uc1.onboarded_stack([scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD]) as ctx:
        yield ctx


# ======================================================================================
# Live tests — the real OPA plugin's decisions over the full matrix
# ======================================================================================


@pytest.mark.parametrize("subject", list(scn.USERS))
def test_inbound(pipeline: dict, subject: str) -> None:
    """The enforced inbound gate — a real request through AuthBridge as ``subject`` — allows a user
    iff their role may reach some agent scope. The real OPA plugin decides; ``jwt-validation`` builds
    ``input.identity`` (no hand-built input)."""
    assert uc1.inbound_decision(pipeline, subject) == uc1.expected_inbound_decision(subject), subject


@pytest.mark.parametrize("subject", list(scn.USERS))
@pytest.mark.parametrize("tool_bare", scn.TOOL_REQUEST_NAMES)
def test_outbound(pipeline: dict, subject: str, tool_bare: str) -> None:
    """The enforced tool check — a real MCP ``tools/call`` for the **bare** tool through AuthBridge's
    forward proxy (token-exchange → the tool check) — allows a subject's call iff both the subject and
    some agent role are entitled to that tool's scope. ``mcp-parser`` surfaces
    ``input.mcp.params.name`` (no hand-built input). A denial is github-tool's inbound HTTP 403 under
    target side, or the agent's outbound JSON-RPC error frame under agent side; the harness classifies
    both."""
    assert uc1.outbound_decision(pipeline, subject, tool_bare) == uc1.expected_outbound_decision(subject, tool_bare), (
        f"{subject} / {tool_bare}"
    )


# ======================================================================================
# Negative controls — real requests that must be denied by the real plugin
# ======================================================================================


def test_outbound_unknown_tool_denied(pipeline: dict) -> None:
    """An otherwise-allowed subject (dev-user) invoking a tool name that is in **no** allowed scope is
    denied — the tool check (under target side, github-tool's inbound gate) matches
    ``input.mcp.params.name`` exactly, so an unknown tool falls through to deny-by-default (not an
    accidental allow)."""
    assert uc1.outbound_decision(pipeline, "dev-user", "nonexistent-tool") == "deny"


def test_outbound_bogus_tool_shape_denied(pipeline: dict) -> None:
    """A bogus, destructive-sounding tool name matching no discovered scope is denied — guards against
    an over-broad match letting an unrecognized operation through."""
    assert uc1.outbound_decision(pipeline, "dev-user", "delete_everything") == "deny"


# ======================================================================================
# Enforcement point — where the deny comes from, by the live enforcement side
# ======================================================================================


def test_deny_comes_from_enforcement_point(pipeline: dict) -> None:
    """The raw response of an ungranted call (``test-user`` × ``source-read``) shows that the deny comes
    from the enforcement point of the live side (``deny_origin``). Under target side it comes from
    github-tool's inbound (HTTP 403, relayed by the agent's pass-through outbound), so the agent's
    outbound let the call through: the tool check moved from the agent's outbound to the tool's inbound.
    Under agent side it comes from the agent's outbound (a JSON-RPC error frame at HTTP 200)."""
    probe = uc1.outbound_deny_probe(pipeline, "test-user", "source-read")
    want = uc1.SIDE_ENFORCEMENT_POINT[pipeline["side"]]
    assert probe["decision"] == "deny" and probe["origin"] == want, (
        f"{pipeline['side']}: test-user / source-read decision={probe['decision']!r} origin={probe['origin']!r} "
        f"(want 'deny' from {want!r}); HTTP {probe['code']}, body={probe['body'][:300]!r}"
    )
