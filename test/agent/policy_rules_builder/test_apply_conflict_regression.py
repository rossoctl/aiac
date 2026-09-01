"""Apply-conflict guards: two disjoint mechanisms, both leaving persisted state untouched.

Deterministic (NOT ``integration`` / ``llm``) so it runs under ``-m "not integration"``. This
file pins BOTH grant/deny mechanisms and proves each one raises **before** the PCE, so a policy
problem never mutates persisted state:

  A. **Intra-pass ``PolicyContradictionError``** (the LLM auditor, ``graph.py``) — a self-
     contradicting single pass fails **closed** (raises, withholds its whole rule set). Kept
     valid unchanged: it is a *separate* mechanism from the structural detector (#2502), and the
     existing route handler still maps it to HTTP 422 without reaching the PCE.
  B. **Cross-pass structural ``PolicyConflictError``** (#2502) — after ``ServicePolicyBuilder.build``
     assembles every pass's rules, the pure ``detect_conflicts`` allow∩deny intersection surfaces
     a ``(role, scope)`` that is both granted and prohibited and **raises inside the build**,
     before the Orchestrator/Controller reach ``compute_and_apply`` (atomic-by-construction). This
     is the seed repurposed from the former apply-vs-diagnostic guard: its old premise (the #154
     read-only diagnostic doesn't touch ``/apply``) is moot after ``/policy/check`` was retired
     (#2500); it now guards the inline structural raise instead.

Both are proved with the apply seam (``compute_and_apply`` / the PCE) patched and asserted
**never called** on a conflict — the atomic proof — and the LLM/cluster stubbed out.
"""

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from aiac.agent.controller.routes import app
from aiac.agent.policy_rules_builder.conflict_detection import PolicyConflictError
from aiac.agent.policy_rules_builder.diagnostic_models import ConflictStatus, FocalType
from aiac.agent.policy_rules_builder.graph import (
    AuditVerdict,
    Contradiction,
    PolicyContradictionError,
    RoleSelection,
    build_role_rules,
)
from aiac.agent.uc.onboarding.policy_builder.builder import ServicePolicyBuilder
from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.agent.shared.focal_entities import FocalEntitySet
from aiac.policy.model.models import PolicyRule, RuleEffect

client = TestClient(app)
# Server-side exceptions with no route handler surface as 500 rather than propagating, so the
# atomic proof can assert on the PCE seam regardless of how #2503 later wires the 422 body.
tolerant_client = TestClient(app, raise_server_exceptions=False)

_BUILDER = "aiac.agent.uc.onboarding.policy_builder.builder"

_TESTER = Role(id="r-tester", name="tester", composite=False, kind=RoleKind.USER)
_ISSUES = Scope(id="s-iss", name="issues")


def _focal_own_scope() -> FocalEntitySet:
    """A minimal focal set for a Tool onboarding: one own scope, one kind=User candidate role,
    no own roles / other scopes — enough to drive the scope-focal grant + Door B deny passes."""
    return FocalEntitySet(
        own_scopes=[_ISSUES],
        own_roles=[],
        candidate_roles=[_TESTER],
        other_scopes=[],
        service_type=ServiceType.TOOL,
    )


class _Source:
    """Stub PolicySource whose ``fetch()`` returns a fixed policy string (mirrors ``test_graph.py``)."""

    def __init__(self, text: str = "POLICY"):
        self.text = text

    def fetch(self) -> str:
        return self.text


def test_live_build_role_rules_still_raises_policy_contradiction():
    # A genuine grant/deny overlap on the same coarse candidate: the proposer lists `issues` in BOTH
    # its grant and prohibit lists; the auditor adjudicates it GENUINE. The live builder must RAISE
    # (fail-closed) -- the diagnostic's record-not-raise fork must not have leaked into this path.
    role = Role(id="r-dev", name="developer", composite=False)
    issues = Scope(id="s-iss", name="issues")

    with ExitStack() as stack:
        stack.enter_context(
            patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source())
        )
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["issues"],
                        denied_scope_names=["issues"],
                        grant_is_exclusive=False,
                        reasoning="may read issues but must not modify them",
                    ),
                    AuditVerdict(
                        approved=False,
                        contradictions=[
                            Contradiction(
                                candidate_name="issues",
                                description="coarse-scope granularity mismatch: issues covers read and write",
                            )
                        ],
                    ),
                ],
            )
        )
        with pytest.raises(PolicyContradictionError) as exc:
            build_role_rules(role, [issues])

    # The raise carries the focal identity and the genuine contradiction(s) -- no rule set comes back.
    assert role.name in exc.value.focal
    assert [c.candidate_name for c in exc.value.contradictions] == ["issues"]


def test_apply_service_maps_policy_contradiction_to_422_and_skips_pce():
    # The Controller maps a PolicyContradictionError raised inside the onboarding handler to HTTP 422
    # (a policy finding, not a 500), and the PCE is never reached. onboard_service is patched to raise
    # directly so the route mapping is exercised without a cluster or the LLM.
    with (
        patch(
            "aiac.agent.controller.routes.onboard_service",
            side_effect=PolicyContradictionError("focal-svc", []),
        ),
        patch("aiac.agent.controller.routes.compute_and_apply") as pce,
    ):
        resp = client.post("/apply/service/svc-conflict")

    assert resp.status_code == 422
    pce.assert_not_called()


# --- Mechanism B: cross-pass structural PolicyConflictError (#2502) --------------------------


def test_build_raises_structural_conflict_from_assembled_passes():
    # The scope-focal pass grants (tester, issues) and the Door B deny pass prohibits the SAME
    # (tester, issues): the assembled list carries both an Allow and a Deny on one pair. build()
    # must run the inline detector and RAISE PolicyConflictError — never reconcile (ADR 0001).
    with (
        patch(f"{_BUILDER}._config", return_value=MagicMock()),
        patch(f"{_BUILDER}.resolve_focal_entities", return_value=_focal_own_scope()),
        patch(
            f"{_BUILDER}.build_scope_rules",
            return_value=[PolicyRule(role=_TESTER, scope=_ISSUES, effect=RuleEffect.ALLOW)],
        ),
        patch(
            f"{_BUILDER}.build_role_denies",
            return_value=[PolicyRule(role=_TESTER, scope=_ISSUES, effect=RuleEffect.DENY)],
        ),
    ):
        with pytest.raises(PolicyConflictError) as exc:
            ServicePolicyBuilder.build("svc-tool", ServiceType.TOOL)

    report = exc.value.report
    assert report.status is ConflictStatus.CONFLICTS_FOUND
    assert len(report.conflicts) == 1
    c = report.conflicts[0]
    assert (c.role.id, c.scope.id) == ("r-tester", "s-iss")
    assert c.focal.type is FocalType.SCOPE
    assert c.quotes_verified is False


def _drive_apply_with_passes(scope_rules, deny_rules) -> MagicMock:
    """Drive ``POST /apply/service/{id}`` through the REAL onboarding sequence (provision graph
    stubbed to a Tool, the two PRB passes stubbed to the given rule lists, LLM/cluster untouched)
    and return the patched ``compute_and_apply`` mock so the caller can assert on the PCE seam."""
    provision = MagicMock()
    provision.invoke.return_value = {"service_type": ServiceType.TOOL}
    with (
        patch(
            "aiac.agent.uc.onboarding.orchestrator.build_provision_graph", return_value=provision
        ),
        patch(f"{_BUILDER}._config", return_value=MagicMock()),
        patch(f"{_BUILDER}.resolve_focal_entities", return_value=_focal_own_scope()),
        patch(f"{_BUILDER}.build_scope_rules", return_value=scope_rules),
        patch(f"{_BUILDER}.build_role_denies", return_value=deny_rules),
        patch("aiac.agent.controller.routes.compute_and_apply") as pce,
    ):
        tolerant_client.post("/apply/service/svc-tool")
    return pce


def test_conflict_raises_before_compute_and_apply_is_atomic():
    # ATOMIC PROOF: a conflicting build (Allow + Deny on the same pair) short-circuits inside
    # build() — the PCE (the persistence seam) is provably NEVER reached, so a conflict leaves
    # persisted state untouched. This exercises the real detect_conflicts, not a patched raise.
    pce = _drive_apply_with_passes(
        scope_rules=[PolicyRule(role=_TESTER, scope=_ISSUES, effect=RuleEffect.ALLOW)],
        deny_rules=[PolicyRule(role=_TESTER, scope=_ISSUES, effect=RuleEffect.DENY)],
    )
    pce.assert_not_called()


def test_clean_build_reaches_compute_and_apply():
    # Control: the SAME path with no allow∩deny overlap (Door B contributes no deny) is clean —
    # the build returns and the PCE IS reached. Proves the raise is conditional on a real conflict
    # and that clean policies still apply.
    pce = _drive_apply_with_passes(
        scope_rules=[PolicyRule(role=_TESTER, scope=_ISSUES, effect=RuleEffect.ALLOW)],
        deny_rules=[],
    )
    pce.assert_called_once()
