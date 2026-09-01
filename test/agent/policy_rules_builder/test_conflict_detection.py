"""Unit tests for the pure, deterministic structural conflict detector (#2502).

``detect_conflicts`` is a pure ``(role.id, scope.id)`` allow∩deny set-intersection over the
assembled ``list[PolicyRule]`` — **no LLM**. Per ADR 0001 it surfaces every overlap as a
``Conflict`` and never reconciles. These tests pin: clean → NO_CONFLICT, overlap → one DIRECT
scope-focal ``Conflict`` (real ids, no quotes), order-independence (keyed on ids), id-vs-name
discrimination, and the empty case. They are deterministic (NOT ``integration``/``llm``).
"""

from aiac.agent.policy_rules_builder.conflict_detection import (
    PolicyConflictError,
    detect_conflicts,
)
from aiac.agent.policy_rules_builder.diagnostic_models import (
    ConflictKind,
    ConflictStatus,
    FocalType,
)
from aiac.idp.configuration.models import Role, Scope
from aiac.policy.model.models import PolicyRule, RuleEffect

_TESTER = Role(id="r-tester", name="tester", composite=False)
_DEV = Role(id="r-dev", name="developer", composite=False)
_ISSUES = Scope(id="s-iss", name="issues")
_SOURCE = Scope(id="s-src", name="source")


def _allow(role: Role, scope: Scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)


def _deny(role: Role, scope: Scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)


def test_clean_ruleset_has_no_conflict():
    # Distinct (role, scope) pairs across allow and deny -> no overlap -> NO_CONFLICT.
    report = detect_conflicts([_allow(_DEV, _ISSUES), _deny(_TESTER, _SOURCE)])
    assert report.conflicts == []
    assert report.status is ConflictStatus.NO_CONFLICT


def test_empty_ruleset_reports_no_conflicts():
    report = detect_conflicts([])
    assert report.conflicts == []
    # Nothing to grant/prohibit means nothing collides; the raise decision reads ``conflicts``.


def test_direct_overlap_is_surfaced_as_scope_focal_conflict():
    report = detect_conflicts([_allow(_TESTER, _ISSUES), _deny(_TESTER, _ISSUES)])

    assert report.status is ConflictStatus.CONFLICTS_FOUND
    assert len(report.conflicts) == 1
    c = report.conflicts[0]
    # Real ids from the colliding rules, classified DIRECT, focal anchored on the SCOPE side (Q16).
    assert (c.role.id, c.role.name) == ("r-tester", "tester")
    assert (c.scope.id, c.scope.name) == ("s-iss", "issues")
    assert c.focal.type is FocalType.SCOPE
    assert (c.focal.id, c.focal.name) == ("s-iss", "issues")
    assert c.kind is ConflictKind.DIRECT
    # Structural form for this ticket: no quotes, unverified (enrichment is #2503).
    assert c.granting_quotes == [] and c.prohibiting_quotes == []
    assert c.quotes_verified is False
    assert "tester" in c.explanation and "issues" in c.explanation


def test_detection_is_order_independent():
    # Same rules, opposite orders (mirrors tool-first vs agent-first assembly) -> identical result.
    rules = [_allow(_TESTER, _ISSUES), _deny(_TESTER, _ISSUES), _allow(_DEV, _SOURCE)]
    forward = detect_conflicts(rules)
    reverse = detect_conflicts(list(reversed(rules)))
    key = lambda rep: sorted((c.role.id, c.scope.id) for c in rep.conflicts)
    assert key(forward) == key(reverse) == [("r-tester", "s-iss")]


def test_overlap_keyed_on_ids_not_names():
    # Same name, different ids => NOT the same pair => no conflict (id-keyed, never name-keyed).
    other_tester = Role(id="r-tester-2", name="tester", composite=False)
    report = detect_conflicts([_allow(_TESTER, _ISSUES), _deny(other_tester, _ISSUES)])
    assert report.conflicts == []
    assert report.status is ConflictStatus.NO_CONFLICT


def test_multiple_conflicts_each_surfaced():
    report = detect_conflicts(
        [
            _allow(_TESTER, _ISSUES),
            _deny(_TESTER, _ISSUES),
            _allow(_DEV, _SOURCE),
            _deny(_DEV, _SOURCE),
        ]
    )
    assert report.status is ConflictStatus.CONFLICTS_FOUND
    assert sorted((c.role.id, c.scope.id) for c in report.conflicts) == [
        ("r-dev", "s-src"),
        ("r-tester", "s-iss"),
    ]


def test_error_carries_report():
    report = detect_conflicts([_allow(_TESTER, _ISSUES), _deny(_TESTER, _ISSUES)])
    err = PolicyConflictError(report)
    assert err.report is report
    assert "tester" in str(err) and "issues" in str(err)
