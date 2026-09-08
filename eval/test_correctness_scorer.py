"""Unit tests for ``correctness_scorer.py`` (spec: ``docs/specs/eval/
policy-eval-correctness-prb.md``).

Pure-logic, unmarked — runs in the default fast pass (``testpaths`` already includes ``eval/``).
No LLM, no Keycloak, no fixtures beyond plain dicts/sets.
"""

from __future__ import annotations

from eval.correctness_scorer import score_gate, score_scenario


def test_exact_match_scores_perfectly() -> None:
    granted = {("role-a", "scope-x"), ("role-a", "scope-y")}
    expected = {("role-a", "scope-x"), ("role-a", "scope-y")}

    score = score_gate("inbound", granted, denied=set(), expected=expected)

    assert score.true_positives == frozenset(expected)
    assert score.over_grants == frozenset()
    assert score.under_grants == frozenset()
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.denial_precision == 1.0
    assert score.over_grant_free


def test_pure_over_grant_fails_precision() -> None:
    granted = {("role-a", "scope-x"), ("role-a", "scope-z")}  # scope-z not expected
    expected = {("role-a", "scope-x")}

    score = score_gate("inbound", granted, denied=set(), expected=expected)

    assert score.true_positives == frozenset({("role-a", "scope-x")})
    assert score.over_grants == frozenset({("role-a", "scope-z")})
    assert score.under_grants == frozenset()
    assert score.precision == 0.5
    assert score.recall == 1.0
    assert not score.over_grant_free


def test_pure_under_grant_reduces_recall_but_stays_over_grant_free() -> None:
    granted = {("role-a", "scope-x")}
    expected = {("role-a", "scope-x"), ("role-a", "scope-y")}  # scope-y missing

    score = score_gate("inbound", granted, denied=set(), expected=expected)

    assert score.under_grants == frozenset({("role-a", "scope-y")})
    assert score.over_grants == frozenset()
    assert score.precision == 1.0
    assert score.recall == 0.5
    assert score.over_grant_free


def test_correct_denial_has_denial_precision_one() -> None:
    granted: set[tuple[str, str]] = set()
    denied = {("role-a", "scope-x")}  # scope-x correctly denied: not in expected
    expected: set[tuple[str, str]] = set()

    score = score_gate("outbound_target", granted, denied, expected)

    assert score.correctly_denied == frozenset({("role-a", "scope-x")})
    assert score.incorrectly_denied == frozenset()
    assert score.denial_precision == 1.0
    # A deny never gates — over_grant_free is about the granted/expected sets only.
    assert score.over_grant_free


def test_incorrect_denial_is_subset_of_under_grants_and_does_not_gate() -> None:
    granted: set[tuple[str, str]] = set()
    denied = {("role-a", "scope-x")}  # scope-x explicitly denied, but expected
    expected = {("role-a", "scope-x")}

    score = score_gate("outbound_target", granted, denied, expected)

    assert score.incorrectly_denied == frozenset({("role-a", "scope-x")})
    assert score.incorrectly_denied <= score.under_grants
    assert score.correctly_denied == frozenset()
    assert score.denial_precision == 0.0
    assert score.over_grant_free  # incorrect denial is still just an under-grant for gating


def test_empty_sets_are_vacuously_perfect() -> None:
    score = score_gate("inbound", granted=set(), denied=set(), expected=set())

    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.denial_precision == 1.0
    assert score.over_grant_free


def test_scenario_aggregates_across_gates() -> None:
    granted = {
        "inbound": {("role-a", "scope-in")},
        "outbound_subject": {("role-a", "scope-out"), ("role-a", "scope-extra")},
    }
    denied = {
        "outbound_target": {("agent-role", "scope-out")},
    }
    expected = {
        "inbound": {("role-a", "scope-in")},
        "outbound_subject": {("role-a", "scope-out")},
        "outbound_target": {("agent-role", "scope-out")},
    }

    scenario_score = score_scenario("demo", granted, denied, expected)

    assert set(scenario_score.gates) == {"inbound", "outbound_subject", "outbound_target"}
    # over-grant lives only in outbound_subject
    assert scenario_score.over_grants == {"outbound_subject": frozenset({("role-a", "scope-extra")})}
    assert not scenario_score.passed  # zero-tolerance: any gate with an over-grant fails
    # under-grant lives only in outbound_target (granted nothing there, expected one pair)
    assert scenario_score.under_grants == {"outbound_target": frozenset({("agent-role", "scope-out")})}
    # that same pair was also explicitly denied -> incorrectly_denied
    assert scenario_score.incorrectly_denied == {"outbound_target": frozenset({("agent-role", "scope-out")})}

    # Aggregate precision/recall across all gates' pairs unioned: TP={in, out} (2), FP={extra} (1),
    # FN={outbound_target's out} (1).
    assert scenario_score.precision == 2 / 3
    assert scenario_score.recall == 2 / 3
    assert scenario_score.denial_precision == 0.0  # the one denial made was incorrect


def test_scenario_passes_with_only_under_grants() -> None:
    granted = {"inbound": set()}
    denied: dict[str, set[tuple[str, str]]] = {}
    expected = {"inbound": {("role-a", "scope-in")}}

    scenario_score = score_scenario("demo", granted, denied, expected)

    assert scenario_score.passed
    assert scenario_score.recall == 0.0
    assert scenario_score.precision == 1.0


def test_scenario_with_no_gates_is_vacuously_passing() -> None:
    scenario_score = score_scenario("empty", granted={}, denied={}, expected={})

    assert scenario_score.gates == {}
    assert scenario_score.passed
    assert scenario_score.precision == 1.0
    assert scenario_score.recall == 1.0
    assert scenario_score.denial_precision == 1.0
