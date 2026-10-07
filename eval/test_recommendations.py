"""Tests for ``eval/recommendations.py`` (spec: ``docs/evaluation/eval-framework.md`` §9.1,
#2472). Two tiers, mirroring how the PRB's own structured-call seam is tested
(``test/unit/agent/policy_rules_builder/test_diagnostic.py``):

- Offline (untagged, runs in the default pass): the six pure ``EvidenceCase`` builders need no
  LLM at all; ``build_recommendations`` is exercised with ``_draft_patterns`` monkeypatched to a
  canned stub so the pattern-validation/fallback logic is tested without a network call; a
  dedicated test drives ``_draft_patterns`` itself with the LLM seam mocked to raise.
- Live-LLM (``@pytest.mark.llm``): one small test calling the real ``_draft_patterns`` against a
  live endpoint, skipping cleanly when unset.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from eval.recommendations import (
    EvidenceCase,
    Recommendation,
    _Pattern,
    build_recommendations,
    consistency_cases,
    invariance_cases,
    over_grant_cases,
    scale_mistake_cases,
    sensitivity_cases,
    under_grant_cases,
)
from test.system.launcher import require_env_or_skip

# =========================================================================== #
# over_grant_cases / under_grant_cases                                        #
# =========================================================================== #


class TestOverGrantCases:
    def test_no_evidence_returns_empty(self) -> None:
        assert over_grant_cases([]) == []
        assert over_grant_cases([("correctness_prb", "baseline", {})]) == []
        assert over_grant_cases([("correctness_prb", "baseline", {"over_grants": {}})]) == []

    def test_one_case_per_entry_with_correct_fields(self) -> None:
        entries = [
            ("correctness_prb", "baseline", {"over_grants": {"inbound": [("role-a", "scope-a")]}}),
            ("correctness_e2e", "wildcard_grant", {"over_grants": {"outbound": [("role-b", "scope-b")]}}),
        ]
        cases = over_grant_cases(entries)
        assert len(cases) == 2  # never pooled at this layer -- one EvidenceCase per entry
        first, second = cases
        assert first.case_id == "correctness_prb:baseline:over_grant"
        assert first.finding_type == "over_grant"
        assert first.fallback_key == "correctness_prb"
        assert "role-a" in first.evidence and "scope-a" in first.evidence
        assert second.case_id == "correctness_e2e:wildcard_grant:over_grant"
        assert second.fallback_key == "correctness_e2e"


class TestUnderGrantCases:
    def test_no_evidence_returns_empty(self) -> None:
        assert under_grant_cases([("correctness_prb", "baseline", {"under_grants": {}})]) == []
        assert (
            under_grant_cases([("correctness_prb", "baseline", {"under_grants": {}, "incorrectly_denied": {}})]) == []
        )

    def test_one_case_per_entry_with_correct_fields(self) -> None:
        entries = [("correctness_prb", "baseline", {"under_grants": {"inbound": [("role-a", "scope-a")]}})]
        [case] = under_grant_cases(entries)
        assert case.case_id == "correctness_prb:baseline:under_grant"
        assert case.finding_type == "under_grant"
        assert case.fallback_key == "correctness_prb"
        assert "role-a" in case.evidence and "scope-a" in case.evidence

    def test_incorrectly_denied_alone_still_produces_a_case(self) -> None:
        # The edge case: a pair simultaneously granted AND denied (e.g. a coarse scope split by
        # the auditor into one approved and one best-effort-rejected sub-decision) lands in
        # incorrectly_denied without ever appearing in under_grants -- must not be silently
        # dropped from the recommendations section.
        entries = [
            (
                "correctness_e2e",
                "agent_delegation",
                {"under_grants": {}, "incorrectly_denied": {"inbound": [("role-dock-worker", "agent-scope-x")]}},
            )
        ]
        [case] = under_grant_cases(entries)
        assert case.case_id == "correctness_e2e:agent_delegation:under_grant"
        assert case.finding_type == "under_grant"
        assert case.fallback_key == "correctness_e2e"
        assert "role-dock-worker" in case.evidence and "agent-scope-x" in case.evidence
        assert "incorrectly) denied" in case.evidence

    def test_both_present_combines_into_one_case_not_two(self) -> None:
        entries = [
            (
                "correctness_prb",
                "baseline",
                {
                    "under_grants": {"inbound": [("role-a", "scope-a")]},
                    "incorrectly_denied": {"outbound": [("role-b", "scope-b")]},
                },
            )
        ]
        cases = under_grant_cases(entries)
        assert len(cases) == 1
        assert "role-a" in cases[0].evidence and "role-b" in cases[0].evidence


# =========================================================================== #
# sensitivity_cases / invariance_cases                                        #
# =========================================================================== #


class TestSensitivityCases:
    def test_no_evidence_when_sensitive(self) -> None:
        entries = [("robustness_mechanical_sensitivity", "baseline", {"sensitive": True, "edit_type": "negation"})]
        assert sensitivity_cases(entries) == []

    def test_one_case_per_entry_with_edit_type_fallback_key(self) -> None:
        entries = [
            (
                "robustness_mechanical_sensitivity",
                "baseline",
                {
                    "sensitive": False,
                    "edit_type": "restriction_word",
                    "perturbation": "only testers may...",
                    "expected_grants": {"inbound": [("role-tester", "scope-x")]},
                    "actual_grants": {"inbound": [("role-dev", "scope-x")]},
                },
            )
        ]
        [case] = sensitivity_cases(entries)
        assert case.case_id == "robustness_mechanical_sensitivity:baseline:sensitivity"
        assert case.finding_type == "sensitivity"
        assert case.fallback_key == "restriction_word"
        assert "role-tester" in case.evidence and "role-dev" in case.evidence


class TestInvarianceCases:
    def test_no_evidence_when_invariant(self) -> None:
        entries = [("robustness_mechanical_invariance", "baseline", {"invariant": True})]
        assert invariance_cases(entries) == []

    def test_one_case_per_entry_with_suite_fallback_key(self) -> None:
        entries = [
            (
                "robustness_semantic_invariance",
                "wildcard_grant",
                {
                    "invariant": False,
                    "perturbation": "reworded sibling",
                    "expected_grants": {"inbound": [("role-a", "scope-a")]},
                    "actual_grants": {},
                },
            )
        ]
        [case] = invariance_cases(entries)
        assert case.case_id == "robustness_semantic_invariance:wildcard_grant:invariance"
        assert case.finding_type == "invariance"
        # No edit_type here (unlike sensitivity) -- falls back to the suite (tier) itself.
        assert case.fallback_key == "robustness_semantic_invariance"


# =========================================================================== #
# consistency_cases -- the cluster-vs-random classification boundary          #
# =========================================================================== #


class TestConsistencyCases:
    def test_no_cases_when_consistent(self) -> None:
        entries = [("baseline", {"inconsistent": False})]
        assert consistency_cases(entries, "no disagreements") == []

    def test_one_case_per_inconsistent_scenario_folds_in_classification(self) -> None:
        entries = [
            ("baseline", {"inconsistent": True, "mismatches": "gate=inbound run=0 vs run=1: ..."}),
            ("wildcard_grant", {"inconsistent": False}),
        ]
        [case] = consistency_cases(entries, "clusters on these scenario(s)")
        assert case.case_id == "consistency:baseline"
        assert case.finding_type == "consistency"
        assert case.fallback_key == "consistency"
        assert "clusters on these scenario(s)" in case.evidence
        assert "gate=inbound" in case.evidence

    def test_classification_boundary_at_exactly_half_vs_just_above(self) -> None:
        from eval.conftest import _classify_consistency_disagreements

        half = [("a", {"inconsistent": True}), ("b", {"inconsistent": False})]
        assert _classify_consistency_disagreements(half) == "clusters on these scenario(s)"

        just_above_half = [
            ("a", {"inconsistent": True}),
            ("b", {"inconsistent": True}),
            ("c", {"inconsistent": False}),
        ]
        assert _classify_consistency_disagreements(just_above_half) == "appears random/widespread"


# =========================================================================== #
# scale_mistake_cases -- remedy-menu text identical across both dimensions/    #
# both levels; fallback_key is always the suite itself (#2472 decision 1: no  #
# numeric threshold, any occurrence IS the finding)                           #
# =========================================================================== #


class TestScaleMistakeCases:
    def test_no_evidence_returns_empty(self) -> None:
        entries = [("scale_total_corpus_prb", {"over_grants": {}, "under_grants": {}, "incorrectly_denied": {}})]
        assert scale_mistake_cases(entries) == []

    @pytest.mark.parametrize(
        "suite",
        ["scale_total_corpus_prb", "scale_total_corpus_e2e", "scale_per_decision_prb", "scale_per_decision_e2e"],
    )
    def test_remedy_menu_identical_across_every_dimension_and_level(self, suite: str) -> None:
        entries = [(suite, {"over_grants": {"inbound": [("role-a", "scope-a")]}})]
        [case] = scale_mistake_cases(entries)
        assert case.finding_type == "scale_mistake"
        assert case.fallback_key == suite
        assert "context-window management" in case.remedy_menu
        assert "candidate-list pruning" in case.remedy_menu

    def test_any_single_pair_breakdown_is_sufficient(self) -> None:
        for props in (
            {"under_grants": {"inbound": [("role-a", "scope-a")]}},
            {"incorrectly_denied": {"inbound": [("role-a", "scope-a")]}},
        ):
            [case] = scale_mistake_cases([("scale_per_decision_prb", props)])
            assert case.case_id == "scale_per_decision_prb:scale_mistake"


# =========================================================================== #
# build_recommendations -- pattern validation + deterministic fallback        #
# =========================================================================== #


_OVER_GRANT_ENTRY = ("correctness_prb", "baseline", {"over_grants": {"inbound": [("role-a", "scope-a")]}})


class TestBuildRecommendations:
    def _call(self, over_grant=(), **overrides) -> list[Recommendation]:
        kwargs = dict(
            over_grant=list(over_grant),
            under_grant=[],
            sensitivity=[],
            invariance=[],
            consistency=[],
            consistency_classification="no consistency data",
            scale_mistake=[],
        )
        kwargs.update(overrides)
        return build_recommendations(**kwargs)

    def test_zero_cases_never_calls_draft_patterns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = []
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: calls.append(cases) or [])
        assert self._call() == []
        assert calls == []

    def test_pattern_case_ids_map_back_to_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _Pattern(
            heading="Over-interpreting 'only'",
            recommendation="Add a prompt constraint for restriction words.",
            case_ids=["correctness_prb:baseline:over_grant"],
        )
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        [rec] = self._call(over_grant=[_OVER_GRANT_ENTRY])
        assert rec.heading == "Over-interpreting 'only'"
        assert rec.body == "Add a prompt constraint for restriction words."
        assert len(rec.evidence) == 1
        assert "role-a" in rec.evidence[0] and "scope-a" in rec.evidence[0]

    def test_unknown_case_id_is_dropped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _Pattern(
            heading="pattern",
            recommendation="rec",
            case_ids=["correctness_prb:baseline:over_grant", "hallucinated:nonexistent:over_grant"],
        )
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        [rec] = self._call(over_grant=[_OVER_GRANT_ENTRY])
        assert len(rec.evidence) == 1

    def test_pattern_left_with_zero_valid_ids_is_omitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _Pattern(heading="pattern", recommendation="rec", case_ids=["hallucinated:nonexistent:over_grant"])
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        # Falls through to the deterministic fallback since no pattern survived validation.
        [rec] = self._call(over_grant=[_OVER_GRANT_ENTRY])
        assert "LLM pattern analysis unavailable" in rec.body

    def test_empty_draft_patterns_triggers_deterministic_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [])
        [rec] = self._call(over_grant=[_OVER_GRANT_ENTRY])
        assert "LLM pattern analysis unavailable" in rec.body
        assert "correctness_prb" in rec.heading
        assert len(rec.evidence) == 1


# =========================================================================== #
# _draft_patterns itself -- LLM failure returns [] rather than raising        #
# =========================================================================== #


class TestDraftPatternsLLMFailure:
    def test_llm_access_error_returns_empty_list_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aiac.agent.llm import LLMAccessError
        from eval.recommendations import _draft_patterns

        def _raise(*_args, **_kwargs):
            raise LLMAccessError("LLM endpoint unreachable after exhausting transport retries")

        monkeypatch.setattr("eval.recommendations.call_with_retry", _raise)
        monkeypatch.setattr("eval.recommendations.build_llm", lambda settings: MagicMock())
        cases = [
            EvidenceCase(
                case_id="x:y:over_grant",
                finding_type="over_grant",
                evidence="evidence",
                remedy_menu="menu",
                fallback_key="x",
            )
        ]
        assert _draft_patterns(cases) == []


# =========================================================================== #
# Live-LLM: the real batched call actually merges same-root-cause cases       #
# =========================================================================== #


@pytest.mark.llm
def test_draft_patterns_merges_same_root_cause_cases_live() -> None:
    """Two synthetic cases that obviously share one root cause (the same policy clause, two
    different scenarios) should be returned under one pattern's case_ids, not echoed 1:1 -- and
    every returned case_id must be one of the inputs (no hallucinated ids)."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    from eval.recommendations import _draft_patterns

    cases = [
        EvidenceCase(
            case_id="correctness_prb:scenario_one:over_grant",
            finding_type="over_grant",
            evidence=(
                "correctness_prb/scenario_one: over-granted pairs -> inbound: (role-tester, "
                "agent-scope-triager) -- the PRB granted read access to the issue tracker despite "
                "the policy text saying 'Only developers may read the issue tracker.'"
            ),
            remedy_menu="Identify the specific policy clause the PRB is over-interpreting.",
            fallback_key="correctness_prb",
        ),
        EvidenceCase(
            case_id="correctness_e2e:scenario_two:over_grant",
            finding_type="over_grant",
            evidence=(
                "correctness_e2e/scenario_two: over-granted pairs -> inbound: (role-tester, "
                "agent-scope-triager) -- same issue: the PRB granted read access to the issue "
                "tracker despite the policy text saying 'Only developers may read the issue "
                "tracker.'"
            ),
            remedy_menu="Identify the specific policy clause the PRB is over-interpreting.",
            fallback_key="correctness_e2e",
        ),
        EvidenceCase(
            case_id="consistency:unrelated_scenario",
            finding_type="consistency",
            evidence=(
                "consistency/unrelated_scenario (clusters on these scenario(s)): mismatches -> "
                "gate=outbound run=0 vs run=1: differing pairs=[('role-x', 'scope-y')]"
            ),
            remedy_menu="Note whether disagreements cluster or appear random.",
            fallback_key="consistency",
        ),
    ]
    patterns = _draft_patterns(cases)
    assert patterns, "expected at least one drafted pattern from a live LLM call"
    known_ids = {case.case_id for case in cases}
    all_covered_ids = [case_id for pattern in patterns for case_id in pattern.case_ids]
    assert all_covered_ids, "expected at least one case_id covered"
    for case_id in all_covered_ids:
        assert case_id in known_ids, f"hallucinated case_id: {case_id}"
