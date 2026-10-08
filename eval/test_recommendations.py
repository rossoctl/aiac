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
    _grant_diff,
    _Pattern,
    _truncate,
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
# _truncate / _grant_diff                                                     #
# =========================================================================== #


class TestTruncate:
    def test_short_text_is_unchanged(self) -> None:
        assert _truncate("short", limit=10) == "short"

    def test_long_text_is_cut_with_a_marker(self) -> None:
        result = _truncate("x" * 20, limit=10)
        assert result == "x" * 10 + "... (truncated)"

    def test_exactly_at_the_limit_is_unchanged(self) -> None:
        assert _truncate("x" * 10, limit=10) == "x" * 10


class TestGrantDiff:
    def test_identical_grants_show_no_difference(self) -> None:
        grants = {"inbound": [("role-a", "scope-a")]}
        assert _grant_diff(grants, grants) == "no difference"

    def test_lost_and_gained_are_both_reported(self) -> None:
        expected = {"inbound": [("role-tester", "scope-x")]}
        actual = {"inbound": [("role-dev", "scope-x")]}
        result = _grant_diff(expected, actual)
        assert "lost -> inbound: (role-tester, scope-x)" in result
        assert "gained -> inbound: (role-dev, scope-x)" in result

    def test_shared_pair_is_excluded_from_the_diff(self) -> None:
        expected = {"inbound": [("role-a", "scope-a"), ("role-shared", "scope-y")]}
        actual = {"inbound": [("role-b", "scope-a"), ("role-shared", "scope-y")]}
        result = _grant_diff(expected, actual)
        assert "role-shared" not in result

    def test_only_lost_no_gained(self) -> None:
        expected = {"inbound": [("role-a", "scope-a")]}
        result = _grant_diff(expected, {})
        assert result == "lost -> inbound: (role-a, scope-a)"


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

    def test_a_pair_in_both_dicts_is_not_restated_twice(self) -> None:
        """Confirmed as a real finding in PR review: incorrectly_denied is normally a SUBSET of
        under_grants, so restating the exact same pair under both labels doubles the evidence text
        and the tokens sent to the LLM for no new information."""
        entries = [
            (
                "correctness_prb",
                "baseline",
                {
                    "under_grants": {"inbound": [("role-a", "scope-a")]},
                    "incorrectly_denied": {"inbound": [("role-a", "scope-a")]},
                },
            )
        ]
        [case] = under_grant_cases(entries)
        assert case.evidence.count("role-a") == 1
        assert "also explicitly" not in case.evidence


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
        assert "lost -> inbound: (role-tester, scope-x)" in case.evidence
        assert "gained -> inbound: (role-dev, scope-x)" in case.evidence

    def test_long_perturbation_is_truncated_as_a_well_formed_quoted_string(self) -> None:
        """Confirmed as a real finding in PR review: truncating an already-repr'd string (quotes
        and escapes already applied) can cut mid-escape and drops the closing quote. Truncating
        the raw text FIRST, then repr-ing the (now short) result, always produces a complete,
        well-formed quoted string with the marker inside it."""
        entries = [
            (
                "robustness_mechanical_sensitivity",
                "baseline",
                {"sensitive": False, "perturbation": "x" * 600, "expected_grants": {}, "actual_grants": {}},
            )
        ]
        [case] = sensitivity_cases(entries)
        assert "... (truncated)'" in case.evidence  # closing quote survives, right after the marker
        assert case.evidence.count("x") == 500

    def test_evidence_shows_only_the_difference_not_the_full_lists(self) -> None:
        """Confirmed as a real finding in PR review: independently truncating two full
        expected/actual lists at the same pair-count limit can leave both showing an identical
        prefix with no way to tell which pair changed. Diffing first means a pair both lists
        share (unchanged) never appears in the evidence at all."""
        entries = [
            (
                "robustness_mechanical_sensitivity",
                "baseline",
                {
                    "sensitive": False,
                    "expected_grants": {"inbound": [("role-tester", "scope-x"), ("role-shared", "scope-y")]},
                    "actual_grants": {"inbound": [("role-dev", "scope-x"), ("role-shared", "scope-y")]},
                },
            )
        ]
        [case] = sensitivity_cases(entries)
        assert "role-shared" not in case.evidence  # unchanged pair -- not part of the diff
        assert "lost -> inbound: (role-tester, scope-x)" in case.evidence
        assert "gained -> inbound: (role-dev, scope-x)" in case.evidence


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
        """Classified against the full expected corpus (_EXPECTED_CONSISTENCY_SCENARIO_COUNT),
        not the count of entries passed in -- both cases below score the full corpus."""
        from eval.conftest import _EXPECTED_CONSISTENCY_SCENARIO_COUNT, _classify_consistency_disagreements

        n = _EXPECTED_CONSISTENCY_SCENARIO_COUNT
        half = [(f"s{i}", {"inconsistent": i < n // 2}) for i in range(n)]
        assert _classify_consistency_disagreements(half) == "clusters on these scenario(s)"

        just_above_half = [(f"s{i}", {"inconsistent": i < n // 2 + 1}) for i in range(n)]
        assert _classify_consistency_disagreements(just_above_half) == "appears random/widespread"

    def test_fewer_than_expected_scenarios_is_not_conclusive(self) -> None:
        """Confirmed as a real finding in PR review: a `-k`-filtered run that scores too few
        scenarios must not force a cluster-vs-random verdict against ITS OWN small count -- e.g. a
        single inconsistent scenario out of 1 scored is 100% by that measure, which previously read
        as "appears random/widespread" when it is, by construction, the single-scenario clustering
        case."""
        from eval.conftest import _EXPECTED_CONSISTENCY_SCENARIO_COUNT, _classify_consistency_disagreements

        single_inconsistent = [("baseline", {"inconsistent": True})]
        result = _classify_consistency_disagreements(single_inconsistent)
        assert result == f"not conclusive (1/{_EXPECTED_CONSISTENCY_SCENARIO_COUNT} scenarios scored this run)"

    def test_more_than_expected_scenarios_is_also_not_conclusive(self) -> None:
        """Mirrors _write_trend_log's own "regression" gate (`== _EXPECTED_CONSISTENCY_SCENARIO_
        COUNT`, not `<=`) -- a corpus that grew past the constant without a bump must not silently
        compute a fraction above 1.0 here either."""
        from eval.conftest import _EXPECTED_CONSISTENCY_SCENARIO_COUNT, _classify_consistency_disagreements

        grown = [(f"s{i}", {"inconsistent": True}) for i in range(_EXPECTED_CONSISTENCY_SCENARIO_COUNT + 1)]
        result = _classify_consistency_disagreements(grown)
        assert result.startswith("not conclusive")


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

    def test_a_pair_in_both_under_grants_and_incorrectly_denied_is_not_restated_twice(self) -> None:
        """Confirmed as a real finding in PR review: this builder still restated the same pairs
        under both labels after under_grant_cases was fixed to dedupe them the same way. The
        "also incorrectly denied" clause must be omitted entirely once nothing's left, not shown
        as a stray "-> none" (a second finding from the same review round)."""
        props = {
            "under_grants": {"inbound": [("role-a", "scope-a")]},
            "incorrectly_denied": {"inbound": [("role-a", "scope-a")]},
        }
        [case] = scale_mistake_cases([("scale_per_decision_prb", props)])
        assert case.evidence.count("role-a") == 1
        assert "incorrectly denied" not in case.evidence


# =========================================================================== #
# build_recommendations -- pattern validation + deterministic fallback        #
# =========================================================================== #


_OVER_GRANT_ENTRY = ("correctness_prb", "baseline", {"over_grants": {"inbound": [("role-a", "scope-a")]}})


class TestBuildRecommendations:
    def _call(self, correctness=(), **overrides) -> list[Recommendation]:
        kwargs = dict(
            correctness=list(correctness),
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
        [rec] = self._call(correctness=[_OVER_GRANT_ENTRY])
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
        [rec] = self._call(correctness=[_OVER_GRANT_ENTRY])
        assert len(rec.evidence) == 1

    def test_a_case_id_repeated_in_one_pattern_is_not_restated_twice(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _Pattern(
            heading="pattern",
            recommendation="rec",
            case_ids=["correctness_prb:baseline:over_grant", "correctness_prb:baseline:over_grant"],
        )
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        [rec] = self._call(correctness=[_OVER_GRANT_ENTRY])
        assert len(rec.evidence) == 1

    def test_pattern_left_with_zero_valid_ids_is_omitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _Pattern(heading="pattern", recommendation="rec", case_ids=["hallucinated:nonexistent:over_grant"])
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        # Falls through to the deterministic fallback since no pattern survived validation.
        [rec] = self._call(correctness=[_OVER_GRANT_ENTRY])
        assert "LLM pattern analysis unavailable" in rec.body

    def test_empty_draft_patterns_triggers_deterministic_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [])
        [rec] = self._call(correctness=[_OVER_GRANT_ENTRY])
        assert "LLM pattern analysis unavailable" in rec.body
        assert "correctness_prb" in rec.heading
        assert len(rec.evidence) == 1

    def test_case_the_llm_omits_still_surfaces_via_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A pattern covering only SOME cases must not silently drop the rest -- confirmed as a
        real finding in PR review: the module's "never silently blank" guarantee has to hold per
        case, not just when the whole LLM call fails."""
        other_entry = (
            "correctness_e2e",
            "wildcard_grant",
            {"over_grants": {"outbound_target": [("role-b", "scope-b")]}},
        )
        stub = _Pattern(
            heading="pattern covering only one case",
            recommendation="rec",
            case_ids=["correctness_prb:baseline:over_grant"],  # omits the e2e case entirely
        )
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        recs = self._call(correctness=[_OVER_GRANT_ENTRY, other_entry])
        assert len(recs) == 2
        drafted = next(r for r in recs if r.heading == "pattern covering only one case")
        assert len(drafted.evidence) == 1 and "role-a" in drafted.evidence[0]
        fallback = next(r for r in recs if r is not drafted)
        # Confirmed as a real finding in PR review: "unavailable" is misleading here -- the LLM
        # call clearly worked (it drafted the OTHER recommendation above), it just didn't cover
        # this case.
        assert "Not covered by the LLM pattern analysis" in fallback.body
        assert "LLM pattern analysis unavailable" not in fallback.body
        assert "role-b" in fallback.evidence[0]

    def test_hallucinated_id_in_an_otherwise_valid_pattern_still_surfaces_the_other_case(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One pattern naming a real case plus a hallucinated one, alongside a second real case the
        pattern never mentions at all -- both real cases must end up covered (one drafted, one
        fallback), never just the one the pattern happened to name."""
        other_entry = (
            "correctness_e2e",
            "wildcard_grant",
            {"over_grants": {"outbound_target": [("role-b", "scope-b")]}},
        )
        stub = _Pattern(
            heading="pattern",
            recommendation="rec",
            case_ids=["correctness_prb:baseline:over_grant", "hallucinated:nonexistent:over_grant"],
        )
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [stub])
        recs = self._call(correctness=[_OVER_GRANT_ENTRY, other_entry])
        assert len(recs) == 2
        assert any("Not covered by the LLM pattern analysis" in r.body and "role-b" in r.evidence[0] for r in recs)

    def test_case_claimed_by_an_earlier_pattern_is_not_claimed_by_a_later_one_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Confirmed as a real finding in PR review: deduping only WITHIN one pattern still let
        the same case_id appear in two different patterns, double-counting that case's failure
        under two separate recommendations."""
        first = _Pattern(heading="first", recommendation="rec1", case_ids=["correctness_prb:baseline:over_grant"])
        second = _Pattern(heading="second", recommendation="rec2", case_ids=["correctness_prb:baseline:over_grant"])
        monkeypatch.setattr("eval.recommendations._draft_patterns", lambda cases: [first, second])
        [rec] = self._call(correctness=[_OVER_GRANT_ENTRY])
        assert rec.heading == "first"


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

    def test_structured_output_none_returns_empty_list_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``with_structured_output`` can return ``None`` instead of raising when the model's
        response can't be coerced into the schema -- confirmed as a real finding in PR review."""
        from eval.recommendations import _draft_patterns

        monkeypatch.setattr("eval.recommendations.call_with_retry", lambda *a, **k: None)
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


class TestDraftPatternsLLMDisabledFlag:
    """Confirmed as a real finding in PR review: a developer rerunning one failing scenario with
    ``-k`` had no way to skip the blocking, retried LLM call pytest_sessionfinish makes whenever
    at least one case failed."""

    def test_flag_unset_still_calls_the_llm(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from eval.recommendations import _draft_patterns

        monkeypatch.delenv("EVAL_RECOMMENDATIONS_LLM", raising=False)
        calls = []
        monkeypatch.setattr("eval.recommendations.call_with_retry", lambda *a, **k: calls.append(1) or None)
        monkeypatch.setattr("eval.recommendations.build_llm", lambda settings: MagicMock())
        cases = [
            EvidenceCase(
                case_id="x:y:over_grant", finding_type="over_grant", evidence="e", remedy_menu="m", fallback_key="x"
            )
        ]
        _draft_patterns(cases)
        assert calls == [1]

    @pytest.mark.parametrize("value", ["0", "false", "False", "no", "NO"])
    def test_falsy_flag_skips_the_call_entirely(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        from eval.recommendations import _draft_patterns

        monkeypatch.setenv("EVAL_RECOMMENDATIONS_LLM", value)
        calls = []
        monkeypatch.setattr("eval.recommendations.load_llm_settings", lambda: calls.append(1))
        cases = [
            EvidenceCase(
                case_id="x:y:over_grant", finding_type="over_grant", evidence="e", remedy_menu="m", fallback_key="x"
            )
        ]
        assert _draft_patterns(cases) == []
        assert calls == []  # not even settings were loaded -- no attempt made at all


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
