"""Unit tests for ``eval.conftest``'s own pure-logic helpers (spec:
``docs/evaluation/policy-eval-scale.md``, #2469).

``eval/conftest.py`` is a pytest plugin module, not something this repo otherwise unit-tests
directly -- but ``_scale_run_matches_fixed_100`` is pure logic over ``os.environ`` with real
per-suite branching worth protecting on its own. Unmarked, runs in the default fast pass.
"""

from __future__ import annotations

import pytest

from eval.conftest import (
    _classify_nodeid,
    _render_field,
    _sanitize_recommendation_heading,
    _scale_run_matches_fixed_100,
    _scenario_name_from_nodeid,
)


@pytest.fixture(autouse=True)
def _clear_scale_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "SCALE_TOTAL_CORPUS_SIZE",
        "SCALE_TOTAL_CORPUS_ROLES",
        "SCALE_PER_DECISION_CANDIDATES",
        "SCALE_SEED",
        "SCALE_CONCURRENCY",
    ):
        monkeypatch.delenv(var, raising=False)


class TestScaleRunMatchesFixed100:
    def test_true_for_every_suite_with_no_overrides(self) -> None:
        for suite in (
            "scale_total_corpus_prb",
            "scale_total_corpus_e2e",
            "scale_per_decision_prb",
            "scale_per_decision_e2e",
        ):
            assert _scale_run_matches_fixed_100(suite), suite

    def test_total_corpus_size_override_only_affects_total_corpus_suites(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SCALE_TOTAL_CORPUS_SIZE", "10")
        assert not _scale_run_matches_fixed_100("scale_total_corpus_prb")
        assert not _scale_run_matches_fixed_100("scale_total_corpus_e2e")
        # The whole point of the fix: a total-corpus-only override must not also tag the
        # per-decision rows "partial" -- they ran at the real fixed-100 size.
        assert _scale_run_matches_fixed_100("scale_per_decision_prb")
        assert _scale_run_matches_fixed_100("scale_per_decision_e2e")

    def test_per_decision_candidates_override_only_affects_per_decision_suites(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SCALE_PER_DECISION_CANDIDATES", "20")
        assert not _scale_run_matches_fixed_100("scale_per_decision_prb")
        assert not _scale_run_matches_fixed_100("scale_per_decision_e2e")
        assert _scale_run_matches_fixed_100("scale_total_corpus_prb")
        assert _scale_run_matches_fixed_100("scale_total_corpus_e2e")

    def test_seed_override_affects_every_suite(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SCALE_SEED", "7")
        for suite in (
            "scale_total_corpus_prb",
            "scale_total_corpus_e2e",
            "scale_per_decision_prb",
            "scale_per_decision_e2e",
        ):
            assert not _scale_run_matches_fixed_100(suite), suite

    def test_concurrency_override_only_affects_total_corpus_suites(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # orchestrate_prb_concurrent's thread pool is the only thing SCALE_CONCURRENCY governs,
        # and only the total-corpus fixtures call it -- the per-decision fixtures make exactly
        # two sequential calls and never read this var at all, so their rows must stay "regression"
        # eligible.
        monkeypatch.setenv("SCALE_CONCURRENCY", "1")
        assert not _scale_run_matches_fixed_100("scale_total_corpus_prb")
        assert not _scale_run_matches_fixed_100("scale_total_corpus_e2e")
        assert _scale_run_matches_fixed_100("scale_per_decision_prb")
        assert _scale_run_matches_fixed_100("scale_per_decision_e2e")


class TestScenarioNameFromNodeid:
    def test_extracts_trailing_bracket_id(self) -> None:
        nodeid = "eval/test_policy_pipeline_eval.py::test_prb_correctness[baseline]"
        assert _scenario_name_from_nodeid(nodeid) == "baseline"

    def test_extracts_id_with_special_characters(self) -> None:
        nodeid = "eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[agent_delegation]"
        assert _scenario_name_from_nodeid(nodeid) == "agent_delegation"

    def test_non_parametrized_nodeid_returned_unchanged(self) -> None:
        nodeid = "eval/test_policy_pipeline_scale.py::test_scale_total_corpus_correctness_prb"
        assert _scenario_name_from_nodeid(nodeid) == nodeid

    def test_bracket_not_at_end_is_not_mistaken_for_parametrize_id(self) -> None:
        # Defensive: a nodeid with a literal "[" that doesn't end in "]" (shouldn't occur in
        # practice) falls through to the unchanged-return branch rather than mis-slicing.
        nodeid = "eval/test_policy_pipeline_eval.py::test_prb_correctness[baseline"
        assert _scenario_name_from_nodeid(nodeid) == nodeid


class TestRenderFieldFencing:
    """Confirmed as a real finding in PR review: a multi-line value containing its own backtick
    run (e.g. an LLM-drafted recommendation body with inline/fenced code) must not be able to
    prematurely close the outer fence ``_render_field`` wraps it in."""

    def test_plain_multiline_text_uses_a_three_backtick_fence(self) -> None:
        lines: list[str] = []
        _render_field(lines, "Recommendation", "line one\nline two")
        assert lines[1] == "  ```"
        assert lines[-1] == "  ```"

    def test_body_containing_a_three_backtick_fence_gets_a_longer_outer_fence(self) -> None:
        lines: list[str] = []
        body = "Wrap the fix like:\n```python\nraise ValueError\n```"
        _render_field(lines, "Recommendation", body)
        opening_fence = lines[1].strip()
        assert opening_fence == "````"  # one longer than the body's own ``` run
        assert lines[-1].strip() == "````"
        # The body's own fence lines must survive untouched, not be mistaken for the outer close.
        assert "  ```python" in lines
        assert "  ```" in lines

    def test_body_containing_a_longer_backtick_run_still_gets_a_proper_fence(self) -> None:
        lines: list[str] = []
        body = "A run of ```` four backticks\nsecond line"
        _render_field(lines, "Recommendation", body)
        opening_fence = lines[1].strip()
        assert opening_fence == "`````"  # one longer than the body's own run of 4
        assert lines[-1].strip() == opening_fence

    def test_a_lone_trailing_newline_still_gets_fenced(self) -> None:
        """``"x\\n".splitlines() == ["x"]`` -- a bare line-count check would miss this and write
        the literal embedded newline into one unfenced bullet line instead."""
        lines: list[str] = []
        _render_field(lines, "Recommendation", "Do X.\n")
        assert lines[1] == "  ```"
        assert lines[-1] == "  ```"

    def test_single_line_text_with_no_boundary_at_all_stays_unfenced(self) -> None:
        lines: list[str] = []
        _render_field(lines, "Recommendation", "Do X.")
        assert lines == ["- **Recommendation:** Do X."]

    def test_empty_text_stays_unfenced(self) -> None:
        """``"".splitlines() == []``, not ``== [""]`` -- without the ``text and`` guard this would
        wrongly take the fenced branch and render an empty fenced block."""
        lines: list[str] = []
        _render_field(lines, "Recommendation", "")
        assert lines == ["- **Recommendation:** "]


class TestSanitizeRecommendationHeading:
    """Confirmed as a real finding in PR review: an LLM-drafted heading written as a bare
    ``### heading`` line could otherwise corrupt the report's structure or fabricate a false
    ScenarioEntry in eval.dashboard.dashboard's parser."""

    def test_plain_heading_is_unchanged(self) -> None:
        assert _sanitize_recommendation_heading("Over-interpreting 'only'") == "Over-interpreting 'only'"

    def test_embedded_newline_is_collapsed_to_a_space(self) -> None:
        heading = "Over-grant\n- **Precision:** 0.1"
        sanitized = _sanitize_recommendation_heading(heading)
        assert "\n" not in sanitized
        assert sanitized == "Over-grant - **Precision:** 0.1"

    def test_backtick_wrapped_heading_no_longer_matches_the_dashboard_entry_pattern(self) -> None:
        heading = "`correctness_prb:baseline:over_grant`"
        sanitized = _sanitize_recommendation_heading(heading)
        assert "`" not in sanitized


class TestClassifyNodeid:
    """One nodeid -> family/suite classification, shared by ``_write_trend_log`` and
    ``_collect_recommendation_evidence`` (confirmed as a real finding in PR review: the two used
    to repeat this same match independently, risking silent divergence between them)."""

    def test_correctness_nodeid(self) -> None:
        nodeid = "eval/test_policy_pipeline_eval.py::test_prb_correctness[baseline]"
        result = _classify_nodeid(nodeid)
        assert result is not None
        assert result.family == "correctness"
        assert result.suite == "correctness_prb"

    def test_robustness_nodeid_carries_prop_name_and_rate_key(self) -> None:
        nodeid = "eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[baseline]"
        result = _classify_nodeid(nodeid)
        assert result is not None
        assert result.family == "robustness"
        assert result.suite == "robustness_mechanical_sensitivity"
        assert result.prop_name == "sensitive"
        assert result.rate_key == "sensitivity_rate"

    def test_consistency_nodeid(self) -> None:
        nodeid = "eval/test_policy_pipeline_consistency.py::test_prb_consistent_across_repeats[baseline]"
        result = _classify_nodeid(nodeid)
        assert result is not None
        assert result.family == "consistency"
        assert result.suite == "consistency"

    def test_scale_nodeid_carries_check_type(self) -> None:
        nodeid = "eval/test_policy_pipeline_scale.py::test_scale_total_corpus_structural_prb"
        result = _classify_nodeid(nodeid)
        assert result is not None
        assert result.family == "scale"
        assert result.suite == "scale_total_corpus_prb"
        assert result.check_type == "structural"

    def test_unrecognized_nodeid_returns_none(self) -> None:
        assert _classify_nodeid("eval/test_recommendations.py::TestFormatPairs::test_empty_dict_is_none") is None
