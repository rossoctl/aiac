"""Tests for ``eval/nodeid.py`` (spec: ``docs/evaluation/eval-framework.md`` §9.1, #2472).

Pure logic, no LLM, no I/O -- unmarked, runs in the default fast pass.
"""

from __future__ import annotations

from eval.nodeid import scenario_for_nodeid


class TestScenarioForNodeid:
    def test_extracts_trailing_bracket_id(self) -> None:
        nodeid = "eval/test_policy_pipeline_eval.py::test_prb_correctness[baseline]"
        assert scenario_for_nodeid(nodeid) == "baseline"

    def test_extracts_id_with_special_characters(self) -> None:
        nodeid = "eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[agent_delegation]"
        assert scenario_for_nodeid(nodeid) == "agent_delegation"

    def test_non_parametrized_nodeid_returns_none(self) -> None:
        nodeid = "eval/test_policy_pipeline_scale.py::test_scale_total_corpus_correctness_prb"
        assert scenario_for_nodeid(nodeid) is None

    def test_bracket_not_at_end_returns_none(self) -> None:
        # Defensive: a nodeid with a literal "[" that doesn't end in "]" (shouldn't occur in
        # practice) must not be mistaken for a parametrize id.
        nodeid = "eval/test_policy_pipeline_eval.py::test_prb_correctness[baseline"
        assert scenario_for_nodeid(nodeid) is None

    def test_nested_brackets_are_rejected(self) -> None:
        # The pattern disallows a nested "["/"]" inside the captured group -- an unusual
        # parametrize id with its own brackets must not be mistaken for a clean scenario name.
        nodeid = "eval/test_policy_pipeline_eval.py::test_prb_correctness[a[b]]"
        assert scenario_for_nodeid(nodeid) is None
