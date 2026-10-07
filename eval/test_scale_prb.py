"""Unit tests for ``eval.scale_prb``'s precheck-capture helper (spec:
``docs/evaluation/policy-eval-scale.md``).

``orchestrate_prb_concurrent``/``run_concurrently`` themselves need a real LLM endpoint and are
exercised only by the live-LLM suite (``eval/test_policy_pipeline_scale.py``, ``-m eval``).
``capture_precheck_drops`` wraps the real (production, unmodified) ``_precheck`` function, so it
can be exercised directly here with hand-built state dicts, no LLM/IO needed -- unmarked, runs in
the default fast pass.
"""

from __future__ import annotations

import aiac.agent.policy_rules_builder.graph as graph_module
from eval.scale_prb import capture_precheck_drops


def _state(selected: list[str], denied: list[str]) -> dict[str, list[str]]:
    # The only two keys the real _precheck reads (aiac/agent/policy_rules_builder/graph.py).
    return {"selected_names": selected, "denied_names": denied}


class TestCapturePrecheckDrops:
    def test_captures_a_drop_during_the_with_block(self) -> None:
        with capture_precheck_drops() as cap:
            graph_module._precheck(_state(["ghost-role"], []), candidate_names=set())
        assert cap.granted == ["ghost-role"]
        assert cap.denied == []

    def test_captures_both_granted_and_denied_sides(self) -> None:
        with capture_precheck_drops() as cap:
            graph_module._precheck(_state(["ghost-role"], ["ghost-scope"]), candidate_names=set())
        assert cap.granted == ["ghost-role"]
        assert cap.denied == ["ghost-scope"]

    def test_empty_when_nothing_called(self) -> None:
        with capture_precheck_drops() as cap:
            pass
        assert cap.granted == []
        assert cap.denied == []

    def test_a_clean_call_reports_no_drops(self) -> None:
        # Every selected/denied name is a real candidate -- nothing dropped.
        with capture_precheck_drops() as cap:
            graph_module._precheck(_state(["real-role"], []), candidate_names={"real-role"})
        assert cap.granted == []
        assert cap.denied == []

    def test_a_clean_retry_after_a_dirty_attempt_correctly_resets_to_empty(self) -> None:
        # The exact scenario review flagged: a first attempt hallucinates and gets rejected for a
        # reason unrelated to that, the retry is clean and is the one actually used -- the
        # capture must not keep blaming the final, correct response for the earlier, superseded
        # attempt. An approach that only listens to _precheck's own diagnostic log line can't do
        # this: that line is logged only when something is dropped, so the clean retry leaves no
        # event to reset on. Wrapping _precheck itself sees this call too, clean or not.
        with capture_precheck_drops() as cap:
            graph_module._precheck(_state(["ghost-role"], []), candidate_names=set())
            graph_module._precheck(_state(["real-role"], []), candidate_names={"real-role"})
        assert cap.granted == []
        assert cap.denied == []

    def test_a_second_dirty_attempt_replaces_not_accumulates_the_first(self) -> None:
        with capture_precheck_drops() as cap:
            graph_module._precheck(_state(["ghost-role-1"], []), candidate_names=set())
            graph_module._precheck(_state(["ghost-role-2"], []), candidate_names=set())
        assert cap.granted == ["ghost-role-2"]

    def test_original_precheck_is_restored_after_the_with_block(self) -> None:
        original = graph_module._precheck
        with capture_precheck_drops():
            assert graph_module._precheck is not original
        assert graph_module._precheck is original

    def test_two_sequential_with_blocks_do_not_leak_into_each_other(self) -> None:
        with capture_precheck_drops() as first:
            graph_module._precheck(_state(["ghost-role-1"], []), candidate_names=set())
        with capture_precheck_drops() as second:
            graph_module._precheck(_state(["ghost-role-2"], []), candidate_names=set())
        assert first.granted == ["ghost-role-1"]
        assert second.granted == ["ghost-role-2"]
