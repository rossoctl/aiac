"""Unit tests for ``eval.scale_prb``'s log-capture helper (spec:
``docs/evaluation/policy-eval-scale.md``).

``orchestrate_prb_concurrent``/``run_concurrently`` themselves need a real LLM endpoint and are
exercised only by the live-LLM suite (``eval/test_policy_pipeline_scale.py``, ``-m eval``).
``capture_precheck_drops`` is pure logging plumbing with no LLM/IO of its own, so it's tested
directly here, offline -- unmarked, runs in the default fast pass.
"""

from __future__ import annotations

import logging

from eval.scale_prb import _PRECHECK_LOGGER_NAME, capture_precheck_drops


def _log_precheck_drop(granted: list[str], denied: list[str]) -> None:
    # Mirrors exactly how aiac.agent.policy_rules_builder.graph._precheck logs a drop -- same
    # logger name, same message template, same two-list args shape.
    logging.getLogger(_PRECHECK_LOGGER_NAME).warning(
        "PRB precheck dropped hallucinated names: granted=%s denied=%s", granted, denied
    )


class TestCapturePrecheckDrops:
    def test_captures_a_drop_logged_during_the_with_block(self) -> None:
        with capture_precheck_drops() as cap:
            _log_precheck_drop(["ghost-role"], [])
        assert cap.granted == ["ghost-role"]
        assert cap.denied == []

    def test_captures_both_granted_and_denied_sides(self) -> None:
        with capture_precheck_drops() as cap:
            _log_precheck_drop(["ghost-role"], ["ghost-scope"])
        assert cap.granted == ["ghost-role"]
        assert cap.denied == ["ghost-scope"]

    def test_empty_when_nothing_logged(self) -> None:
        with capture_precheck_drops() as cap:
            pass
        assert cap.granted == []
        assert cap.denied == []

    def test_ignores_an_unrelated_warning_on_the_same_logger(self) -> None:
        with capture_precheck_drops() as cap:
            logging.getLogger(_PRECHECK_LOGGER_NAME).warning("some unrelated warning: %s", "noise")
        assert cap.granted == []
        assert cap.denied == []

    def test_handler_is_removed_after_the_with_block(self) -> None:
        logger = logging.getLogger(_PRECHECK_LOGGER_NAME)
        before = list(logger.handlers)
        with capture_precheck_drops():
            pass
        assert logger.handlers == before

    def test_two_sequential_with_blocks_do_not_leak_into_each_other(self) -> None:
        with capture_precheck_drops() as first:
            _log_precheck_drop(["ghost-role-1"], [])
        with capture_precheck_drops() as second:
            _log_precheck_drop(["ghost-role-2"], [])
        assert first.granted == ["ghost-role-1"]
        assert second.granted == ["ghost-role-2"]

    def test_a_retried_attempt_replaces_not_accumulates_an_earlier_drop(self) -> None:
        # A rejected proposal can route back to a fresh propose/_precheck pass within the SAME
        # decision call (aiac.agent.policy_rules_builder.graph._audit's retry routing) -- if that
        # retry drops a *different* name, the capture must reflect only the latest attempt, not
        # the union of every attempt's drops.
        with capture_precheck_drops() as cap:
            _log_precheck_drop(["ghost-role-attempt-1"], [])
            _log_precheck_drop(["ghost-role-attempt-2"], [])
        assert cap.granted == ["ghost-role-attempt-2"]
