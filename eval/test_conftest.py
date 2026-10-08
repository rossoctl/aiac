"""Unit tests for ``eval.conftest``'s own pure-logic helpers (spec:
``docs/evaluation/policy-eval-scale.md``, #2469).

``eval/conftest.py`` is a pytest plugin module, not something this repo otherwise unit-tests
directly -- but ``_scale_run_matches_fixed_100`` is pure logic over ``os.environ`` with real
per-suite branching worth protecting on its own. Unmarked, runs in the default fast pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import eval.conftest as eval_conftest
from eval.conftest import _scale_run_matches_fixed_100, _write_trend_log


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


class TestWriteTrendLogPartialScaleSuites:
    """``_write_trend_log`` returns the Scale suites whose row it tagged "partial"; the report
    header names exactly these, so the dashboard and the trend log agree."""

    @pytest.fixture(autouse=True)
    def rows(self, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
        """The ``(suite, run_type)`` of each row that ``_write_trend_log`` appends (no file write)."""
        rows: list[tuple[str, str]] = []
        monkeypatch.setattr(eval_conftest, "append_row", lambda suite, _m, run_type: rows.append((suite, run_type)))
        monkeypatch.setattr(eval_conftest, "pool_scale_metrics", lambda entries: {})
        monkeypatch.setattr(eval_conftest, "pool_correctness_metrics", lambda entries: {})
        return rows

    def _ran(self, monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
        reports = {}
        for name in names:
            nodeid = f"eval/test_policy_pipeline_scale.py::{name}"
            props = [("structural_pass", True)] if "structural" in name else [("true_positives", 1)]
            reports[nodeid] = SimpleNamespace(nodeid=nodeid, user_properties=props)
        monkeypatch.setattr(eval_conftest, "_reports", reports)

    def test_a_full_fixed_100_run_is_not_partial(
        self, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str]]
    ) -> None:
        self._ran(monkeypatch, "test_scale_total_corpus_structural_prb", "test_scale_total_corpus_correctness_prb")
        assert _write_trend_log() == []
        assert rows == [("scale_total_corpus_prb", "regression")]

    def test_a_reduced_size_run_is_partial(self, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str]]) -> None:
        self._ran(monkeypatch, "test_scale_total_corpus_structural_prb", "test_scale_total_corpus_correctness_prb")
        monkeypatch.setenv("SCALE_TOTAL_CORPUS_SIZE", "10")
        partial = _write_trend_log()
        assert partial == ["scale_total_corpus_prb"]
        assert partial == sorted(suite for suite, run_type in rows if run_type == "partial")

    def test_a_run_of_only_one_half_is_partial(
        self, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str]]
    ) -> None:
        self._ran(monkeypatch, "test_scale_per_decision_correctness_e2e")
        partial = _write_trend_log()
        assert partial == ["scale_per_decision_e2e"]
        assert partial == sorted(suite for suite, run_type in rows if run_type == "partial")

    def test_a_skipped_suite_records_nothing_so_is_not_named(
        self, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str]]
    ) -> None:
        nodeid = "eval/test_policy_pipeline_scale.py::test_scale_total_corpus_correctness_prb"
        monkeypatch.setattr(eval_conftest, "_reports", {nodeid: SimpleNamespace(nodeid=nodeid, user_properties=[])})
        monkeypatch.setenv("SCALE_TOTAL_CORPUS_SIZE", "10")
        assert _write_trend_log() == []
        assert rows == []

    def test_a_count_mismatch_between_the_halves_is_partial(
        self, monkeypatch: pytest.MonkeyPatch, rows: list[tuple[str, str]]
    ) -> None:
        # Two structural entries (as if the test were parametrized) against one correctness entry.
        self._ran(
            monkeypatch,
            "test_scale_total_corpus_structural_prb[a]",
            "test_scale_total_corpus_structural_prb[b]",
            "test_scale_total_corpus_correctness_prb",
        )
        partial = _write_trend_log()
        assert partial == ["scale_total_corpus_prb"]
        assert partial == sorted(suite for suite, run_type in rows if run_type == "partial")
