"""Unit tests for ``eval.conftest``'s own pure-logic helpers (spec:
``docs/evaluation/policy-eval-scale.md``, #2469).

``eval/conftest.py`` is a pytest plugin module, not something this repo otherwise unit-tests
directly -- but ``_scale_run_matches_fixed_100`` is pure logic over ``os.environ`` with real
per-suite branching worth protecting on its own. Unmarked, runs in the default fast pass.
"""

from __future__ import annotations

import pytest

from eval.conftest import _scale_run_matches_fixed_100


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
