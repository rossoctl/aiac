"""Shared, reusable trend-log writer (spec: ``docs/evaluation/eval-framework.md`` §9).

A small, **committed-to-git**, append-only file — ``eval/dashboard/trend_log.jsonl`` by default — holding
one JSON line per eval run: model version, timestamp, and a handful of small aggregate metrics
(never verbose per-cell reasoning text or raw pair listings, which stay in the gitignored per-run
Markdown report, ``eval/conftest.py``).

JSON Lines rather than CSV: the metric-key set grows across suite tickets (Correctness's
``precision``/``recall``/``denial_precision`` today; Robustness/Consistency/Scale add their own
keys in later tickets, per the parent epic #2087) — each row is an independent JSON object, so a
new suite's row simply carries new keys with no shared-header rewrite or backfill of older rows,
unlike CSV.

``append_row`` is the whole write-side API and is suite-agnostic — callers pass their own
``suite`` name and metrics dict. ``pool_correctness_metrics`` pools the ``true_positives``/
``over_grants``/``under_grants``/``denied_total``/``incorrectly_denied`` shape ``score_scenario``
(``eval/correctness_scorer.py``) produces into aggregate precision/recall/denial_precision — the
two Correctness suites (``eval/conftest.py``'s ``_write_trend_log``, fed from
``test_prb_correctness``/``test_e2e_correctness``) use it directly, and so does the Robustness
suite's invariance/sensitivity families (``test_prb_invariant_to_mechanical_perturbation``/
``test_prb_sensitive_to_mechanical_edit``, same ``score_scenario`` shape, pooled per family so
precision/recall/denial_precision is directly comparable against the two Correctness charts —
what varies is which family's own pass/fail rate ``_write_trend_log`` adds alongside it).
``pool_consistency_metrics`` pools the Consistency suite's own ``inconsistent`` per-scenario
booleans (``eval/test_policy_pipeline_consistency.py``, #2468) into an ``agreement_rate`` instead
— its metric shape doesn't fit ``pool_correctness_metrics`` since there's no truth table involved,
just run-to-run agreement. Deliberately framed as *agreement* (higher is better), not
*disagreement* (lower is better): every other metric on the dashboard's shared 0-1 axis
(precision/recall/denial_precision, invariance_rate/sensitivity_rate) reads "line goes up = good",
and an unlabeled inverted-polarity line among them would silently read backwards.
``pool_scale_metrics`` pools the Scale suite's structural-check entries
(``eval/test_policy_pipeline_scale.py``, #2469) into a ``structural_pass_rate``/
``structural_issue_count``/latency/cost aggregate — its correctness half reuses
``pool_correctness_metrics`` as-is (the same precision/recall/denial_precision shape), so each
Scale suite row is built from both pooling functions' output merged together
(``eval/conftest.py``'s ``_write_trend_log``).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
# Beside this writer and eval/dashboard/dashboard.py, not under eval/reports/ or eval/rego_out/
# (the only two paths .gitignore excludes) — so this file is tracked by git with no .gitignore
# change needed.
DEFAULT_PATH = HERE / "trend_log.jsonl"


def pool_correctness_metrics(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Pool per-scenario counts recorded by ``test_prb_correctness``/``test_e2e_correctness`` —
    ``true_positives`` (int), ``denied_total`` (int), ``over_grants``/``under_grants``/
    ``incorrectly_denied`` (``{gate: [(role, scope), ...]}``) — into one run's aggregate
    precision/recall/denial_precision.

    Pooled by summed count across every scenario, not averaged per-scenario — mirrors
    ``correctness_scorer.score_scenario``'s own union-not-average aggregation across gates, so a
    run with an uneven pair count per scenario isn't skewed by weighting every scenario equally.
    Vacuously ``1.0`` when a denominator is 0, same convention as ``correctness_scorer``.
    """
    true_positives = sum(e["true_positives"] for e in entries)
    over_grants = sum(len(pairs) for e in entries for pairs in e.get("over_grants", {}).values())
    under_grants = sum(len(pairs) for e in entries for pairs in e.get("under_grants", {}).values())
    denied_total = sum(e.get("denied_total", 0) for e in entries)
    incorrectly_denied = sum(len(pairs) for e in entries for pairs in e.get("incorrectly_denied", {}).values())
    correctly_denied = denied_total - incorrectly_denied

    granted = true_positives + over_grants
    expected = true_positives + under_grants
    precision = 1.0 if granted == 0 else true_positives / granted
    recall = 1.0 if expected == 0 else true_positives / expected
    denial_precision = 1.0 if denied_total == 0 else correctly_denied / denied_total

    return {
        "scenarios_scored": len(entries),
        "precision": precision,
        "recall": recall,
        "denial_precision": denial_precision,
    }


def pool_scale_metrics(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Pool the Scale suite's structural-check entries (``test_policy_pipeline_scale.py``, #2469)
    into one run's aggregate. Unlike ``pool_correctness_metrics``/``pool_consistency_metrics``,
    both scale dimensions (total-corpus, per-decision) record the same two common fields
    regardless of which concrete checks ran underneath -- ``structural_pass`` (bool: did every
    gated check -- completeness/no-duplication/no-orphans -- pass) and
    ``structural_issue_count`` (int: total offending entities found across every gated check) --
    so this one pooling function covers both dimensions' rows without needing to know each
    dimension's own field taxonomy (``missing_decisions``/``duplicate_triples``/``orphaned_scopes``
    for total-corpus; ``scope_invalid_names``/``role_invalid_names``/``duplicate_triples`` for
    per-decision -- see ``eval.scale_structural``). ``wall_clock_seconds``/``total_tokens``/
    ``token_coverage`` are latency/cost, reported and trended only (no SLA to gate against).

    Pooled by summed count / mean, not per-entry-averaged floats blended into a single number that
    hides which run contributed what -- mirrors ``pool_correctness_metrics``'s summed-not-averaged
    philosophy. In practice each dimension/level is a single test case per run (not an 8-scenario
    sweep), so ``entries`` is usually length 1 -- pooling is kept generic anyway, the same reason
    ``pool_correctness_metrics``/``pool_consistency_metrics`` are, so a future ticket that adds more
    structural entries per run needs no new pooling function."""
    runs = len(entries)
    issue_count = sum(e.get("structural_issue_count", 0) for e in entries)
    clean_runs = sum(1 for e in entries if e.get("structural_pass"))
    total_tokens = sum(e.get("total_tokens", 0) for e in entries)
    wall_clock_values = [e["wall_clock_seconds"] for e in entries if e.get("wall_clock_seconds") is not None]
    coverage_values = [e["token_coverage"] for e in entries if e.get("token_coverage") is not None]
    return {
        # "scenarios_scored", not "runs_scored": every pooling function in this module uses this
        # exact key for its row count, and eval/dashboard/dashboard.py's _ROW_BOOKKEEPING_KEYS excludes it
        # from the trend chart by that exact name -- a different name here would have silently
        # slipped through as a plottable "metric" instead (confirmed: it did, until this was
        # caught in review).
        "scenarios_scored": runs,
        "structural_pass_rate": clean_runs / runs if runs else 1.0,
        "structural_issue_count": issue_count,
        "total_tokens": total_tokens,
        "mean_wall_clock_seconds": sum(wall_clock_values) / len(wall_clock_values) if wall_clock_values else 0.0,
        "mean_token_coverage": sum(coverage_values) / len(coverage_values) if coverage_values else 1.0,
    }


def pool_consistency_metrics(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Pool per-scenario ``inconsistent`` booleans recorded by ``test_prb_consistent_across_repeats``
    (``eval/test_policy_pipeline_consistency.py``) into one run's aggregate agreement rate — the
    fraction of scenarios where the PRB's grant sets stayed identical across all of its
    ``PRB_CONSISTENCY_REPEATS`` (default 5) repeats. Unlike ``pool_correctness_metrics``, there is no
    truth table here — Consistency checks run-to-run agreement, not correctness against ground
    truth — so this pools a pass/fail flag per scenario rather than true_positives/over_grants/etc.
    counts. Framed as *agreement* rather than *disagreement* so "higher is better" holds for this
    metric the same way it does for every other rate on the dashboard's shared 0-1 axis; vacuously
    ``1.0`` (fully agreed) when no scenario was scored, same optimistic-default convention
    ``pool_correctness_metrics`` uses for its own denominators."""
    scenarios_scored = len(entries)
    disagreements = sum(1 for e in entries if e.get("inconsistent"))
    return {
        "scenarios_scored": scenarios_scored,
        "agreement_rate": 1.0 if not scenarios_scored else (scenarios_scored - disagreements) / scenarios_scored,
    }


def append_row(
    suite: str,
    metrics: dict[str, Any],
    *,
    run_type: str = "regression",
    model: str | None = None,
    timestamp: datetime | None = None,
    path: Path = DEFAULT_PATH,
) -> dict[str, Any]:
    """Append one JSON line to the committed trend log.

    ``model`` defaults to ``LLM_MODEL`` (spec §7: the pinned model version is recorded on every
    row so historical trend data stays interpretable across model changes), falling back to
    ``"unknown"`` when unset. ``run_type`` distinguishes routine ``"regression"`` rows from
    ``"partial"`` (``eval/conftest.py``'s ``_write_trend_log``, when a run — a ``-k`` filter, or
    most scenarios erroring in setup — scores fewer than the full scenario corpus, so it's not
    comparable to a full-corpus regression row) and from the ``"model_selection"`` comparison run
    (spec §7.1) — not produced by this ticket, but the parameter exists so that future run reuses
    this same writer instead of a parallel one.

    Every float value in ``metrics`` is rounded to 3 decimal digits before being written — plenty
    of precision to see drift over time, and keeps the committed file's diffs small and readable.
    Non-float values (``scenarios_scored``, etc.) pass through unchanged. Applied here, not by
    each suite's own pooling function, so every suite that reuses this writer gets it uniformly.
    """
    rounded_metrics = {k: round(v, 3) if isinstance(v, float) else v for k, v in metrics.items()}
    row: dict[str, Any] = {
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "suite": suite,
        "run_type": run_type,
        "model": model if model is not None else os.environ.get("LLM_MODEL", "unknown"),
        **rounded_metrics,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    return row
