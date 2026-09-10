"""Shared, reusable trend-log writer (spec: ``docs/specs/eval/eval-framework.md`` §9).

A small, **committed-to-git**, append-only file — ``eval/trend_log.jsonl`` by default — holding
one JSON line per eval run: model version, timestamp, and a handful of small aggregate metrics
(never verbose per-cell reasoning text or raw pair listings, which stay in the gitignored per-run
Markdown report, ``eval/conftest.py``).

JSON Lines rather than CSV: the metric-key set grows across suite tickets (Correctness's
``precision``/``recall``/``denial_precision`` today; Robustness/Consistency/Scale add their own
keys in later tickets, per the parent epic #2087) — each row is an independent JSON object, so a
new suite's row simply carries new keys with no shared-header rewrite or backfill of older rows,
unlike CSV.

``append_row`` is the whole write-side API and is suite-agnostic — callers pass their own
``suite`` name and metrics dict. ``pool_correctness_metrics`` is specific to the Correctness
suites (``eval/conftest.py``'s ``_write_trend_log``, fed from ``test_prb_correctness``/
``test_e2e_correctness``'s ``record_property`` calls) and is not meant to be reused as-is by the
later Robustness/Consistency/Scale tickets — each of those will need its own pooling function for
its own metric shape, written the same way, then handed to the same ``append_row``.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
# Beside conftest.py, not under eval/reports/ or eval/rego_out/ (the only two paths .gitignore
# excludes) — so this file is tracked by git with no .gitignore change needed.
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
