"""Unit tests for ``trend_log.py`` (spec: ``docs/specs/eval/eval-framework.md`` §9).

Pure-logic + a small file-append, unmarked — runs in the default fast pass (``testpaths`` already
includes ``eval/``). No LLM, no Keycloak, no live pytest reports.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval.trend_log import append_row, pool_correctness_metrics


def test_pool_empty_entries_is_vacuously_perfect() -> None:
    metrics = pool_correctness_metrics([])

    assert metrics == {
        "scenarios_scored": 0,
        "precision": 1.0,
        "recall": 1.0,
        "denial_precision": 1.0,
    }


def test_pool_pure_over_grant_lowers_precision_only() -> None:
    entries = [
        {
            "true_positives": 1,
            "over_grants": {"inbound": [("role-a", "scope-x")]},
            "under_grants": {},
            "incorrectly_denied": {},
            "denied_total": 0,
        }
    ]

    metrics = pool_correctness_metrics(entries)

    assert metrics["scenarios_scored"] == 1
    assert metrics["precision"] == 0.5  # TP=1, FP=1
    assert metrics["recall"] == 1.0
    assert metrics["denial_precision"] == 1.0  # no denials at all -> vacuous


def test_pool_pure_under_grant_lowers_recall_only() -> None:
    entries = [
        {
            "true_positives": 1,
            "over_grants": {},
            "under_grants": {"outbound_target": [("role-a", "scope-y")]},
            "incorrectly_denied": {},
            "denied_total": 0,
        }
    ]

    metrics = pool_correctness_metrics(entries)

    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.5  # TP=1, FN=1


def test_pool_denial_precision_from_denied_total_and_incorrectly_denied() -> None:
    entries = [
        {
            "true_positives": 2,
            "over_grants": {},
            "under_grants": {"inbound": [("role-a", "scope-z")]},
            "incorrectly_denied": {"inbound": [("role-a", "scope-z")]},
            "denied_total": 3,  # 1 incorrect + 2 correct
        }
    ]

    metrics = pool_correctness_metrics(entries)

    # correctly_denied = denied_total - incorrectly_denied = 3 - 1 = 2
    assert metrics["denial_precision"] == 2 / 3


def test_pool_missing_optional_keys_default_cleanly() -> None:
    entries = [{"true_positives": 1}]

    metrics = pool_correctness_metrics(entries)

    assert metrics == {
        "scenarios_scored": 1,
        "precision": 1.0,
        "recall": 1.0,
        "denial_precision": 1.0,
    }


def test_pool_multiple_scenarios_pools_by_count_not_average() -> None:
    # Scenario 1: TP=1, FP=1 -> precision 0.5. Scenario 2: TP=9, FP=0 -> precision 1.0.
    # A naive per-scenario average would give (0.5 + 1.0) / 2 = 0.75.
    # Pooled by count: TP=10, FP=1 -> precision = 10/11.
    entries = [
        {
            "true_positives": 1,
            "over_grants": {"inbound": [("role-a", "scope-x")]},
            "under_grants": {},
            "incorrectly_denied": {},
            "denied_total": 0,
        },
        {
            "true_positives": 9,
            "over_grants": {},
            "under_grants": {},
            "incorrectly_denied": {},
            "denied_total": 0,
        },
    ]

    metrics = pool_correctness_metrics(entries)

    assert metrics["scenarios_scored"] == 2
    naive_average = (0.5 + 1.0) / 2
    assert metrics["precision"] != naive_average
    assert metrics["precision"] == 10 / 11


def test_append_row_writes_one_json_line(tmp_path: Path) -> None:
    path = tmp_path / "trend_log.jsonl"

    row = append_row("correctness_prb", {"precision": 1.0, "recall": 0.9}, model="gpt-test", path=path)

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    written = json.loads(lines[0])
    assert written == row
    assert written["suite"] == "correctness_prb"
    assert written["run_type"] == "regression"
    assert written["model"] == "gpt-test"
    assert written["precision"] == 1.0
    assert written["recall"] == 0.9
    assert "timestamp" in written


def test_append_row_appends_not_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "trend_log.jsonl"

    append_row("correctness_prb", {"precision": 1.0}, model="m1", path=path)
    append_row("correctness_e2e", {"precision": 0.8}, model="m1", path=path)

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["suite"] == "correctness_prb"
    assert json.loads(lines[1])["suite"] == "correctness_e2e"


def test_append_row_model_falls_back_to_llm_model_env(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "trend_log.jsonl"
    monkeypatch.setenv("LLM_MODEL", "env-pinned-model")

    row = append_row("correctness_prb", {"precision": 1.0}, path=path)

    assert row["model"] == "env-pinned-model"


def test_append_row_model_unknown_when_unset(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "trend_log.jsonl"
    monkeypatch.delenv("LLM_MODEL", raising=False)

    row = append_row("correctness_prb", {"precision": 1.0}, path=path)

    assert row["model"] == "unknown"
