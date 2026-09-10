"""Unit tests for ``dashboard.py`` (spec: issue #2542 — eval results dashboard).

Pure-logic + file I/O against tmp paths, unmarked (runs in the default fast pass; ``testpaths``
already includes ``eval/``). No LLM, no Keycloak, no live pytest run.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from eval.dashboard import (
    ParsedReport,
    ScenarioEntry,
    _find_matching_report,
    _report_anchor,
    build_dashboard,
    load_trend_log,
    parse_report,
    parse_reports,
    render_dashboard,
    render_scenario_table,
    render_svg_chart,
)


def _report(run_at_iso: str, suite: str | None) -> ParsedReport:
    entries = [ScenarioEntry(nodeid="n", suite=suite)] if suite else []
    return ParsedReport(
        path=Path(f"report_{run_at_iso}.md"), run_at=datetime.fromisoformat(run_at_iso), entries=entries
    )


def test_find_matching_report_picks_nearest_same_suite_within_tolerance() -> None:
    row = {"suite": "correctness_prb", "timestamp": "2026-09-10T07:00:05+00:00"}
    far = _report("2026-09-10T01:00:00+00:00", "correctness_prb")
    near = _report("2026-09-10T07:00:00+00:00", "correctness_prb")
    other_suite = _report("2026-09-10T07:00:01+00:00", "correctness_e2e")

    match = _find_matching_report(row, [far, other_suite, near])

    assert match is near


def test_find_matching_report_returns_none_outside_tolerance() -> None:
    row = {"suite": "correctness_prb", "timestamp": "2026-09-10T07:00:00+00:00"}
    stale = _report("2026-09-09T00:00:00+00:00", "correctness_prb")

    assert _find_matching_report(row, [stale]) is None


def test_find_matching_report_returns_none_when_no_same_suite_report() -> None:
    row = {"suite": "correctness_prb", "timestamp": "2026-09-10T07:00:00+00:00"}
    other = _report("2026-09-10T07:00:00+00:00", "correctness_e2e")

    assert _find_matching_report(row, [other]) is None


REPORT_HEADER = "# policy-eval-scenarios test report\n\nRun: 2026-09-10T07:00:36.717976+00:00\nExit status: 0\nTotal: 1 — passed=1\n\n"


def _write_report(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "report_10_09_07_00_36.md"
    path.write_text(REPORT_HEADER + body)
    return path


def test_parse_report_extracts_passing_correctness_prb_entry(tmp_path: Path) -> None:
    body = (
        "## passed (1)\n\n"
        "### `eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[baseline]`\n"
        "- **What it tests:** Checks the PRB's raw grant set against the truth table.\n"
        "- **Precision:** 1.000\n"
        "- **Recall:** 1.000\n"
        "- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:** none\n"
        "- **Incorrectly denied:** none\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    assert report.path == path
    assert report.run_at.isoformat() == "2026-09-10T07:00:36.717976+00:00"
    assert len(report.entries) == 1
    entry = report.entries[0]
    assert entry.suite == "correctness_prb"
    assert entry.scenario == "baseline"
    assert entry.category == "passed"
    assert entry.what_it_tests == "Checks the PRB's raw grant set against the truth table."
    assert entry.precision == 1.0
    assert entry.recall == 1.0
    assert entry.denial_precision == 1.0
    assert entry.over_grants == "none"
    assert entry.under_grants == "none"
    assert entry.incorrectly_denied == "none"


def test_parse_report_handles_multiline_fenced_under_grants(tmp_path: Path) -> None:
    body = (
        "## passed (1)\n\n"
        "### `eval/test_policy_pipeline_correctness_e2e.py::test_e2e_correctness[agent_delegation]`\n"
        "- **Precision:** 0.875\n"
        "- **Recall:** 0.700\n"
        "- **Denial precision:** 0.500\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:**\n"
        "  ```\n"
        "  outbound_subject: (a, b), (c, d)\n"
        "  outbound_target: (e, f)\n"
        "  ```\n"
        "- **Incorrectly denied:** none\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    entry = report.entries[0]
    assert entry.suite == "correctness_e2e"
    assert entry.scenario == "agent_delegation"
    assert entry.under_grants == "outbound_subject: (a, b), (c, d)\noutbound_target: (e, f)"


def test_parse_report_setup_failure_leaves_metrics_none(tmp_path: Path) -> None:
    body = (
        "## error (1)\n\n"
        "### `eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[wildcard_grant]`\n"
        "- **What it tests:** Some docstring.\n"
        "- **Failure:** setup crashed\n"
        "- **Precision:** unavailable — scenario setup failed before scoring could run\n"
        "- **Recall:** unavailable — scenario setup failed before scoring could run\n"
        "- **Denial precision:** unavailable — scenario setup failed before scoring could run\n"
        "- **Over-grants:** unavailable — scenario setup failed before scoring could run\n"
        "- **Under-grants:** unavailable — scenario setup failed before scoring could run\n"
        "- **Incorrectly denied:** unavailable — scenario setup failed before scoring could run\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    entry = report.entries[0]
    assert entry.category == "error"
    assert entry.failure == "setup crashed"
    assert entry.precision is None
    assert entry.recall is None
    assert entry.denial_precision is None


def test_parse_report_non_correctness_entry_has_no_suite(tmp_path: Path) -> None:
    body = (
        "## passed (1)\n\n"
        "### `eval/test_policy_pipeline_eval.py::test_inbound[baseline-repo-agent-dev]`\n"
        "- **What it tests:** Checks one inbound cell.\n"
        "- **Expected output:** True — some reason\n"
        "- **Output:** True — some reason\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    entry = report.entries[0]
    assert entry.suite is None
    assert entry.scenario is None
    assert entry.precision is None


def test_parse_reports_sorts_by_run_at_and_skips_garbage(tmp_path: Path) -> None:
    (tmp_path / "report_10_09_06_00_00.md").write_text(
        "# policy-eval-scenarios test report\n\nRun: 2026-09-10T06:00:00+00:00\n\n## passed (0)\n\n_none_\n\n"
    )
    (tmp_path / "report_10_09_08_00_00.md").write_text(
        "# policy-eval-scenarios test report\n\nRun: 2026-09-10T08:00:00+00:00\n\n## passed (0)\n\n_none_\n\n"
    )
    (tmp_path / "report_garbage.md").write_text("not a real report, no Run: line at all")

    reports = parse_reports(tmp_path)

    assert [r.run_at.hour for r in reports] == [6, 8]


def test_render_svg_chart_has_one_circle_per_row_and_legend_labels() -> None:
    rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 0.9,
            "denial_precision": 1.0,
        },
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T08:00:00+00:00",
            "precision": 0.8,
            "recall": 0.7,
            "denial_precision": 0.9,
        },
    ]

    svg = render_svg_chart(rows, reports=[], suite="correctness_prb")

    assert svg.count("<circle") == 2 * 3  # 3 metrics per row
    assert "precision" in svg
    assert "recall" in svg
    assert "denial_precision" in svg


def test_render_svg_chart_links_point_to_matching_report_anchor() -> None:
    rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        }
    ]
    report = _report("2026-09-10T07:00:01+00:00", "correctness_prb")

    svg = render_svg_chart(rows, reports=[report], suite="correctness_prb")

    assert f'href="#{_report_anchor(report)}"' in svg


def test_render_scenario_table_lists_correctness_entries_anchored_for_chart_links() -> None:
    entry = ScenarioEntry(
        nodeid="eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[baseline]",
        suite="correctness_prb",
        scenario="baseline",
        category="passed",
        precision=1.0,
        recall=1.0,
        denial_precision=1.0,
    )
    report = ParsedReport(
        path=Path("report_x.md"), run_at=datetime.fromisoformat("2026-09-10T07:00:00+00:00"), entries=[entry]
    )

    table = render_scenario_table(report)

    assert f'id="{_report_anchor(report)}"' in table
    assert "baseline" in table
    assert "1.000" in table


def test_render_scenario_table_escapes_html_and_preserves_multiline_breaks() -> None:
    entry = ScenarioEntry(
        nodeid="eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[baseline]",
        suite="correctness_prb",
        scenario="baseline",
        category="failed",
        under_grants="inbound: (<role>, scope)\noutbound_target: (a, b)",
    )
    report = ParsedReport(
        path=Path("report_x.md"), run_at=datetime.fromisoformat("2026-09-10T07:00:00+00:00"), entries=[entry]
    )

    table = render_scenario_table(report)

    assert "<role>" not in table
    assert "&lt;role&gt;" in table
    assert "inbound: (&lt;role&gt;, scope)<br>outbound_target: (a, b)" in table


def test_render_scenario_table_empty_for_report_with_no_correctness_entries() -> None:
    entry = ScenarioEntry(nodeid="eval/test_policy_pipeline_eval.py::test_inbound[x]", suite=None)
    report = ParsedReport(
        path=Path("report_x.md"), run_at=datetime.fromisoformat("2026-09-10T07:00:00+00:00"), entries=[entry]
    )

    assert render_scenario_table(report) == ""


def test_render_dashboard_includes_chart_and_drilldown_sections() -> None:
    trend_rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        }
    ]
    entry = ScenarioEntry(
        nodeid="eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[baseline]",
        suite="correctness_prb",
        scenario="baseline",
        category="passed",
        precision=1.0,
        recall=1.0,
        denial_precision=1.0,
    )
    report = ParsedReport(
        path=Path("report_x.md"), run_at=datetime.fromisoformat("2026-09-10T07:00:00+00:00"), entries=[entry]
    )

    html = render_dashboard(trend_rows, [report])

    assert "correctness_prb" in html
    assert "baseline" in html
    assert "<svg" in html


def test_render_dashboard_empty_state_when_no_data() -> None:
    html = render_dashboard([], [])

    assert "<svg" not in html
    assert "No trend-log rows" in html
    assert "No per-run reports" in html


def test_build_dashboard_writes_html_from_real_files(tmp_path: Path) -> None:
    trend_log_path = tmp_path / "trend_log.jsonl"
    trend_log_path.write_text(
        json.dumps(
            {
                "suite": "correctness_prb",
                "timestamp": "2026-09-10T07:00:00+00:00",
                "precision": 1.0,
                "recall": 1.0,
                "denial_precision": 1.0,
            }
        )
        + "\n"
    )
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    _write_report(
        reports_dir,
        "## passed (1)\n\n"
        "### `eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[baseline]`\n"
        "- **Precision:** 1.000\n- **Recall:** 1.000\n- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n- **Under-grants:** none\n- **Incorrectly denied:** none\n\n",
    )
    output_path = tmp_path / "dashboard.html"

    result = build_dashboard(trend_log_path=trend_log_path, reports_dir=reports_dir, output_path=output_path)

    assert result == output_path
    html = output_path.read_text()
    assert "correctness_prb" in html
    assert "baseline" in html


def test_load_trend_log_reads_jsonl_rows(tmp_path: Path) -> None:
    path = tmp_path / "trend_log.jsonl"
    path.write_text(
        json.dumps({"suite": "correctness_prb", "precision": 1.0})
        + "\n"
        + json.dumps({"suite": "correctness_e2e", "precision": 0.9})
        + "\n"
    )

    rows = load_trend_log(path)

    assert rows == [
        {"suite": "correctness_prb", "precision": 1.0},
        {"suite": "correctness_e2e", "precision": 0.9},
    ]


def test_load_trend_log_missing_file_returns_empty(tmp_path: Path) -> None:
    rows = load_trend_log(tmp_path / "does_not_exist.jsonl")

    assert rows == []
