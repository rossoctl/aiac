"""Unit tests for ``dashboard.py`` (spec: issue #2542 — eval results dashboard).

Pure-logic + file I/O against tmp paths, unmarked (runs in the default fast pass; ``testpaths``
already includes ``eval/``). No LLM, no Keycloak, no live pytest run.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

import pytest

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


def test_parse_report_extracts_passing_robustness_mechanical_entry(tmp_path: Path) -> None:
    """A robustness sensitivity-tier entry gets its own
    `suite="robustness_mechanical_sensitivity"` -- confirming the fix for #2466's report: before
    it, every robustness nodeid fell through to `suite=None` and was silently dropped from the
    drill-down table entirely (see `test_render_scenario_table_includes_robustness_entries`
    below)."""
    body = (
        "## passed (1)\n\n"
        "### `eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[baseline]`\n"
        "- **Perturbation:** negation: 'X.' -> 'Not X.'\n"
        "- **Expected grants:** outbound_subject: (a, b)\n"
        "- **Actual grants:** outbound_subject: (a, b)\n"
        "- **Precision:** 1.000\n"
        "- **Recall:** 1.000\n"
        "- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:** none\n"
        "- **Incorrectly denied:** none\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    entry = report.entries[0]
    assert entry.suite == "robustness_mechanical_sensitivity"
    assert entry.scenario == "baseline"
    assert entry.precision == 1.0


def test_parse_report_semantic_robustness_entries_get_their_own_suites(tmp_path: Path) -> None:
    """The semantic-tier invariance and sensitivity tests each feed the trend log under their own
    suite (`robustness_semantic_invariance`/`robustness_semantic_sensitivity`, mirroring
    `eval/conftest.py`'s `_ROBUSTNESS_TEST_MARKERS`) -- confirming their drill-down entries link up
    with their trend-log rows instead of falling through to a mismatched or missing suite label."""
    body = (
        "## passed (2)\n\n"
        "### `eval/test_policy_pipeline_robustness.py::test_prb_invariant_to_semantic_perturbation[baseline]`\n"
        "- **Precision:** 1.000\n"
        "- **Recall:** 1.000\n"
        "- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:** none\n"
        "- **Incorrectly denied:** none\n\n"
        "### `eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_semantic_perturbation[baseline]`\n"
        "- **Precision:** 1.000\n"
        "- **Recall:** 1.000\n"
        "- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:** none\n"
        "- **Incorrectly denied:** none\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    assert report.entries[0].suite == "robustness_semantic_invariance"
    assert report.entries[1].suite == "robustness_semantic_sensitivity"


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


def test_render_svg_chart_plots_a_non_correctness_metric_shape() -> None:
    """The chart must be generic over metric *names*, not hardcoded to precision/recall/
    denial_precision -- a robustness_mechanical_invariance row (precision/recall/denial_precision
    plus its own invariance_rate) plotted the same way, with zero blank/empty series. Regression
    test for the bug where such a row rendered an empty chart (every hardcoded metric key was
    absent, so `_METRIC_COLORS` found nothing)."""
    rows = [
        {
            "suite": "robustness_mechanical_invariance",
            "timestamp": "2026-09-15T13:40:04+00:00",
            "run_type": "regression",
            "model": "m1",
            "scenarios_scored": 8,
            "precision": 1.0,
            "recall": 0.9,
            "denial_precision": 0.95,
            "invariance_rate": 0.75,
        }
    ]

    svg = render_svg_chart(rows, reports=[], suite="robustness_mechanical_invariance")

    assert svg.count("<circle") == 4  # one per metric, this suite has four
    assert "precision" in svg
    assert "recall" in svg
    assert "denial_precision" in svg
    assert "invariance_rate" in svg
    # Bookkeeping fields must never be treated as plottable metrics.
    assert "scenarios_scored" not in svg
    assert "run_type" not in svg


def test_render_svg_chart_polyline_skips_a_missing_metric_instead_of_plotting_zero() -> None:
    rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        },
        {
            # A future suite's row missing denial_precision entirely -- should be a gap in that
            # metric's line, not a dip to 0.
            "suite": "correctness_prb",
            "timestamp": "2026-09-11T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
        },
    ]

    svg = render_svg_chart(rows, reports=[], suite="correctness_prb")

    polylines = re.findall(r'<polyline points="([^"]+)"', svg)
    precision_points, recall_points, denial_points = polylines
    assert len(precision_points.split()) == 2
    assert len(recall_points.split()) == 2
    assert len(denial_points.split()) == 1  # only the first row -- no plotted point for row 2


def test_render_svg_chart_tooltip_is_structured_multiline() -> None:
    rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "model": "Azure/gpt-5-mini-2025-08-07",
            "precision": 1.0,
            "recall": 0.9,
            "denial_precision": 0.957,
        }
    ]

    svg = render_svg_chart(rows, reports=[], suite="correctness_prb")

    expected_title = (
        "Datetime = 2026-09-10T07:00:00+00:00\n"
        "LLM = Azure/gpt-5-mini-2025-08-07\n"
        "precision = 1.0\n"
        "recall = 0.9\n"
        "denial_precision = 0.957"
    )
    assert f"<title>{expected_title}</title>" in svg


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


def test_render_svg_chart_has_y_axis_value_labels_and_x_axis_date_labels() -> None:
    rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        },
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-14T06:53:44+00:00",
            "precision": 0.8,
            "recall": 0.9,
            "denial_precision": 0.95,
        },
    ]

    svg = render_svg_chart(rows, reports=[], suite="correctness_prb")

    assert "0.00" in svg  # y-axis low-end label
    assert "1.00" in svg  # y-axis high-end label
    assert "2026-09-10" in svg  # x-axis date label for the first row
    assert "2026-09-14" in svg  # x-axis date label for the second row


def test_render_dashboard_uses_dark_theme_colors() -> None:
    page = render_dashboard([], [])

    assert "#121212" in page  # dark background
    assert "#e8eaed" in page  # bright text


def test_render_scenario_table_lists_correctness_entries_anchored_for_chart_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("eval.dashboard._EXPECTED_SCENARIO_COUNT", 1)  # one-entry fixture below
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


def test_render_scenario_table_summary_names_file_and_suite_not_raw_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The summary line leads with the report filename and names which suite ran, in parentheses
    -- e.g. ``report_x.md (correctness_prb suite)`` -- rather than the raw ``run_at`` ISO
    timestamp, which was redundant with the report's own filename/sort order."""
    monkeypatch.setattr("eval.dashboard._EXPECTED_SCENARIO_COUNT", 1)  # one-entry fixture below
    entry = ScenarioEntry(
        nodeid="eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[baseline]",
        suite="correctness_prb",
        scenario="baseline",
        category="passed",
    )
    report = ParsedReport(
        path=Path("report_16_09_15_41_20.md"),
        run_at=datetime.fromisoformat("2026-09-16T15:41:20.889219+00:00"),
        entries=[entry],
    )

    table = render_scenario_table(report)

    assert "<summary>report_16_09_15_41_20.md (correctness_prb suite)</summary>" in table
    assert "2026-09-16T15:41:20" not in table


def test_render_scenario_table_summary_lists_multiple_suites(monkeypatch: pytest.MonkeyPatch) -> None:
    """A report with entries from more than one suite names all of them, pluralized."""
    monkeypatch.setattr("eval.dashboard._EXPECTED_SCENARIO_COUNT", 1)  # one entry per suite below
    entries = [
        ScenarioEntry(
            nodeid="eval/test_policy_pipeline_robustness.py::test_prb_invariant_to_mechanical_perturbation[baseline]",
            suite="robustness_mechanical_invariance",
            scenario="baseline",
            category="passed",
        ),
        ScenarioEntry(
            nodeid="eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[baseline]",
            suite="robustness_mechanical_sensitivity",
            scenario="baseline",
            category="passed",
        ),
    ]
    report = ParsedReport(
        path=Path("report_x.md"), run_at=datetime.fromisoformat("2026-09-10T07:00:00+00:00"), entries=entries
    )

    table = render_scenario_table(report)

    assert (
        "<summary>report_x.md (robustness_mechanical_invariance, robustness_mechanical_sensitivity suites)</summary>"
        in table
    )


def test_render_scenario_table_includes_robustness_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression test for the bug where a report with *only* robustness entries rendered as an
    empty string and vanished from the drill-down entirely, because `_suite_for_nodeid` recognized
    no robustness nodeid pattern and every entry's `suite` stayed `None`."""
    monkeypatch.setattr("eval.dashboard._EXPECTED_SCENARIO_COUNT", 1)  # one-entry fixture below
    entry = ScenarioEntry(
        nodeid="eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[baseline]",
        suite="robustness_mechanical_sensitivity",
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

    assert table != ""
    assert "robustness_mechanical_sensitivity" in table
    assert "baseline" in table


def test_render_scenario_table_distinguishes_mechanical_invariant_and_sensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two mechanical-tier test functions each write their own trend-log suite now
    (`robustness_mechanical_invariance`/`robustness_mechanical_sensitivity`), so the drill-down
    table's Suite column tells the two families apart from `entry.suite` alone -- no separate
    display-name override needed."""
    monkeypatch.setattr("eval.dashboard._EXPECTED_SCENARIO_COUNT", 1)  # one entry per suite below
    body = (
        "## passed (2)\n\n"
        "### `eval/test_policy_pipeline_robustness.py::test_prb_invariant_to_mechanical_perturbation[baseline]`\n"
        "- **Precision:** 1.000\n"
        "- **Recall:** 1.000\n"
        "- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:** none\n"
        "- **Incorrectly denied:** none\n\n"
        "### `eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[baseline]`\n"
        "- **Precision:** 1.000\n"
        "- **Recall:** 1.000\n"
        "- **Denial precision:** 1.000\n"
        "- **Over-grants:** none\n"
        "- **Under-grants:** none\n"
        "- **Incorrectly denied:** none\n\n"
    )
    path = _write_report(tmp_path, body)

    report = parse_report(path)

    invariant_entry, sensitive_entry = report.entries
    assert invariant_entry.suite == "robustness_mechanical_invariance"
    assert sensitive_entry.suite == "robustness_mechanical_sensitivity"

    table = render_scenario_table(report)

    assert "robustness_mechanical_invariance" in table
    assert "robustness_mechanical_sensitivity" in table


def test_render_scenario_table_escapes_html_and_preserves_multiline_breaks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("eval.dashboard._EXPECTED_SCENARIO_COUNT", 1)  # one-entry fixture below
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


def test_render_scenario_table_excludes_a_suite_with_fewer_than_the_full_corpus() -> None:
    """A suite with only 1 of the expected 8 scenario entries in this report (a `-k`-filtered
    debug run) is dropped from the drill-down entirely, at the real, unpatched
    ``_EXPECTED_SCENARIO_COUNT``."""
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

    assert render_scenario_table(report) == ""


def test_render_scenario_table_keeps_a_full_suite_but_drops_a_partial_one_in_the_same_report() -> None:
    """One report can mix a full run of one suite with a partial run of another (e.g.
    `-k baseline` touching both mechanical robustness test functions for just one scenario) --
    only the full suite's entries survive."""
    full_suite_entries = [
        ScenarioEntry(
            nodeid=f"eval/test_policy_pipeline_correctness_prb.py::test_prb_correctness[{name}]",
            suite="correctness_prb",
            scenario=name,
            category="passed",
            precision=1.0,
            recall=1.0,
            denial_precision=1.0,
        )
        for name in (
            "baseline",
            "agent_delegation",
            "unreachable_resources",
            "ambiguous_clause",
            "wildcard_grant",
            "misleading_descriptions",
            "confusable_agents",
            "empty_descriptions",
        )
    ]
    partial_suite_entry = ScenarioEntry(
        nodeid="eval/test_policy_pipeline_robustness.py::test_prb_sensitive_to_mechanical_edit[baseline]",
        suite="robustness_mechanical_sensitivity",
        scenario="baseline",
        category="passed",
        precision=1.0,
        recall=1.0,
        denial_precision=1.0,
    )
    report = ParsedReport(
        path=Path("report_x.md"),
        run_at=datetime.fromisoformat("2026-09-10T07:00:00+00:00"),
        entries=full_suite_entries + [partial_suite_entry],
    )

    table = render_scenario_table(report)

    assert "correctness_prb" in table
    assert "robustness_mechanical_sensitivity" not in table


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


def test_render_dashboard_chart_excludes_partial_runs() -> None:
    """A `-k`-filtered single-scenario debug row (`run_type="partial"`) must not appear on the
    chart alongside real full-corpus regression rows -- it pools far fewer scenarios and would
    otherwise show up as an unlabeled outlier indistinguishable from a genuine regression."""
    trend_rows = [
        {
            "suite": "correctness_prb",
            "run_type": "regression",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        },
        {
            "suite": "correctness_prb",
            "run_type": "partial",
            "timestamp": "2026-09-11T07:00:00+00:00",
            "precision": 0.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        },
    ]

    html = render_dashboard(trend_rows, [])

    assert "2026-09-10" in html
    assert "2026-09-11" not in html


def test_render_dashboard_chart_includes_row_with_no_run_type_field() -> None:
    """A row written before `run_type` existed (or a hand-built test row) has no `run_type` key at
    all -- must still be treated as a full run, not silently dropped."""
    trend_rows = [
        {
            "suite": "correctness_prb",
            "timestamp": "2026-09-10T07:00:00+00:00",
            "precision": 1.0,
            "recall": 1.0,
            "denial_precision": 1.0,
        }
    ]

    html = render_dashboard(trend_rows, [])

    assert "2026-09-10" in html


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


def test_load_trend_log_skips_a_line_that_fails_to_parse(tmp_path: Path) -> None:
    path = tmp_path / "trend_log.jsonl"
    path.write_text(
        json.dumps({"suite": "correctness_prb", "precision": 1.0})
        + "\n"
        + "not valid json, e.g. a truncated final line\n"
        + json.dumps({"suite": "correctness_e2e", "precision": 0.9})
        + "\n"
    )

    rows = load_trend_log(path)

    assert rows == [
        {"suite": "correctness_prb", "precision": 1.0},
        {"suite": "correctness_e2e", "precision": 0.9},
    ]
