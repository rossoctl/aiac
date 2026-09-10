"""Static eval results dashboard — scenario drill-down + historical trend charts (issue #2542).

Renders entirely from the artifacts ``eval/trend_log.py``/``eval/conftest.py`` (#2091) already
produce — the committed, append-only ``eval/trend_log.jsonl`` and the gitignored per-run
``eval/reports/report_<timestamp>.md`` — no new data source, no CI wiring, no server. A single
self-contained HTML file (inline SVG, inline CSS, no external requests) a developer regenerates
locally after an eval run.

Two artifacts, two read paths: ``load_trend_log`` reads the committed trend log; ``parse_report``/
``parse_reports`` re-derive structured scenario data from the Markdown report(s) ``eval/conftest.py``
already writes, mirroring that module's own render logic (``_render_entry``/``_render_metrics_block``/
``_render_field``) in reverse. The two are stitched together only for the drill-down link (see
``_find_matching_report``) — the trend chart itself needs only the former.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from eval.trend_log import DEFAULT_PATH as TREND_LOG_DEFAULT_PATH

HERE = Path(__file__).resolve().parent


def load_trend_log(path: Path = TREND_LOG_DEFAULT_PATH) -> list[dict[str, Any]]:
    """Read the committed trend log's rows, oldest first. ``[]`` if the file doesn't exist yet
    (a fresh checkout before any suite has ever run)."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# Nodeid substring -> trend-log suite name, the inverse of ``eval/conftest.py``'s
# ``_CORRECTNESS_TEST_MARKERS``/``_TREND_LOG_SUITES``. A non-correctness entry (``eval_extended``'s
# ``test_inbound``/``test_outbound``, ``eval_consistency``, ``eval_robustness``) matches neither, so
# ``suite`` stays ``None`` -- captured for the drill-down table but excluded from any trend chart,
# since only the two Correctness suites write trend-log rows today.
_SUITE_BY_NODEID_MARKER = {
    "::test_prb_correctness[": "correctness_prb",
    "::test_e2e_correctness[": "correctness_e2e",
}

_RUN_RE = re.compile(r"^Run: (.+)$")
_HEADING_RE = re.compile(r"^## (\w+) \(\d+\)$")
_ENTRY_RE = re.compile(r"^### `(.+)`$")
_BULLET_RE = re.compile(r"^- \*\*(.+?):\*\*\s?(.*)$")
_SCENARIO_RE = re.compile(r"\[([^\[\]]+)\]$")

# Bullet label -> ScenarioEntry field name, mirroring the labels ``eval/conftest.py``'s
# ``_render_metrics_block``/``_render_entry`` write. "What it tests"/"Failure"/"Reason" are handled
# separately in ``_assign_field`` (they map to differently-named attributes).
_LABEL_FIELDS = {
    "Precision": "precision",
    "Recall": "recall",
    "Denial precision": "denial_precision",
    "Over-grants": "over_grants",
    "Under-grants": "under_grants",
    "Incorrectly denied": "incorrectly_denied",
}
_FLOAT_FIELDS = {"precision", "recall", "denial_precision"}


@dataclass
class ScenarioEntry:
    """One ``### \\`nodeid\\``` entry from a per-run Markdown report (``eval/conftest.py``'s
    ``_render_entry``). ``suite``/``scenario`` are ``None`` for a non-correctness-suite entry.
    ``precision``/``recall``/``denial_precision`` are ``None`` when the scenario's own setup failed
    before scoring ever ran (``_render_metrics_block``'s ``unavailable_reason`` branch)."""

    nodeid: str
    suite: str | None = None
    scenario: str | None = None
    category: str = ""
    what_it_tests: str | None = None
    precision: float | None = None
    recall: float | None = None
    denial_precision: float | None = None
    over_grants: str = "none"
    under_grants: str = "none"
    incorrectly_denied: str = "none"
    failure: str | None = None


@dataclass
class ParsedReport:
    path: Path
    run_at: datetime
    entries: list[ScenarioEntry] = field(default_factory=list)


def _suite_for_nodeid(nodeid: str) -> str | None:
    for marker, suite in _SUITE_BY_NODEID_MARKER.items():
        if marker in nodeid:
            return suite
    return None


def _scenario_for_nodeid(nodeid: str) -> str | None:
    m = _SCENARIO_RE.search(nodeid)
    return m.group(1) if m else None


def _parse_metric(value: str) -> float | None:
    """``value`` is a float string (``"1.000"``) or the ``"unavailable — ..."`` placeholder
    ``_render_metrics_block`` writes for a scenario whose setup failed before scoring ran."""
    if value.startswith("unavailable"):
        return None
    return float(value)


def _assign_field(entry: ScenarioEntry, label: str, value: str) -> None:
    if label == "What it tests":
        entry.what_it_tests = value
    elif label in ("Failure", "Reason"):
        entry.failure = value
    elif label in _LABEL_FIELDS:
        field_name = _LABEL_FIELDS[label]
        setattr(entry, field_name, _parse_metric(value) if field_name in _FLOAT_FIELDS else value)


def parse_report(path: Path) -> ParsedReport:
    """Re-derive structured per-scenario data from one ``eval/reports/report_<timestamp>.md`` file,
    mirroring ``eval/conftest.py``'s render logic in reverse (see module docstring)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    run_at: datetime | None = None
    category = ""
    entries: list[ScenarioEntry] = []
    entry: ScenarioEntry | None = None
    pending_label: str | None = None
    fenced_lines: list[str] = []

    i, n = 0, len(lines)
    while i < n:
        line = lines[i]

        if pending_label is not None:
            if line.strip() == "```":
                if entry is not None:
                    _assign_field(entry, pending_label, "\n".join(fenced_lines))
                pending_label, fenced_lines = None, []
            else:
                fenced_lines.append(line[2:] if line.startswith("  ") else line)
            i += 1
            continue

        if run_m := _RUN_RE.match(line):
            run_at = datetime.fromisoformat(run_m.group(1))
        elif heading_m := _HEADING_RE.match(line):
            category = heading_m.group(1)
        elif entry_m := _ENTRY_RE.match(line):
            nodeid = entry_m.group(1)
            suite = _suite_for_nodeid(nodeid)
            entry = ScenarioEntry(
                nodeid=nodeid,
                suite=suite,
                # Only meaningful for a correctness-suite entry -- the bracket for any other
                # suite's nodeid (e.g. eval_extended's ``test_inbound[scenario-agent-subject]``)
                # is a different, non-scenario parametrize id.
                scenario=_scenario_for_nodeid(nodeid) if suite is not None else None,
                category=category,
            )
            entries.append(entry)
        elif bullet_m := _BULLET_RE.match(line):
            label, value = bullet_m.group(1), bullet_m.group(2)
            if value == "" and i + 1 < n and lines[i + 1].strip() == "```":
                pending_label, fenced_lines = label, []
                i += 1  # skip the opening ``` fence too
            elif entry is not None:
                _assign_field(entry, label, value)
        i += 1

    if run_at is None:
        raise ValueError(f"{path}: no 'Run:' line found")
    return ParsedReport(path=path, run_at=run_at, entries=entries)


def parse_reports(reports_dir: Path) -> list[ParsedReport]:
    """Parse every ``report_*.md`` under ``reports_dir``, oldest first. A file that fails to parse
    (partial write, unrelated content) is skipped rather than crashing the whole dashboard build."""
    reports: list[ParsedReport] = []
    if not reports_dir.exists():
        return reports
    for path in sorted(reports_dir.glob("report_*.md")):
        try:
            reports.append(parse_report(path))
        except ValueError:
            continue
    reports.sort(key=lambda r: r.run_at)
    return reports


# Both timestamps come from separate ``datetime.now()`` calls inside the same
# ``pytest_sessionfinish`` (``eval/conftest.py``'s ``_write_trend_log`` then its own report-writing
# code), normally sub-second apart. The window is generous only to guard against matching a trend
# row to a stale, unrelated report once the real one has since been deleted from the gitignored
# ``eval/reports/`` dir -- not because the two clocks can plausibly drift by hours.
_MATCH_TOLERANCE = timedelta(hours=6)


def _find_matching_report(row: dict[str, Any], reports: list[ParsedReport]) -> ParsedReport | None:
    """The parsed report that is this trend-log row's likely evidence, or ``None`` if no
    same-suite report is within tolerance (the chart point still renders, just without a
    drill-down link)."""
    row_time = datetime.fromisoformat(row["timestamp"])
    best: ParsedReport | None = None
    best_delta: timedelta | None = None
    for report in reports:
        if not any(e.suite == row.get("suite") for e in report.entries):
            continue
        delta = abs(report.run_at - row_time)
        if delta > _MATCH_TOLERANCE:
            continue
        if best_delta is None or delta < best_delta:
            best, best_delta = report, delta
    return best


def _report_anchor(report: ParsedReport) -> str:
    """HTML ``id`` for this report's drill-down section -- unique per run, stable across
    re-renders of the same report file (derived from ``run_at``, not the filename)."""
    return "run-" + report.run_at.strftime("%Y%m%dT%H%M%SZ")


# Metric -> (line/point color, CSS class). One polyline + one point series per metric, all three
# always plotted together since every correctness-suite trend-log row carries all three (see
# eval/trend_log.py's pool_correctness_metrics) -- a future suite with a different metric shape
# gets its own dict here when it starts writing trend-log rows (dashboard.py's caller loop is
# already generic over `suite`; only this mapping is correctness-specific today).
_METRIC_COLORS = {
    "precision": "#4c72b0",
    "recall": "#55a868",
    "denial_precision": "#c44e52",
}


def render_svg_chart(rows: list[dict[str, Any]], reports: list[ParsedReport], *, suite: str) -> str:
    """One inline, self-contained ``<svg>`` line chart for one suite's trend-log rows (already
    filtered to that suite by the caller) -- precision/recall/denial_precision plotted as three
    polylines with per-row points. A point is wrapped in a link to its matching evidence report
    (see ``_find_matching_report``) when one is found within tolerance; every point always carries
    a ``<title>`` tooltip with the exact values regardless."""
    width, height, pad = 640, 220, 30
    n = len(rows)

    def x(i: int) -> float:
        return pad if n <= 1 else pad + i * (width - 2 * pad) / (n - 1)

    def y(value: float) -> float:
        return height - pad - value * (height - 2 * pad)

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{suite} trend chart">']
    for metric, color in _METRIC_COLORS.items():
        points = " ".join(f"{x(i):.1f},{y(row.get(metric) or 0):.1f}" for i, row in enumerate(rows))
        parts.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" />')

    for i, row in enumerate(rows):
        match = _find_matching_report(row, reports)
        title = html.escape(
            f"{row.get('timestamp', '')} · {row.get('model', '')} · "
            f"precision={row.get('precision')} recall={row.get('recall')} "
            f"denial_precision={row.get('denial_precision')}"
        )
        for metric, color in _METRIC_COLORS.items():
            value = row.get(metric)
            if value is None:
                continue
            circle = f'<circle cx="{x(i):.1f}" cy="{y(value):.1f}" r="3" fill="{color}"><title>{title}</title></circle>'
            if match is not None:
                circle = f'<a href="#{_report_anchor(match)}">{circle}</a>'
            parts.append(circle)
    parts.append("</svg>")

    legend = "".join(
        f'<span class="legend-item"><span class="legend-swatch" style="background:{color}"></span>{metric}</span>'
        for metric, color in _METRIC_COLORS.items()
    )
    parts.append(f'<div class="legend">{legend}</div>')
    return "".join(parts)


def _fmt_metric(value: float | None) -> str:
    return f"{value:.3f}" if value is not None else "—"


def _escape_cell(text: str) -> str:
    """Escape free text pulled from a report file before embedding it in HTML -- a scenario's
    over/under-grant pair listing or crash message is arbitrary content (role/scope names, or an
    LLM's best-effort-proposal reasoning text) this module didn't generate, not markup. ``\\n``
    (multi-gate breakdowns, see ``eval/conftest.py``'s ``_format_pairs_dict``) becomes ``<br>``
    *after* escaping so a literal ``<`` in the source text can't smuggle in a real line break."""
    return html.escape(text).replace("\n", "<br>")


def render_scenario_table(report: ParsedReport) -> str:
    """One collapsible, anchored drill-down section for a parsed report's correctness-suite
    entries. ``""`` when the report has none (e.g. an ``eval_extended``-only run) -- nothing for
    ``render_dashboard`` to show for that report."""
    correctness_entries = [e for e in report.entries if e.suite is not None]
    if not correctness_entries:
        return ""
    rows_html = "".join(
        "<tr>"
        f"<td>{_escape_cell(e.suite or '')}</td><td>{_escape_cell(e.scenario or '')}</td><td>{_escape_cell(e.category)}</td>"
        f"<td>{_fmt_metric(e.precision)}</td><td>{_fmt_metric(e.recall)}</td><td>{_fmt_metric(e.denial_precision)}</td>"
        f"<td>{_escape_cell(e.over_grants)}</td><td>{_escape_cell(e.under_grants)}</td><td>{_escape_cell(e.incorrectly_denied)}</td>"
        "</tr>"
        for e in correctness_entries
    )
    return (
        f'<details id="{_report_anchor(report)}">'
        f"<summary>{html.escape(report.run_at.isoformat())} — {html.escape(report.path.name)}</summary>"
        "<table><thead><tr>"
        "<th>Suite</th><th>Scenario</th><th>Category</th><th>Precision</th><th>Recall</th>"
        "<th>Denial precision</th><th>Over-grants</th><th>Under-grants</th><th>Incorrectly denied</th>"
        f"</tr></thead><tbody>{rows_html}</tbody></table></details>"
    )


_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
table { border-collapse: collapse; margin: 0.5rem 0 1.5rem; width: 100%; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; font-size: 0.85rem; }
.legend { margin-top: 0.25rem; }
.legend-item { margin-right: 1rem; font-size: 0.85rem; }
.legend-swatch { display: inline-block; width: 10px; height: 10px; margin-right: 4px; }
details { margin-bottom: 0.5rem; }
"""


def render_dashboard(trend_rows: list[dict[str, Any]], reports: list[ParsedReport]) -> str:
    """The full static dashboard page: one trend chart per suite present in ``trend_rows``
    (generic over suite name -- not hardcoded to the two Correctness suites, so a future suite
    gets its own chart the moment it starts writing trend-log rows), then one scenario drill-down
    section per parsed report."""
    suites = sorted({row["suite"] for row in trend_rows if "suite" in row})
    if suites:
        chart_sections = "".join(
            f"<section><h3>{suite}</h3>"
            + render_svg_chart([row for row in trend_rows if row.get("suite") == suite], reports, suite=suite)
            + "</section>"
            for suite in suites
        )
    else:
        chart_sections = "<p>No trend-log rows yet — run an eval suite to populate eval/trend_log.jsonl.</p>"

    tables = "".join(render_scenario_table(report) for report in reports)
    drilldown_sections = (
        tables if tables else "<p>No per-run reports found under eval/reports/ — run an eval suite to generate one.</p>"
    )

    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>AIAC eval dashboard</title>"
        f"<style>{_STYLE}</style></head><body>"
        "<h1>AIAC eval results dashboard</h1>"
        "<h2>Historical trends</h2>"
        f"{chart_sections}"
        "<h2>Scenario drill-down</h2>"
        f"{drilldown_sections}"
        "</body></html>"
    )


def build_dashboard(
    trend_log_path: Path = TREND_LOG_DEFAULT_PATH,
    reports_dir: Path = HERE / "reports",
    output_path: Path = HERE / "dashboard.html",
) -> Path:
    """Load the trend log + every per-run report, render the dashboard, write it to
    ``output_path``, and return that path."""
    trend_rows = load_trend_log(trend_log_path)
    reports = parse_reports(reports_dir)
    html = render_dashboard(trend_rows, reports)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def main() -> None:
    path = build_dashboard()
    print(f"Eval dashboard written to {path}")


if __name__ == "__main__":
    main()
