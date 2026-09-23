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
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from eval.trend_log import DEFAULT_PATH as TREND_LOG_DEFAULT_PATH

HERE = Path(__file__).resolve().parent


def load_trend_log(path: Path = TREND_LOG_DEFAULT_PATH) -> list[dict[str, Any]]:
    """Read the committed trend log's rows, oldest first. ``[]`` if the file doesn't exist yet
    (a fresh checkout before any suite has ever run). A line that fails to parse (a truncated
    final write, a stray merge-conflict marker) is skipped rather than crashing the whole
    dashboard build -- same defensive posture as ``parse_reports`` takes for report files."""
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# Nodeid substring -> suite label for the drill-down table's "Suite" column, the inverse of
# ``eval/conftest.py``'s ``_CORRECTNESS_TEST_MARKERS``/``_ROBUSTNESS_TEST_MARKERS``. Every value
# matches an actual trend-log `suite` (so a matching row can link to this report's drill-down
# section, see ``_find_matching_report``) -- each of the four robustness tier x family
# combinations (mechanical/semantic x invariance/sensitivity) gets its own suite name, one per
# trend-log row/chart, so no separate display-name override is needed to tell them apart. A
# nodeid matching neither pattern (``eval_extended``'s ``test_inbound``/``test_outbound``, the
# consistency/faithfulness suites) still gets `suite=None` and is left out of this table -- a
# pre-existing gap this fix doesn't extend to, since it wasn't reported.
_SUITE_BY_NODEID_MARKER = {
    "::test_prb_correctness[": "correctness_prb",
    "::test_e2e_correctness[": "correctness_e2e",
    "::test_prb_invariant_to_mechanical_perturbation[": "robustness_mechanical_invariance",
    "::test_prb_sensitive_to_mechanical_edit[": "robustness_mechanical_sensitivity",
    "::test_prb_invariant_to_semantic_perturbation[": "robustness_semantic_invariance",
    "::test_prb_sensitive_to_semantic_perturbation[": "robustness_semantic_sensitivity",
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


# Full Correctness/Robustness corpus size (eval.test_policy_pipeline_eval.SCENARIOS) -- the same
# value as eval/conftest.py's own _EXPECTED_SCENARIO_COUNT, kept as a separate plain constant
# rather than imported so this module stays a self-contained, dependency-light tool (see the
# module docstring). Bump alongside conftest.py's copy if the corpus grows.
_EXPECTED_SCENARIO_COUNT = 8


def _full_suites(report: ParsedReport) -> set[str]:
    """The suites within ``report`` that have at least ``_EXPECTED_SCENARIO_COUNT`` *scored*
    entries (``e.precision is not None`` -- see ``render_scenario_table``'s docstring for why that's
    the same thing ``eval/conftest.py``'s ``_write_trend_log`` counts) -- exactly the suites
    ``render_scenario_table`` actually renders a row for. Shared with ``_find_matching_report`` so a
    trend-log row never links to a report where its own suite's entries would be filtered out as
    partial -- matching by suite *presence* alone (the previous behavior) could link a genuine
    full-corpus chart point to a `-k`-filtered debug report that happens to fall within the match
    tolerance, landing the link on a section listing none of that suite's scenarios, or on no
    section at all if every suite in that report is partial."""
    scored = [e for e in report.entries if e.suite is not None and e.precision is not None]
    counts = Counter(e.suite for e in scored)
    return {suite for suite, count in counts.items() if count >= _EXPECTED_SCENARIO_COUNT}


# Both timestamps come from separate ``datetime.now()`` calls inside the same
# ``pytest_sessionfinish`` (``eval/conftest.py``'s ``_write_trend_log`` then its own report-writing
# code), normally sub-second apart. The window is generous only to guard against matching a trend
# row to a stale, unrelated report once the real one has since been deleted from the gitignored
# ``eval/reports/`` dir -- not because the two clocks can plausibly drift by hours.
_MATCH_TOLERANCE = timedelta(hours=6)


def _find_matching_report(row: dict[str, Any], reports: list[ParsedReport]) -> ParsedReport | None:
    """The parsed report that is this trend-log row's likely evidence, or ``None`` if no
    same-suite report is within tolerance (the chart point still renders, just without a
    drill-down link). Only a report where the row's suite is actually full (``_full_suites``)
    counts -- otherwise the link would land on a section with none of that suite's scenarios, or on
    no section at all."""
    row_time = datetime.fromisoformat(row["timestamp"])
    best: ParsedReport | None = None
    best_delta: timedelta | None = None
    for report in reports:
        if row.get("suite") not in _full_suites(report):
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


# Bookkeeping keys every trend-log row carries (eval/trend_log.py's `append_row`, plus
# `scenarios_scored` that every pooling function adds) that are never themselves a plottable
# metric -- everything else on a row is one, whatever the suite. This is what actually makes the
# chart generic over suite (each suite's own `eval/conftest.py` call site decides its row's metric
# *names* -- e.g. `pool_correctness_metrics`'s precision/recall/denial_precision, reused as-is by
# both Correctness suites and both Robustness families, plus whatever else that call site mixes in
# (a family's own invariance_rate/sensitivity_rate); this module never hardcodes any of them).
_ROW_BOOKKEEPING_KEYS = {"timestamp", "suite", "run_type", "model", "scenarios_scored"}

# Fixed palette metrics are assigned from, in first-seen order, so the same metric name gets the
# same color across repeated calls/renders for one suite. Cycles if a suite ever reports more
# metrics than colors (unlikely: no suite has needed more than 3 so far).
_METRIC_PALETTE = ["#8ab4f8", "#81c995", "#f28b82", "#fdd663", "#c58af9", "#78d9ec"]

_AXIS_COLOR = "#9aa0a6"  # legible against the dark chart background, but not competing with the
# brighter per-metric colors above.


def _metric_colors(rows: list[dict[str, Any]]) -> dict[str, str]:
    """Discover every metric key actually present across ``rows`` (first-seen order, skipping
    ``_ROW_BOOKKEEPING_KEYS`` and any non-numeric value) and assign each a stable palette color."""
    names: list[str] = []
    for row in rows:
        for key, value in row.items():
            if key in _ROW_BOOKKEEPING_KEYS or key in names:
                continue
            if isinstance(value, (int, float)):
                names.append(key)
    return {name: _METRIC_PALETTE[i % len(_METRIC_PALETTE)] for i, name in enumerate(names)}


def render_svg_chart(rows: list[dict[str, Any]], reports: list[ParsedReport], *, suite: str) -> str:
    """One inline, self-contained ``<svg>`` line chart for one suite's trend-log rows (already
    filtered to that suite by the caller) -- every numeric metric actually present on these rows
    (see ``_metric_colors``) plotted as its own polyline with per-row points, against a labeled 0-1
    y-axis and a per-row date x-axis. A point is wrapped in a link to its matching evidence report
    (see ``_find_matching_report``) when one is found within tolerance; every point always carries
    a ``<title>`` tooltip with the exact values regardless."""
    width, height = 640, 260
    pad_left, pad_right, pad_top, pad_bottom = 45, 15, 15, 55
    n = len(rows)
    metric_colors = _metric_colors(rows)

    def x(i: int) -> float:
        return pad_left if n <= 1 else pad_left + i * (width - pad_left - pad_right) / (n - 1)

    def y(value: float) -> float:
        return height - pad_bottom - value * (height - pad_top - pad_bottom)

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{suite} trend chart">']

    # Y-axis: gridline + value label every 0.25, spanning the full plot width.
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        ty = y(tick)
        parts.append(
            f'<line x1="{pad_left}" y1="{ty:.1f}" x2="{width - pad_right}" y2="{ty:.1f}" stroke="{_AXIS_COLOR}" stroke-width="0.5" stroke-dasharray="2,2" />'
        )
        parts.append(
            f'<text x="{pad_left - 6}" y="{ty:.1f}" fill="{_AXIS_COLOR}" font-size="10" text-anchor="end" dominant-baseline="middle">{tick:.2f}</text>'
        )

    # X-axis: tick + rotated date label per row (the date portion of its ISO timestamp).
    axis_y = height - pad_bottom
    parts.append(
        f'<line x1="{pad_left}" y1="{axis_y:.1f}" x2="{width - pad_right}" y2="{axis_y:.1f}" stroke="{_AXIS_COLOR}" stroke-width="1" />'
    )
    for i, row in enumerate(rows):
        date_label = str(row.get("timestamp", ""))[:10]
        tx = x(i)
        parts.append(
            f'<line x1="{tx:.1f}" y1="{axis_y:.1f}" x2="{tx:.1f}" y2="{axis_y + 4:.1f}" stroke="{_AXIS_COLOR}" stroke-width="1" />'
        )
        parts.append(
            f'<text x="{tx:.1f}" y="{axis_y + 8:.1f}" fill="{_AXIS_COLOR}" font-size="10" '
            f'text-anchor="end" transform="rotate(-40 {tx:.1f} {axis_y + 8:.1f})">{html.escape(date_label)}</text>'
        )

    for metric, color in metric_colors.items():
        # Skip a row missing this metric entirely -- same as the circle loop below -- so the line
        # doesn't dip to 0 for a gap; it just connects the rows that do carry the metric.
        coords = [(x(i), y(row[metric])) for i, row in enumerate(rows) if row.get(metric) is not None]
        if not coords:
            continue
        points = " ".join(f"{px:.1f},{py:.1f}" for px, py in coords)
        parts.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" />')

    for i, row in enumerate(rows):
        match = _find_matching_report(row, reports)
        # A newline inside an SVG <title> renders as a real line break in the browser's native
        # hover tooltip -- no separate tooltip widget/JS needed for a structured, multi-line view.
        # Generic over metric: every key this suite's row actually carries, not a fixed set of three.
        title_lines = [f"Datetime = {row.get('timestamp', '')}", f"LLM = {row.get('model', '')}"]
        title_lines.extend(f"{metric} = {row.get(metric)}" for metric in metric_colors)
        title = html.escape("\n".join(title_lines))
        for metric, color in metric_colors.items():
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
        for metric, color in metric_colors.items()
    )
    parts.append(f'<div class="legend">{legend}</div>')
    return f'<div class="chart-wrap">{"".join(parts)}</div>'


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
    """One collapsible, anchored drill-down section for a parsed report's scored entries (any
    suite recognized by ``_SUITE_BY_NODEID_MARKER`` -- correctness and robustness today). ``""``
    when the report has none (e.g. an ``eval_extended``-only run, or one left with none after the
    partial-run filter below) -- nothing for ``render_dashboard`` to show for that report.

    A report has no ``run_type`` field of its own (that's a trend-log-only concept, computed from
    ``scenarios_scored`` in ``eval/conftest.py``'s ``_write_trend_log``) -- and a single report can
    mix a full run of one suite with a `-k`-filtered partial run of another (e.g. `-k baseline`
    produces one scenario's worth of entries for *each* robustness test function it touches). So
    "partial" is decided per (report, suite) via ``_full_suites``, counting the *same* thing
    ``_write_trend_log`` counts -- entries that actually got scored (``e.precision is not None``; a
    setup-failed scenario's "unavailable" placeholder and a skipped/unrelated-failure entry both
    parse to ``None``, same as they never reach ``_write_trend_log``'s own ``"true_positives" in
    props`` check) -- rather than every entry whose nodeid merely matched a known suite. Without
    this, a report entry a setup failure kept out of the trend log (marking that row
    ``run_type="partial"`` and dropping it from the chart) would still count toward a *full* corpus
    here, showing as a complete run in the drill-down with no matching chart point."""
    all_scored = [e for e in report.entries if e.suite is not None]
    full_suites = _full_suites(report)
    scored_entries = [e for e in all_scored if e.suite in full_suites]
    if not scored_entries:
        return ""
    rows_html = "".join(
        "<tr>"
        f"<td>{_escape_cell(e.suite or '')}</td><td>{_escape_cell(e.scenario or '')}</td><td>{_escape_cell(e.category)}</td>"
        f"<td>{_fmt_metric(e.precision)}</td><td>{_fmt_metric(e.recall)}</td><td>{_fmt_metric(e.denial_precision)}</td>"
        f"<td>{_escape_cell(e.over_grants)}</td><td>{_escape_cell(e.under_grants)}</td><td>{_escape_cell(e.incorrectly_denied)}</td>"
        "</tr>"
        for e in scored_entries
    )
    # Which suite(s) this report's scored entries belong to (usually one; a mixed-suite run would
    # list more than one), e.g. "(correctness_prb suite)" -- shown instead of the raw run timestamp
    # (already available from the anchor/collapsed sort order) so the summary line leads with what
    # a reader actually wants to know: which file, from which suite.
    suite_names = list(dict.fromkeys(e.suite for e in scored_entries if e.suite))
    suite_word = "suite" if len(suite_names) == 1 else "suites"
    suite_label = f"({', '.join(suite_names)} {suite_word})"
    return (
        f'<details id="{_report_anchor(report)}">'
        f"<summary>{html.escape(report.path.name)} {html.escape(suite_label)}</summary>"
        "<table><thead><tr>"
        "<th>Suite</th><th>Scenario</th><th>Category</th><th>Precision</th><th>Recall</th>"
        "<th>Denial precision</th><th>Over-grants</th><th>Under-grants</th><th>Incorrectly denied</th>"
        f"</tr></thead><tbody>{rows_html}</tbody></table></details>"
    )


_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem; background: #121212; color: #e8eaed; }
a { color: #8ab4f8; }
table { border-collapse: collapse; margin: 0.5rem 0 1.5rem; width: 100%; }
th, td { border: 1px solid #444; padding: 4px 8px; text-align: left; font-size: 0.85rem; }
th { background: #1e1e1e; }
.trends-grid { display: flex; flex-wrap: wrap; gap: 1.5rem; justify-content: center; }
.trend-section { flex: 0 1 45%; max-width: 45%; min-width: 320px; }
.section-summary { font-size: 1.5rem; font-weight: 600; margin: 1rem 0; cursor: pointer; }
.chart-wrap { width: 100%; margin: 0 auto; }
.chart-wrap svg { display: block; width: 100%; height: auto; }
.legend { margin-top: 0.25rem; text-align: center; }
.legend-item { margin-right: 1rem; font-size: 0.85rem; }
.legend-swatch { display: inline-block; width: 10px; height: 10px; margin-right: 4px; }
details { margin-bottom: 0.5rem; }
summary { cursor: pointer; }
"""


def render_dashboard(trend_rows: list[dict[str, Any]], reports: list[ParsedReport]) -> str:
    """The full static dashboard page: one trend chart per suite present in ``trend_rows``
    (generic over suite name -- not hardcoded to the two Correctness suites, so a future suite
    gets its own chart the moment it starts writing trend-log rows), then one scenario drill-down
    section per parsed report.

    Charts only ever plot **full** runs (``run_type != "partial"`` -- a row with no ``run_type`` at
    all, e.g. one written before that field existed, still counts as full). A `-k`-filtered
    single-scenario debug run pools its precision/recall from far fewer scenarios than a real
    8-scenario regression row and would otherwise show up as an unlabeled outlier on the same line,
    indistinguishable from a genuine regression -- see ``eval/conftest.py``'s ``_write_trend_log``
    for where ``run_type`` is set. Excluded rows are dropped only from the *chart*; nothing here
    rewrites ``trend_log.jsonl`` itself."""
    full_run_rows = [row for row in trend_rows if row.get("run_type") != "partial"]
    suites = sorted({row["suite"] for row in full_run_rows if "suite" in row})
    if suites:
        chart_sections = "".join(
            f'<section class="trend-section"><h3>{suite}</h3>'
            + render_svg_chart([row for row in full_run_rows if row.get("suite") == suite], reports, suite=suite)
            + "</section>"
            for suite in suites
        )
        trends_body = f'<div class="trends-grid">{chart_sections}</div>'
    else:
        trends_body = "<p>No trend-log rows yet — run an eval suite to populate eval/trend_log.jsonl.</p>"

    tables = "".join(render_scenario_table(report) for report in reports)
    drilldown_sections = (
        tables if tables else "<p>No per-run reports found under eval/reports/ — run an eval suite to generate one.</p>"
    )

    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>AIAC eval dashboard</title>"
        f"<style>{_STYLE}</style></head><body>"
        "<h1>AIAC eval results dashboard</h1>"
        '<details open class="trends-details"><summary class="section-summary">Historical trends</summary>'
        f"{trends_body}"
        "</details>"
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
    page = render_dashboard(trend_rows, reports)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(page, encoding="utf-8")
    return output_path


def main() -> None:
    path = build_dashboard()
    print(f"Eval dashboard written to {path}")


if __name__ == "__main__":
    main()
