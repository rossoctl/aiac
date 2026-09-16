"""Per-run pass/fail/skip report for the policy-eval-scenarios, policy-eval-robustness,
policy-eval-consistency, policy-eval-correctness-prb, and policy-eval-correctness-e2e suites
(spec: ``docs/evaluation/policy-eval-scenarios.md``, ``docs/evaluation/
policy-eval-robustness-consistency.md``, ``docs/evaluation/policy-eval-correctness-prb.md``, and
``docs/evaluation/policy-eval-correctness-e2e.md``).

Every run of ``test_policy_pipeline_eval.py``, ``test_policy_pipeline_consistency.py``,
``test_policy_pipeline_robustness.py``, ``test_policy_pipeline_correctness_prb.py``, or
``test_policy_pipeline_correctness_e2e.py`` — all now carrying the single flat
``@pytest.mark.eval`` marker (opt in with ``-m eval``) — writes a Markdown report to ``reports/``
listing every collected test's outcome — passed, failed, skipped, xfailed, xpassed, or a
setup/collection error. All six sections are always present (even empty) so a reader can see at a
glance that nothing was silently omitted. Failed/error entries carry the assertion's crash message
(pytest's own computed diff, e.g. "assert True == False" or a custom mismatch message with
expected/actual sets); skipped/xfailed entries carry the skip reason; every entry carries the test
function's docstring so a reader doesn't have to open the source file to know what was actually
being checked. The report is scoped to the ``eval`` marker (not just "any test collected while this
conftest happens to be loaded"), so running the whole repo's test suite from a parent directory
does not pull unrelated tests into this suite's report.

Filename: ``reports/report_<DD_MM_HH_MM_SS>.md``, timestamped in UTC (override via
``EVAL_REPORT_TZ``, e.g. ``Asia/Jerusalem``), e.g. ``report_04_08_16_37_22.md`` for 04 Aug at
16:37:22 UTC. Regenerated (not appended) per run — old reports are left on disk for history but
are gitignored, same as ``rego_out/``.

``test_inbound``/``test_outbound`` (the per-cell tests sweeping every scenario x agent x
subject[/scope] combination) additionally ``record_property`` a concrete per-cell description plus
an expected/actual boolean and explanation -- read back here via ``report.user_properties`` and
rendered as "What it tests" / "Expected output" / "Output" instead of the generic docstring +
crash-message fallback used by every other test in this suite (see ``_render_entry``).

``test_prb_correctness`` (the correctness-prb suite) and ``test_e2e_correctness`` (the
correctness-e2e suite) similarly ``record_property``s precision/recall/denial-precision plus the
over-grants/under-grants/incorrectly-denied pair breakdown per scenario -- rendered as its own
metrics + detail block, always (pass or fail), since the tracked-but-non-gating under-grant/denial
detail is otherwise invisible on a passing run. The render branch dispatches generically on the
presence of ``precision``/``recall`` properties, so it covers both suites with no per-suite
special-casing. All three ``test_policy_pipeline_robustness.py`` test functions (invariant-
mechanical, invariant-semantic, sensitive-mechanical) record the same six fields too, via their own
``_record_scoring`` helper -- so they hit this exact branch and get the same metrics block, plus
(robustness only) a leading ``perturbation``/``expected_grants``/``actual_grants`` trio naming what
actually changed and what was expected/returned, since "did the grant set change" alone doesn't
say what changed it or how.

A scenario whose own *setup* fails (a Keycloak/PRB/PCE error, or an uncaught
``PolicyContradictionError``/``PolicyRulesBuilderError`` from a non-best-effort robustness call,
before ``score_scenario``/``_record_scoring`` ever ran) never gets those properties recorded at
all. Such an entry still gets the crash detail *and* the same six-field metrics block, values
marked ``unavailable`` with why -- identified by nodeid (``::test_prb_correctness[``/
``::test_e2e_correctness[``/the three robustness test functions, see ``_CORRECTNESS_TEST_MARKERS``/
``_ROBUSTNESS_SCORED_TEST_MARKERS``) since there are no properties to dispatch on -- rather than
silently falling back to the generic docstring + crash-message rendering every other test in this
suite gets.

Both suites also ``record_property("best_effort_notes", ...)`` -- a ``{scope_or_role_name:
reason}`` dict naming every decision that fell back to a never-approved PRB proposal instead of
aborting the scenario (``eval.test_policy_pipeline_eval.orchestrate_prb``'s ``best_effort=True``,
by explicit user request so a scenario the auditor partly rejects still scores). When non-empty,
``_render_metrics_block`` appends one more field listing them, with an explicit caveat that those
pairs don't represent real production behavior.

Both suites also ``record_property`` two raw counts alongside the floats above —
``true_positives`` and ``denied_total`` — not rendered in the Markdown report (the floats and pair
breakdowns already cover a human reader) but read back here by ``_write_trend_log`` to pool a
run's precision/recall/denial_precision into one committed, append-only trend-log row per suite
(``eval/trend_log.py``, spec: ``docs/evaluation/eval-framework.md`` §9) — pooled by summed count
across every scenario that reached ``score_scenario`` in the run, not averaged per-scenario, so a
run with an uneven pair count per scenario isn't skewed by weighting every scenario equally. A
scenario whose own setup failed never recorded these, so it contributes nothing to the pooled row
(consistent with ``_CORRECTNESS_TEST_MARKERS``'s existing setup-failure handling above).

``test_prb_invariant_to_mechanical_perturbation`` and ``test_prb_sensitive_to_mechanical_edit``
(``test_policy_pipeline_robustness.py``, spec §4) similarly each ``record_property`` a boolean
(``"invariant"``/``"sensitive"``) -- pooled here by nodeid substring (``_ROBUSTNESS_TEST_MARKERS``,
mirroring ``_CORRECTNESS_TEST_MARKERS``'s pattern, since the single flat ``eval`` marker spans
three test functions across two families/tiers that must stay unblended) into one committed
trend-log row, ``suite="robustness_mechanical"``, carrying both ``invariance_rate`` and
``sensitivity_rate`` (``eval/trend_log.py``'s ``pool_robustness_metrics``). The third test in that
module, ``test_prb_invariant_to_semantic_perturbation``, is deliberately excluded from this wiring --
semantic-tier trend-log wiring is tracked separately as #2467.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from dotenv import load_dotenv

from eval.trend_log import append_row, pool_correctness_metrics, pool_robustness_metrics

HERE = Path(__file__).resolve().parent
REPORTS_DIR = HERE / "reports"
REPORT_TZ = ZoneInfo(os.environ.get("EVAL_REPORT_TZ", "UTC"))

# Auto-load the repo-root .env so LLM_BASE_URL/KEYCLOAK_URL/etc. are set without having to
# `set -a; . .env; set +a` before invoking pytest. Existing environment
# variables take precedence (override=False), so CI/shell exports still win.
load_dotenv(HERE.parent / ".env", override=False)

_docstrings: dict[str, str] = {}
_reports: dict[str, pytest.TestReport] = {}
# Nodeids that actually carry `@pytest.mark.eval`, captured at collection. We must NOT gate on the
# keyword set (`"eval" in report.keywords`): the suite lives in a package directory literally named
# `eval/` with an `__init__.py`, so pytest builds a `Package` node named `eval` and injects that
# name into every collected item's keyword set — marked or not. Gating on the keyword would scoop
# the pure-unit helpers under `eval/` (test_dashboard, test_trend_log, …) into this report on a
# bare offline `pytest`, breaking this module's guarantee that only `-m eval` tests are captured.
# The real marker is only reachable via `item.iter_markers()` at collection, so we record the
# nodeids there and gate reports on membership. (Same controller-side flow xdist already relies on
# for `_docstrings`.)
_eval_nodeids: set[str] = set()


def pytest_collection_modifyitems(session: pytest.Session, config: pytest.Config, items: list) -> None:
    for item in items:
        if not any(marker.name == "eval" for marker in item.iter_markers()):
            continue
        _eval_nodeids.add(item.nodeid)
        func = getattr(item, "obj", None)
        doc = (getattr(func, "__doc__", None) or "").strip()
        if doc:
            # First paragraph only — the rest is often maintainer-facing rationale.
            _docstrings[item.nodeid] = " ".join(doc.split("\n\n")[0].split())


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.when == "teardown" and report.outcome == "passed":
        return
    if report.nodeid not in _eval_nodeids:
        return
    # A later phase (call) supersedes an earlier one (setup) for the same nodeid; a setup or
    # teardown failure has no later phase to supersede it.
    _reports[report.nodeid] = report


def _categorize(report: pytest.TestReport) -> str:
    wasxfail = getattr(report, "wasxfail", None) is not None
    if report.when in ("setup", "teardown") and report.outcome == "failed":
        return "error"
    if report.outcome == "passed":
        return "xpassed" if wasxfail else "passed"
    if report.outcome == "failed":
        return "xpassed" if wasxfail else "failed"  # strict-xfail unexpected pass -> reported failed
    if report.outcome == "skipped":
        return "xfailed" if wasxfail else "skipped"
    return report.outcome


def _detail(report: pytest.TestReport, category: str) -> str | None:
    """Full crash/skip detail — pytest's own computed expected-vs-actual diff for failures, the
    literal ``pytest.skip()``/``xfail()`` reason for skips."""
    longrepr = report.longrepr
    if longrepr is None:
        return None
    if category in ("failed", "error"):
        crash = getattr(longrepr, "reprcrash", None)
        if crash is not None:
            return str(crash.message).strip()
        return str(longrepr).strip().splitlines()[-1]
    if category in ("skipped", "xfailed"):
        if isinstance(longrepr, tuple) and len(longrepr) == 3:
            reason = str(longrepr[2])
            for prefix in ("Skipped: ", "XFAIL: ", "XFAIL "):
                if reason.startswith(prefix):
                    reason = reason[len(prefix) :]
            return reason
        return str(longrepr).strip()
    return None


def _render_field(lines: list[str], label: str, text: str) -> None:
    """Append a ``- **label:** text`` bullet, code-fencing ``text`` if it spans multiple lines."""
    if "\n" in text:
        lines.append(f"- **{label}:**")
        lines.append("  ```")
        lines.extend(f"  {line}" for line in text.splitlines())
        lines.append("  ```")
    else:
        lines.append(f"- **{label}:** {text}")


def _format_pairs_dict(pairs_by_gate: dict) -> str:
    """Render a ``{gate: [(role, scope), ...]}`` dict (as produced by ``ScenarioScore.over_grants``
    /``under_grants``/``incorrectly_denied``) as one line per non-empty gate, or ``"none"``."""
    if not pairs_by_gate:
        return "none"
    return "\n".join(
        f"{gate}: " + ", ".join(f"({r}, {s})" for r, s in pairs) for gate, pairs in sorted(pairs_by_gate.items())
    )


# Nodeid substrings identifying the two correctness suites' single test function each (parametrized
# by scenario name) — used to give a scenario whose *setup* failed (before score_scenario ever ran,
# so none of precision/recall/etc got record_property'd) the same six-field metrics shape every
# other entry gets, instead of silently omitting it. See `_render_entry`'s middle branch. Gated on
# `category in ("failed", "error")` there too, not just this nodeid check — a *skipped*/xfailed
# correctness entry (e.g. `opa` missing from PATH) also matches this nodeid substring but never
# reached score_scenario for an unrelated, non-failure reason, so it must fall through to the
# generic branch and render its actual skip reason instead of a misleading "setup failed".
_CORRECTNESS_TEST_MARKERS = ("::test_prb_correctness[", "::test_e2e_correctness[")

# Nodeid substrings for all three robustness test functions (mirrors _CORRECTNESS_TEST_MARKERS
# above, same purpose) -- every one of them, not just the two that feed the trend log
# (_ROBUSTNESS_TEST_MARKERS below), records precision/recall/etc. via _record_scoring for the
# report, so a scenario whose setup fails before that call ever runs gets the same
# "unavailable, here's why" six-field shape instead of silently falling back to the generic
# docstring + crash-message rendering.
_ROBUSTNESS_SCORED_TEST_MARKERS = (
    "::test_prb_invariant_to_mechanical_perturbation[",
    "::test_prb_invariant_to_semantic_perturbation[",
    "::test_prb_sensitive_to_mechanical_edit[",
)

# Nodeid substring -> trend-log suite name (eval/trend_log.py). With the five former ``eval_*``
# markers collapsed to one flat ``eval`` marker, every suite under `eval/` is disambiguated by its
# own test function's nodeid rather than by marker — the same ``::test_prb_correctness[``/
# ``::test_e2e_correctness[`` substrings ``_CORRECTNESS_TEST_MARKERS`` already uses. Deliberately
# scoped to the two Correctness suites for now — the Consistency/Scale suite tickets (#2468-#2470)
# add their own entries here when they land, reusing the same _write_trend_log/append_row mechanism
# rather than building a parallel one. Robustness (#2466) is wired separately below
# (_ROBUSTNESS_TEST_MARKERS) since its three test functions span two families/tiers that must stay
# unblended (spec §4) — a single nodeid -> suite entry here would conflate them.
_TREND_LOG_SUITES = {
    "::test_prb_correctness[": "correctness_prb",
    "::test_e2e_correctness[": "correctness_e2e",
}

# Nodeid substring -> robustness property name, mirroring _CORRECTNESS_TEST_MARKERS below. Only
# the mechanical-tier invariance/sensitivity tests feed the trend log — the semantic-tier
# invariance test (test_prb_invariant_to_semantic_perturbation) is out of scope for #2466 (tracked
# as #2467) and deliberately excluded here, per that test's own docstring.
_ROBUSTNESS_TEST_MARKERS = {
    "::test_prb_invariant_to_mechanical_perturbation[": "invariant",
    "::test_prb_sensitive_to_mechanical_edit[": "sensitive",
}

# Full Correctness corpus size (eval.test_policy_pipeline_eval.SCENARIOS) -- kept as a plain
# constant rather than imported, so this module (loaded for every eval/ run, marked or not) stays
# free of that file's heavy Keycloak/launcher imports. A run that scores fewer scenarios than this
# (a `-k` filter, or most scenarios erroring in setup) is not comparable to a full-corpus run, so
# it's tagged "partial" rather than "regression" -- see _write_trend_log. Bump if the corpus grows.
_EXPECTED_SCENARIO_COUNT = 8


def _format_best_effort_notes(notes: dict[str, str]) -> str:
    """Render a ``{scope_or_role_name: reason}`` dict (``orchestrate_prb``'s ``best_effort_notes``)
    as one line per entry, or ``"none"``."""
    if not notes:
        return "none"
    return "\n".join(f"{name}: {reason}" for name, reason in sorted(notes.items()))


def _render_metrics_block(lines: list[str], props: dict, *, unavailable_reason: str | None = None) -> None:
    """Render the precision/recall/denial-precision + over-/under-grant/incorrect-denial breakdown
    ``test_prb_correctness``/``test_e2e_correctness`` record, and (the robustness suite only)
    ``_record_scoring``'s ``perturbation``/``expected_grants``/``actual_grants`` fields first, when
    present, so a reader sees what changed and what was expected/returned before the numbers.
    When ``unavailable_reason`` is given (the scenario's own setup failed before scoring could run,
    so ``props`` has none of this), render the same six metrics fields with a uniform placeholder
    instead — so a reader always sees the same shape, pass or fail, setup-failed or scored."""
    if unavailable_reason is not None:
        for label in ("Precision", "Recall", "Denial precision", "Over-grants", "Under-grants", "Incorrectly denied"):
            lines.append(f"- **{label}:** unavailable — {unavailable_reason}")
        return
    if "perturbation" in props:
        _render_field(lines, "Perturbation", str(props["perturbation"]))
        _render_field(lines, "Expected grants", _format_pairs_dict(props.get("expected_grants", {})))
        _render_field(lines, "Actual grants", _format_pairs_dict(props.get("actual_grants", {})))
    lines.append(f"- **Precision:** {props['precision']:.3f}")
    lines.append(f"- **Recall:** {props['recall']:.3f}")
    lines.append(f"- **Denial precision:** {props['denial_precision']:.3f}")
    _render_field(lines, "Over-grants", _format_pairs_dict(props.get("over_grants", {})))
    _render_field(lines, "Under-grants", _format_pairs_dict(props.get("under_grants", {})))
    _render_field(lines, "Incorrectly denied", _format_pairs_dict(props.get("incorrectly_denied", {})))
    best_effort_notes = props.get("best_effort_notes", {})
    if best_effort_notes:
        _render_field(
            lines,
            "Best-effort proposals used (not real production behavior — the auditor never approved these)",
            _format_best_effort_notes(best_effort_notes),
        )


def _render_entry(lines: list[str], nodeid: str, report: pytest.TestReport, category: str) -> None:
    """Per-cell tests (``test_inbound``/``test_outbound``) ``record_property`` a concrete
    description + expected/actual boolean + explanation; ``test_prb_correctness`` (correctness-prb)
    ``record_property``s precision/recall/denial-precision + the over-/under-grant/incorrect-denial
    pair breakdown; render each instead of the generic docstring + crash/skip-reason fallback every
    other test in this suite gets. A correctness-suite scenario whose *setup* failed (a pipeline
    error before ``score_scenario`` ever ran) gets the crash detail *and* the same six-field metrics
    block, marked unavailable with why — not silently dropped to the generic fallback."""
    lines.append(f"### `{nodeid}`")
    props = dict(report.user_properties)
    if "expected" in props and "output" in props:
        description = props.get("description") or _docstrings.get(nodeid)
        if description:
            lines.append(f"- **What it tests:** {description}")
        _render_field(lines, "Expected output", f"{props['expected']} — {props.get('expected_explanation', '')}")
        _render_field(lines, "Output", f"{props['output']} — {props.get('llm_reasoning', '')}")
    elif "precision" in props and "recall" in props:
        description = _docstrings.get(nodeid)
        if description:
            lines.append(f"- **What it tests:** {description}")
        _render_metrics_block(lines, props)
    elif category in ("failed", "error") and any(
        marker in nodeid for marker in _CORRECTNESS_TEST_MARKERS + _ROBUSTNESS_SCORED_TEST_MARKERS
    ):
        doc = _docstrings.get(nodeid)
        if doc:
            lines.append(f"- **What it tests:** {doc}")
        detail = _detail(report, category)
        if detail:
            _render_field(lines, "Failure", detail)
        _render_metrics_block(lines, props, unavailable_reason="scenario setup failed before scoring could run")
    else:
        doc = _docstrings.get(nodeid)
        if doc:
            lines.append(f"- **What it tests:** {doc}")
        detail = _detail(report, category)
        if detail:
            label = "Reason" if category in ("skipped", "xfailed") else "Failure"
            _render_field(lines, label, detail)
    lines.append("")


def _write_trend_log() -> None:
    """One committed trend-log row per Correctness suite present in this session (PRB-level
    and/or end-to-end) — spec: docs/evaluation/eval-framework.md §9. Pools every scenario's
    true_positives/denied_total counts (and over_grants/under_grants/incorrectly_denied pair
    dicts) that reached score_scenario — a scenario whose own setup failed never recorded these,
    so it contributes nothing to the pooled row, same as _render_metrics_block's
    unavailable_reason branch above treats it as absent rather than zero.

    Always stamped in UTC, independent of ``EVAL_REPORT_TZ`` (that variable only controls the
    gitignored per-run Markdown report's timestamp/filename) — a committed file read by every
    contributor and by downstream trend analysis must not carry a per-contributor UTC offset."""
    by_suite: dict[str, list[dict]] = {}
    invariant_flags: list[bool] = []
    sensitive_flags: list[bool] = []
    for nodeid, report in _reports.items():
        for nodeid_marker, suite in _TREND_LOG_SUITES.items():
            if nodeid_marker in report.nodeid:
                props = dict(report.user_properties)
                if "true_positives" in props:
                    by_suite.setdefault(suite, []).append(props)
                break
        for substring, prop_name in _ROBUSTNESS_TEST_MARKERS.items():
            if substring in nodeid:
                props = dict(report.user_properties)
                if prop_name in props:
                    (invariant_flags if prop_name == "invariant" else sensitive_flags).append(bool(props[prop_name]))
                break

    for suite, entries in by_suite.items():
        if entries:
            run_type = "regression" if len(entries) == _EXPECTED_SCENARIO_COUNT else "partial"
            append_row(suite, pool_correctness_metrics(entries), run_type=run_type)

    if invariant_flags or sensitive_flags:
        scored = max(len(invariant_flags), len(sensitive_flags))
        run_type = "regression" if scored == _EXPECTED_SCENARIO_COUNT else "partial"
        append_row(
            "robustness_mechanical", pool_robustness_metrics(invariant_flags, sensitive_flags), run_type=run_type
        )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if hasattr(session.config, "workerinput"):
        return  # xdist worker -- only the controller (which receives every worker's reports via
        # pytest_runtest_logreport) has the full-session picture; each worker would otherwise
        # write its own partial trend-log row and Markdown report on top of the controller's.
    if not _reports:
        return  # this session collected none of this suite's tests -- nothing to report

    order = ["failed", "passed", "error", "xpassed", "xfailed", "skipped"]
    buckets: dict[str, list[tuple[str, pytest.TestReport]]] = {cat: [] for cat in order}
    for nodeid, report in _reports.items():
        buckets[_categorize(report)].append((nodeid, report))
    for cat in buckets:
        buckets[cat].sort(key=lambda pair: pair[0])

    now = datetime.now(REPORT_TZ)
    _write_trend_log()
    total = len(_reports)
    lines = [
        "# policy-eval-scenarios test report",
        "",
        f"Run: {now.isoformat()}",
        f"Exit status: {exitstatus}",
        f"Total: {total} — " + ", ".join(f"{cat}={len(buckets[cat])}" for cat in order),
        "",
    ]
    for cat in order:
        entries = buckets[cat]
        lines.append(f"## {cat} ({len(entries)})")
        lines.append("")
        if not entries:
            lines.append("_none_")
            lines.append("")
            continue
        for nodeid, report in entries:
            _render_entry(lines, nodeid, report, cat)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = now.strftime("%d_%m_%H_%M_%S")
    report_path = REPORTS_DIR / f"report_{suffix}.md"
    report_path.write_text("\n".join(lines))
    print(f"\npolicy-eval-scenarios report written to {report_path}")
