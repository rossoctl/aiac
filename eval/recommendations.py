"""Deterministic evidence gathering + one batched LLM call to draft the "Improvement
recommendations" section of the per-run eval report (spec: ``docs/evaluation/eval-framework.md``
§9.1, issue #2472).

Three layers, in this file:

1. **Six pure builder functions** (``over_grant_cases``/``under_grant_cases``/``sensitivity_cases``/
   ``invariance_cases``/``consistency_cases``/``scale_mistake_cases``) — each walks already
   scenario-attributed ``record_property`` data (gathered by ``eval/conftest.py``) and emits one
   ``EvidenceCase`` per concrete failing test case/cell. No I/O, no LLM — fully unit-testable.
2. **One single structured LLM call per report run** (``_draft_patterns``), made only when step 1
   produced at least one case. Sends every case's id/finding-type/evidence/remedy-menu in one
   request and asks the model to cluster them into DISTINCT underlying error patterns — explicitly
   merging cases that share a root cause rather than echoing one output per input case. Reuses the
   shared ``aiac.agent.llm`` seam (``load_llm_settings``/``build_llm``/``call_with_retry``) on the
   bare ``LLM_*`` profile, the same pattern ``aiac.agent.policy_rules_builder.graph._structured_call``
   already uses for schema-constrained calls — no new LLM plumbing invented here. Returns ``[]`` on
   ANY exception (settings/client-construction error, transport failure, or the structured-output
   call returning ``None`` outright instead of raising) -- the caller never needs to distinguish why
   it got nothing back.
3. **Deterministic fallback** inside ``build_recommendations``: for every case left uncovered after
   validating the drafted patterns' ``case_ids`` against the known set (whether because the call
   above returned ``[]``, or a pattern simply omitted a case or named it with a hallucinated id),
   falls back to one ``Recommendation`` per ``(finding_type, fallback_key)``, body text a static,
   clearly-labeled note, evidence = that group's cases' evidence lines verbatim. This keeps the
   feature honest — never silently blank, never a fabricated-sounding recommendation when the model
   didn't actually produce one, and never a case quietly dropped because the model omitted it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from aiac.agent.llm import build_llm, call_with_retry, load_llm_settings
from eval.pairs import format_pairs, pairs_not_in

# EVAL_RECOMMENDATIONS_LLM env override (default enabled) -- lets a developer skip the blocking,
# retried LLM call entirely for a quick -k debug run (confirmed as a real finding in PR review:
# pytest_sessionfinish makes this call whenever at least one case failed, with no way to opt out
# short of unsetting LLM_BASE_URL/LLM_API_KEY/LLM_MODEL entirely -- which would also break
# anything else in the session that needs them). Disabling it still produces the section: an
# empty _draft_patterns result is exactly what build_recommendations' own documented contract
# already falls back to on any unusable result -- never a missing section, just an unclustered
# one.
_RECOMMENDATIONS_LLM_ENV = "EVAL_RECOMMENDATIONS_LLM"


@dataclass(frozen=True)
class EvidenceCase:
    """One concrete failing test case/cell, grounded in deterministically-gathered evidence.

    ``remedy_menu`` is the spec's own framing of what kind of fix applies to this finding type
    (constant per finding_type, fed to the LLM as instruction, not evidence). ``fallback_key`` is
    the deterministic grouping key used ONLY when the LLM call/response is unusable."""

    case_id: str
    finding_type: str  # "over_grant" | "under_grant" | "sensitivity" | "invariance" | "consistency" | "scale_mistake"
    evidence: str
    remedy_menu: str
    fallback_key: str


@dataclass(frozen=True)
class Recommendation:
    heading: str
    body: str  # LLM-drafted pattern writeup, or the labeled fallback note
    evidence: list[str]  # one line per case this recommendation covers


# Evidence strings this module builds are capped in two ways, both bounding what goes into ONE
# batched _draft_patterns request: per-gate pair counts (eval.pairs.format_pairs's own
# MAX_PAIRS_PER_GATE) and, for free-form text fields that aren't pair lists at all (perturbation,
# mismatches), a plain character cap -- see _truncate below.
_MAX_FIELD_CHARS = 500


def _truncate(text: str, limit: int = _MAX_FIELD_CHARS) -> str:
    """``text`` cut to ``limit`` characters with a trailing ``"... (truncated)"`` marker --
    bounds a free-form evidence field (``perturbation``/``mismatches``) that ``format_pairs``'s own
    per-gate cap doesn't reach, since neither is a pair list. Confirmed as a real finding in PR
    review: a long policy-text edit or a high ``PRB_CONSISTENCY_REPEATS`` run could otherwise make
    ONE case's evidence string large enough, on its own, to risk overflowing the model's context
    window in the single batched request every case shares."""
    if len(text) <= limit:
        return text
    return text[:limit] + "... (truncated)"


def _grant_diff(expected: dict, actual: dict) -> str:
    """One line summarizing exactly what differs between ``expected``/``actual`` grants, per gate
    -- ``lost`` (in ``expected``, not ``actual``) and ``gained`` (in ``actual``, not ``expected``).
    Sent instead of the two full lists (confirmed as a real finding in PR review): when both lists
    are independently capped at the same ``format_pairs`` pair limit, a pair that changed past that
    cutoff (e.g. expected pair #25 of 30, sorted) could leave BOTH truncated lists showing the same
    first N pairs plus "... and K more" -- identical on their face, with no way to tell which pair
    actually changed. Diffing first means the cap only ever has to represent genuine differences,
    which are typically far fewer than either full list."""
    lost = pairs_not_in(expected, actual)
    gained = pairs_not_in(actual, expected)
    if not lost and not gained:
        return "no difference"
    parts = []
    if lost:
        parts.append(f"lost -> {format_pairs(lost)}")
    if gained:
        parts.append(f"gained -> {format_pairs(gained)}")
    return "; ".join(parts)


# Remedy-menu constants -- the spec's own recommendation-form framing per finding type
# (docs/evaluation/eval-framework.md §9.1's table), fed to the LLM as instruction for that
# finding type's cases, never as evidence.
_OVER_GRANT_REMEDY = (
    "Identify the specific policy clause or semantic pattern the PRB is over-interpreting; "
    "recommend a prompt constraint, a PRB graph edge, or a targeted scenario addition to the "
    "training/prompt corpus."
)
_UNDER_GRANT_REMEDY = (
    "Identify whether the miss is a parsing gap (policy text not recognized) or a reasoning gap "
    "(text parsed but grant not inferred); recommend either input normalization upstream of the "
    "PRB or an explicit reasoning step in the graph."
)
_SENSITIVITY_REMEDY = (
    "Flag which policy-text edit types the PRB is insensitive to (e.g. negation words, exception "
    'clauses, restriction words like "only"/"just"); recommend adding those edit patterns to '
    "the Robustness corpus and reviewing PRB prompts for those constructs."
)
_INVARIANCE_REMEDY = (
    "Flag which surface-form changes destabilize the PRB; recommend prompt hardening or normalization pre-processing."
)
_CONSISTENCY_REMEDY = (
    "Note whether disagreements cluster on specific scenarios (structural prompt sensitivity) or "
    "appear random (temperature/batching noise); recommend temperature=0 enforcement or a "
    "retry-with-majority-vote strategy accordingly."
)
_SCALE_MISTAKE_REMEDY = (
    "Identify whether the mistake is in per-decision scale (large candidate lists) or "
    "total-corpus scale; recommend context-window management changes (chunking, summarization) or "
    "candidate-list pruning strategies respectively."
)

# Constant fallback_key for the Consistency finding type -- there's only one Consistency suite
# (unlike the per-suite/per-edit-type keys the other five finding types fall back to), so every
# inconsistent-scenario case groups into a single fallback bucket.
_CONSISTENCY_FALLBACK_KEY = "consistency"


def over_grant_cases(entries: list[tuple[str, str, dict]]) -> list[EvidenceCase]:
    """``entries``: ``(correctness_suite, scenario_name, props)`` for every entry of the two
    Correctness suites (``correctness_prb``/``correctness_e2e``) present in this run. One
    ``EvidenceCase`` per entry whose ``over_grants`` is non-empty."""
    cases = []
    for suite, scenario, props in entries:
        over_grants = props.get("over_grants") or {}
        if not over_grants:
            continue
        cases.append(
            EvidenceCase(
                case_id=f"{suite}:{scenario}:over_grant",
                finding_type="over_grant",
                evidence=f"{suite}/{scenario}: over-granted pairs -> {format_pairs(over_grants)}",
                remedy_menu=_OVER_GRANT_REMEDY,
                fallback_key=suite,
            )
        )
    return cases


def under_grant_cases(entries: list[tuple[str, str, dict]]) -> list[EvidenceCase]:
    """Mirrors ``over_grant_cases`` for ``under_grants`` -- PLUS the part of ``incorrectly_denied``
    not already in ``under_grants``. ``incorrectly_denied`` (an explicit deny for a pair that should
    be granted) is normally a SUBSET of ``under_grants`` (``eval.correctness_scorer``'s own
    docstring) -- restating it in full would double the same pairs in the evidence text and the
    tokens sent to the LLM for no new information. The genuinely distinct edge case this still
    needs to catch is a pair that is simultaneously ``granted`` AND ``denied`` -- e.g. a coarse
    scope split by the auditor into one approved sub-decision and one best-effort-rejected
    sub-decision for the same (role, scope) pair -- which lands in ``incorrectly_denied`` without
    ever appearing in ``under_grants`` (it IS in ``granted``, so ``expected - granted`` excludes
    it). ``eval.pairs.pairs_not_in`` isolates exactly that: whatever's in ``incorrectly_denied`` but
    not already in ``under_grants``."""
    cases = []
    for suite, scenario, props in entries:
        under_grants = props.get("under_grants") or {}
        incorrectly_denied_only = pairs_not_in(props.get("incorrectly_denied") or {}, under_grants)
        if not under_grants and not incorrectly_denied_only:
            continue
        detail_parts = []
        if under_grants:
            detail_parts.append(f"under-granted pairs -> {format_pairs(under_grants)}")
        if incorrectly_denied_only:
            detail_parts.append(f"also explicitly (incorrectly) denied -> {format_pairs(incorrectly_denied_only)}")
        evidence = f"{suite}/{scenario}: " + "; ".join(detail_parts)
        cases.append(
            EvidenceCase(
                case_id=f"{suite}:{scenario}:under_grant",
                finding_type="under_grant",
                evidence=evidence,
                remedy_menu=_UNDER_GRANT_REMEDY,
                fallback_key=suite,
            )
        )
    return cases


def sensitivity_cases(entries: list[tuple[str, str, dict]]) -> list[EvidenceCase]:
    """``entries``: ``(sensitivity_suite, scenario_name, props)`` for every entry of the two
    sensitivity-family Robustness suites (``robustness_mechanical_sensitivity``/
    ``robustness_semantic_sensitivity``). One ``EvidenceCase`` per entry whose ``"sensitive"``
    flag is ``False`` (the PRB failed to change its decision on a deliberately meaning-changing
    edit). ``fallback_key`` is the edit's own ``edit_type`` -- the policy-text-level pattern the
    PRB was insensitive to, not just which suite caught it. Evidence shows the grant DIFFERENCE
    (``_grant_diff``), not the two full expected/actual lists -- confirmed as a real finding in PR
    review: independently capping two full lists at the same pair limit could leave both showing
    an identical truncated prefix with no way to tell which pair actually changed."""
    cases = []
    for suite, scenario, props in entries:
        if props.get("sensitive", True):
            continue
        edit_type = props.get("edit_type", "unknown")
        perturbation = repr(_truncate(str(props.get("perturbation", ""))))
        diff = _grant_diff(props.get("expected_grants") or {}, props.get("actual_grants") or {})
        evidence = f"{suite}/{scenario} (edit_type={edit_type}): perturbation={perturbation}; {diff}"
        cases.append(
            EvidenceCase(
                case_id=f"{suite}:{scenario}:sensitivity",
                finding_type="sensitivity",
                evidence=evidence,
                remedy_menu=_SENSITIVITY_REMEDY,
                fallback_key=edit_type,
            )
        )
    return cases


def invariance_cases(entries: list[tuple[str, str, dict]]) -> list[EvidenceCase]:
    """``entries``: ``(invariance_suite, scenario_name, props)`` for every entry of the two
    invariance-family Robustness suites (``robustness_mechanical_invariance``/
    ``robustness_semantic_invariance``). One ``EvidenceCase`` per entry whose ``"invariant"`` flag
    is ``False`` (the PRB's decision changed under a meaning-preserving perturbation).
    ``fallback_key`` is the suite itself (tier) -- there is no edit_type here, every change is
    unwanted by definition. Evidence shows the grant DIFFERENCE (``_grant_diff``), not the two
    full expected/actual lists -- see ``sensitivity_cases``'s docstring for why."""
    cases = []
    for suite, scenario, props in entries:
        if props.get("invariant", True):
            continue
        perturbation = repr(_truncate(str(props.get("perturbation", ""))))
        diff = _grant_diff(props.get("expected_grants") or {}, props.get("actual_grants") or {})
        evidence = f"{suite}/{scenario}: perturbation={perturbation}; {diff}"
        cases.append(
            EvidenceCase(
                case_id=f"{suite}:{scenario}:invariance",
                finding_type="invariance",
                evidence=evidence,
                remedy_menu=_INVARIANCE_REMEDY,
                fallback_key=suite,
            )
        )
    return cases


def consistency_cases(entries: list[tuple[str, dict]], classification: str) -> list[EvidenceCase]:
    """``entries``: ``(scenario_name, props)`` for every Consistency-suite entry present in this
    run. One ``EvidenceCase`` per entry whose ``"inconsistent"`` flag is ``True``. ``classification``
    is the already-decided cluster-vs-random verdict for the WHOLE run (computed deterministically
    by the caller from the fraction of inconsistent scenarios -- see
    ``eval.conftest._classify_consistency_disagreements`` -- not recomputed here), folded into every
    case's evidence so the LLM's pattern-level writeup stays consistent with it."""
    cases = []
    for scenario, props in entries:
        if not props.get("inconsistent"):
            continue
        # ``mismatches`` (test_policy_pipeline_consistency.py's own record_property) is already
        # newline-joined when a scenario disagreed on more than one gate/run -- ``!r`` here (same
        # convention sensitivity_cases/invariance_cases use for `perturbation`) keeps this case's
        # evidence a single line, so _case_prompt_line's per-case indentation and
        # ``"\n".join(rec.evidence)`` in the rendered report both still read as one case each.
        # ``_truncate`` bounds it too: a high PRB_CONSISTENCY_REPEATS run can produce an
        # arbitrarily long mismatch list that format_pairs's pair-count cap never reaches, since
        # this isn't a pair list at all.
        mismatches = repr(_truncate(props.get("mismatches") or "none"))
        evidence = f"consistency/{scenario} ({classification}): mismatches -> {mismatches}"
        cases.append(
            EvidenceCase(
                case_id=f"consistency:{scenario}",
                finding_type="consistency",
                evidence=evidence,
                remedy_menu=_CONSISTENCY_REMEDY,
                fallback_key=_CONSISTENCY_FALLBACK_KEY,
            )
        )
    return cases


def scale_mistake_cases(entries: list[tuple[str, dict]]) -> list[EvidenceCase]:
    """``entries``: ``(scale_suite, props)`` for every Scale-correctness-test entry present in this
    run -- one per dimension/level (``scale_total_corpus_prb``/``scale_per_decision_prb``/their
    ``_e2e`` counterparts), never parametrized by scenario. One ``EvidenceCase`` per entry whose
    over-grants, under-grants, or incorrectly-denied pairs are non-empty -- any occurrence IS the
    finding (decision 1: the Scale suite's correctness check reuses the same zero-tolerance gate as
    Correctness, so there is no numeric degradation threshold to diff against). ``over-grants``/
    ``under-grants`` are always shown (even as ``none``) since one Scale case spans all three
    categories at once and a reader benefits from seeing which are and aren't empty -- UNLIKE
    ``under_grant_cases``' two conditional clauses. The one thing this DOES share with
    ``under_grant_cases``: only the part of ``incorrectly_denied`` not already covered by
    ``under_grants`` is included, and that clause is omitted entirely (not shown as ``none``) when
    nothing's left -- confirmed as a real finding in PR review: this builder still restated the
    same pairs under both labels after ``under_grant_cases`` was fixed to dedupe them, doubling
    the same pairs in a 100-entity Scale run's largest evidence strings."""
    cases = []
    for suite, props in entries:
        over_grants = props.get("over_grants") or {}
        under_grants = props.get("under_grants") or {}
        incorrectly_denied_only = pairs_not_in(props.get("incorrectly_denied") or {}, under_grants)
        if not (over_grants or under_grants or incorrectly_denied_only):
            continue
        detail_parts = [f"over-grants -> {format_pairs(over_grants)}", f"under-grants -> {format_pairs(under_grants)}"]
        if incorrectly_denied_only:
            detail_parts.append(f"also incorrectly denied -> {format_pairs(incorrectly_denied_only)}")
        evidence = f"{suite}: " + "; ".join(detail_parts)
        cases.append(
            EvidenceCase(
                case_id=f"{suite}:scale_mistake",
                finding_type="scale_mistake",
                evidence=evidence,
                remedy_menu=_SCALE_MISTAKE_REMEDY,
                fallback_key=suite,
            )
        )
    return cases


class _Pattern(BaseModel):
    heading: str
    recommendation: str
    case_ids: list[str]


class _PatternBatch(BaseModel):
    patterns: list[_Pattern]


_DRAFT_SYSTEM_PROMPT = (
    "You are drafting an 'Improvement recommendations' section for an AI policy-rules-builder "
    "evaluation report. You are given a list of EVIDENCE CASES -- each a concrete failing test "
    "case/cell with its own finding type, exact evidence, and a remedy menu describing the kind "
    "of fix that applies to that finding type.\n\n"
    "Your job: identify the DISTINCT underlying error patterns across the whole set. Merge cases "
    "that plausibly share one real root cause into a SINGLE pattern, even if they come from "
    "different finding types or different suites -- do not simply echo one output pattern per "
    "input case. Return one recommendation per distinct pattern. Each recommendation must be "
    "concrete and specific to the evidence it covers (name the actual clause/edit/scenario), never "
    "generic boilerplate that would read identically for a different pattern. Each pattern must "
    "list exactly which case_id(s) (verbatim, from the input) it covers."
)


def _case_prompt_line(case: EvidenceCase) -> str:
    return (
        f"- case_id={case.case_id!r} finding_type={case.finding_type!r}\n"
        f"  remedy_menu: {case.remedy_menu}\n"
        f"  evidence: {case.evidence}"
    )


def _build_draft_messages(cases: list[EvidenceCase]) -> list:
    body = "\n".join(_case_prompt_line(case) for case in cases)
    return [
        SystemMessage(content=_DRAFT_SYSTEM_PROMPT),
        HumanMessage(content=f"Evidence cases ({len(cases)} total):\n{body}"),
    ]


def _draft_patterns(cases: list[EvidenceCase]) -> list[_Pattern]:
    """THE seam -- behavior tests patch this. Builds one message listing every case, calls the
    shared LLM structured-output seam, and returns the drafted patterns. Returns ``[]`` on any
    exception -- not just a transport/parse failure from ``call_with_retry``, but also a settings
    or client-construction error from ``load_llm_settings``/``build_llm`` (e.g. a malformed env
    var), or ``result`` coming back a shape ``.patterns`` can't be read off (``None``, or anything
    else unexpected) -- so the caller (``build_recommendations``) can always treat an empty result
    as "fall back to the deterministic grouping", never as a crash that would otherwise propagate
    out of ``pytest_sessionfinish`` and abort the per-cell report before it's written. The whole
    body stays inside one ``try`` on purpose (confirmed as a real finding in PR review: an earlier
    version only guarded the call itself, so a result that was present but the wrong shape still
    raised past this function).

    Also returns ``[]`` immediately, with no call attempted at all, when ``EVAL_RECOMMENDATIONS_LLM``
    is set to a falsy value -- see that env var's own module-level comment."""
    if os.environ.get(_RECOMMENDATIONS_LLM_ENV, "1").strip().lower() in ("0", "false", "no"):
        return []
    try:
        settings = load_llm_settings()
        runnable = build_llm(settings).with_structured_output(_PatternBatch)
        messages = _build_draft_messages(cases)
        result = call_with_retry(runnable, messages, settings=settings)
        # ``with_structured_output`` can return None instead of raising when the model's response
        # can't be coerced into the schema (e.g. it answered in plain text) -- treat that the same
        # as any other unusable response.
        if result is None:
            return []
        return result.patterns
    except Exception:
        return []


def _fallback_recommendations(cases: list[EvidenceCase], *, reason: str) -> list[Recommendation]:
    """One ``Recommendation`` per ``(finding_type, fallback_key)`` group, body a static,
    clearly-labeled note naming ``reason`` -- used for every case the LLM pattern analysis didn't
    cover. ``reason`` must say WHY, not always "unavailable": confirmed as a real finding in PR
    review -- a case can land here even when the LLM call succeeded and produced several good
    patterns, just not one covering THIS case, and "unavailable" would misleadingly suggest the
    whole call failed when most of the section is genuinely LLM-drafted."""
    groups: dict[tuple[str, str], list[EvidenceCase]] = {}
    for case in cases:
        groups.setdefault((case.finding_type, case.fallback_key), []).append(case)
    recommendations = []
    for (finding_type, fallback_key), group_cases in groups.items():
        recommendations.append(
            Recommendation(
                heading=f"{finding_type}: {fallback_key}",
                body=f"{reason} -- raw evidence grouped by {fallback_key}:",
                evidence=[case.evidence for case in group_cases],
            )
        )
    return recommendations


def build_recommendations(
    *,
    correctness: list[tuple[str, str, dict]],
    sensitivity: list[tuple[str, str, dict]],
    invariance: list[tuple[str, str, dict]],
    consistency: list[tuple[str, dict]],
    consistency_classification: str,
    scale_mistake: list[tuple[str, dict]],
) -> list[Recommendation]:
    """Orchestrator: calls all six case-builders to collect ``list[EvidenceCase]`` (pure, instant);
    if empty, returns ``[]`` with no LLM call. Otherwise calls ``_draft_patterns`` once; validates
    each returned pattern's ``case_ids`` against the known set (drops unknown/hallucinated ids,
    drops a pattern left with none). Any case left uncovered by every surviving pattern -- whether
    because the call failed outright, nothing survived validation, or the model simply omitted a
    case or gave it a hallucinated id -- goes through the deterministic ``(finding_type,
    fallback_key)`` grouping instead, so no case is ever silently dropped from the section (the
    module docstring's "never silently blank" guarantee extends to every individual case, not just
    to the section as a whole). Returns the final list sorted by heading for stable rendering.

    ``correctness`` feeds BOTH ``over_grant_cases`` and ``under_grant_cases`` -- the two findings
    read the same Correctness-suite entries (one looking at ``over_grants``, the other at
    ``under_grants``/``incorrectly_denied``), so there used to be two separate parameters a caller
    could (and once did) accidentally pass different lists to, silently producing an over-grant
    finding and an under-grant finding that don't actually agree on which run they describe. One
    parameter makes that impossible.

    A case id already claimed by an earlier pattern is skipped by every later one too (confirmed
    as a real finding in PR review: deduping only WITHIN one pattern still let the same case_id
    appear in two different patterns, so its evidence line -- and the failure it represents --
    showed up under two separate ``###`` recommendations)."""
    cases: list[EvidenceCase] = [
        *over_grant_cases(correctness),
        *under_grant_cases(correctness),
        *sensitivity_cases(sensitivity),
        *invariance_cases(invariance),
        *consistency_cases(consistency, consistency_classification),
        *scale_mistake_cases(scale_mistake),
    ]
    if not cases:
        return []

    cases_by_id = {case.case_id: case for case in cases}
    patterns = _draft_patterns(cases)

    recommendations: list[Recommendation] = []
    covered_ids: set[str] = set()
    for pattern in patterns:
        # dict.fromkeys dedupes while preserving order -- a pattern naming the same case_id twice,
        # or a case_id a PRIOR pattern already claimed, must not duplicate that case's evidence
        # line under two different recommendations.
        pattern_covered_ids = list(
            dict.fromkeys(cid for cid in pattern.case_ids if cid in cases_by_id and cid not in covered_ids)
        )
        if not pattern_covered_ids:
            continue
        covered_ids.update(pattern_covered_ids)
        recommendations.append(
            Recommendation(
                heading=pattern.heading,
                body=pattern.recommendation,
                evidence=[cases_by_id[case_id].evidence for case_id in pattern_covered_ids],
            )
        )

    uncovered_cases = [case for case in cases if case.case_id not in covered_ids]
    if uncovered_cases:
        # "unavailable" only when NOTHING from the LLM survived at all -- if other cases ARE
        # covered by a real pattern above, these specific ones were merely omitted/mis-id'd, a
        # different (and much less alarming) story than "the call failed".
        reason = (
            "LLM pattern analysis unavailable (no usable drafted pattern)"
            if not recommendations
            else "Not covered by the LLM pattern analysis (other cases in this run were)"
        )
        recommendations.extend(_fallback_recommendations(uncovered_cases, reason=reason))

    return sorted(recommendations, key=lambda rec: rec.heading)
