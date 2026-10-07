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

from dataclasses import dataclass

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from aiac.agent.llm import build_llm, call_with_retry, load_llm_settings


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


# Cap on how many (role, scope) pairs one gate contributes to one evidence string -- a large
# corpus (the Scale suite's total-corpus dimension in particular, ~9M tokens / hundreds of
# generated entities) can produce hundreds or thousands of under-granted pairs for a single
# finding, and every evidence string this module builds goes into ONE batched _draft_patterns
# request. An unbounded pair list there can overflow the model's context window outright, failing
# the whole batched call (and with it, every case's chance at an LLM-drafted recommendation, not
# just this one's) rather than just this one case's own detail.
_MAX_PAIRS_PER_GATE = 20


def format_pairs(pairs_by_gate: dict, *, sep: str = "; ", limit: int | None = _MAX_PAIRS_PER_GATE) -> str:
    """Render a ``{gate: [(role, scope), ...]}`` dict (as produced by ``ScenarioScore.over_grants``
    /``under_grants``/``incorrectly_denied``) as one line per non-empty gate joined by ``sep``, or
    ``"none"``. Shared with ``eval.conftest._format_pairs_dict``, which imports this and passes
    ``sep="\\n"``, ``limit=None`` for its unbounded, newline-per-gate Markdown rendering into the
    gitignored, human-read-only per-run report -- unbounded there is a deliberate choice (a reader
    may want every pair of even a 100-entity Scale-suite run, not a truncated sample), not an
    assumption that the pairs are always few. Every call site in THIS module instead keeps the
    defaults: ``sep="; "`` so a value stays single-line (both the per-case prompt line sent to the
    LLM and the fallback recommendation's evidence list would otherwise be corrupted by an embedded
    newline), and ``limit`` so one gate's pair list is capped at ``_MAX_PAIRS_PER_GATE`` with a
    trailing ``"... and N more"`` -- bounding what goes into the batched LLM request, which the
    Markdown report has no such reason to do."""
    if not pairs_by_gate:
        return "none"
    parts = []
    for gate, pairs in sorted(pairs_by_gate.items()):
        shown = pairs if limit is None else pairs[:limit]
        pair_str = ", ".join(f"({r}, {s})" for r, s in shown)
        omitted = len(pairs) - len(shown)
        if omitted > 0:
            pair_str = f"{pair_str}, ... and {omitted} more" if pair_str else f"... and {omitted} more"
        parts.append(f"{gate}: {pair_str}")
    return sep.join(parts)


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


def _pairs_not_in(pairs_by_gate: dict, other_by_gate: dict) -> dict:
    """``pairs_by_gate`` minus every pair already present in ``other_by_gate``, per gate -- drops a
    gate entirely once nothing is left. Used by ``under_grant_cases`` so ``incorrectly_denied``
    (normally a SUBSET of ``under_grants``) only ever adds evidence for the genuinely distinct edge
    case -- a pair that landed in BOTH -- instead of restating the same pairs twice."""
    result: dict = {}
    for gate, pairs in pairs_by_gate.items():
        other = set(other_by_gate.get(gate, []))
        remaining = [pair for pair in pairs if pair not in other]
        if remaining:
            result[gate] = remaining
    return result


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
    it). ``_pairs_not_in`` isolates exactly that: whatever's in ``incorrectly_denied`` but not
    already in ``under_grants``."""
    cases = []
    for suite, scenario, props in entries:
        under_grants = props.get("under_grants") or {}
        incorrectly_denied_only = _pairs_not_in(props.get("incorrectly_denied") or {}, under_grants)
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
    PRB was insensitive to, not just which suite caught it."""
    cases = []
    for suite, scenario, props in entries:
        if props.get("sensitive", True):
            continue
        edit_type = props.get("edit_type", "unknown")
        evidence = (
            f"{suite}/{scenario} (edit_type={edit_type}): perturbation={props.get('perturbation', '')!r}; "
            f"expected grants -> {format_pairs(props.get('expected_grants') or {})}; "
            f"actual grants -> {format_pairs(props.get('actual_grants') or {})}"
        )
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
    unwanted by definition."""
    cases = []
    for suite, scenario, props in entries:
        if props.get("invariant", True):
            continue
        evidence = (
            f"{suite}/{scenario}: perturbation={props.get('perturbation', '')!r}; "
            f"expected grants -> {format_pairs(props.get('expected_grants') or {})}; "
            f"actual grants -> {format_pairs(props.get('actual_grants') or {})}"
        )
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
        evidence = f"consistency/{scenario} ({classification}): mismatches -> {(props.get('mismatches') or 'none')!r}"
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
    Correctness, so there is no numeric degradation threshold to diff against)."""
    cases = []
    for suite, props in entries:
        over_grants = props.get("over_grants") or {}
        under_grants = props.get("under_grants") or {}
        incorrectly_denied = props.get("incorrectly_denied") or {}
        if not (over_grants or under_grants or incorrectly_denied):
            continue
        evidence = (
            f"{suite}: over-grants -> {format_pairs(over_grants)}; under-grants -> "
            f"{format_pairs(under_grants)}; incorrectly denied -> {format_pairs(incorrectly_denied)}"
        )
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
    raised past this function)."""
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


def _fallback_recommendations(cases: list[EvidenceCase]) -> list[Recommendation]:
    """One ``Recommendation`` per ``(finding_type, fallback_key)`` group, body a static,
    clearly-labeled note -- used when the LLM call failed or produced nothing usable."""
    groups: dict[tuple[str, str], list[EvidenceCase]] = {}
    for case in cases:
        groups.setdefault((case.finding_type, case.fallback_key), []).append(case)
    recommendations = []
    for (finding_type, fallback_key), group_cases in groups.items():
        recommendations.append(
            Recommendation(
                heading=f"{finding_type}: {fallback_key}",
                body=(
                    f"LLM pattern analysis unavailable (no usable drafted pattern) -- raw evidence "
                    f"grouped by {fallback_key}:"
                ),
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
    parameter makes that impossible."""
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
        # dict.fromkeys dedupes while preserving order -- a pattern naming the same case_id twice
        # must not duplicate that case's evidence line in the rendered recommendation.
        pattern_covered_ids = list(dict.fromkeys(cid for cid in pattern.case_ids if cid in cases_by_id))
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
        recommendations.extend(_fallback_recommendations(uncovered_cases))

    return sorted(recommendations, key=lambda rec: rec.heading)
