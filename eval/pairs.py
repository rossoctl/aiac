"""``(role, scope)`` pair-dict formatting -- split out of ``eval/recommendations.py`` (spec:
``docs/evaluation/eval-framework.md`` §9.1, issue #2472) so this module stays free of the heavy
LLM imports (``langchain_core``/``pydantic``/``aiac.agent.llm``) that module needs for its own
``_draft_patterns`` seam. ``eval/conftest.py`` is loaded for every pytest session that touches
``eval/`` -- including the plain offline unit lane, since ``eval/`` is in ``testpaths`` -- and
calls ``format_pairs`` (via ``_format_pairs_dict``) unconditionally to render every correctness-
suite entry's over-/under-grants, not just when an eval-marked suite actually ran (confirmed as a
real finding in PR review). Keeping ``format_pairs`` here instead of in ``eval.recommendations``
means ``eval/conftest.py`` itself never needs that heavy stack at all -- a broken/missing optional
LLM dependency now only breaks ``eval/test_recommendations.py``'s own collection (the one module
that actually exercises ``_draft_patterns``) and the recommendations feature at runtime, not
``conftest.py``'s hooks, which the ENTIRE ``eval/`` tree shares regardless of which suite is
running. This narrows the blast radius; it does not make the whole offline lane free of the
import, since ``eval/test_recommendations.py`` is untagged and collected by a bare ``pytest`` too,
and still needs those imports to test the LLM-calling code it covers. ``eval.recommendations``
itself imports ``format_pairs``/``pairs_not_in`` from here rather than keeping its own copy.
"""

from __future__ import annotations

# Cap on how many (role, scope) pairs one gate contributes to one evidence string -- a large
# corpus (the Scale suite's total-corpus dimension in particular, ~9M tokens / hundreds of
# generated entities) can produce hundreds or thousands of under-granted pairs for a single
# finding, and every evidence string eval.recommendations builds goes into ONE batched
# _draft_patterns request. An unbounded pair list there can overflow the model's context window
# outright, failing the whole batched call (and with it, every case's chance at an LLM-drafted
# recommendation, not just this one's) rather than just this one case's own detail.
MAX_PAIRS_PER_GATE = 20


def format_pairs(pairs_by_gate: dict, *, sep: str = "; ", limit: int | None = MAX_PAIRS_PER_GATE) -> str:
    """Render a ``{gate: [(role, scope), ...]}`` dict (as produced by ``ScenarioScore.over_grants``
    /``under_grants``/``incorrectly_denied``) as one line per non-empty gate joined by ``sep``, or
    ``"none"``. ``eval.conftest._format_pairs_dict`` passes ``sep="\\n"``, ``limit=None`` for its
    unbounded, newline-per-gate Markdown rendering into the gitignored, human-read-only per-run
    report -- unbounded there is a deliberate choice (a reader may want every pair of even a
    100-entity Scale-suite run, not a truncated sample), not an assumption that the pairs are
    always few. ``eval.recommendations`` instead keeps the defaults: ``sep="; "`` so a value stays
    single-line (both the per-case prompt line sent to the LLM and the fallback recommendation's
    evidence list would otherwise be corrupted by an embedded newline), and ``limit`` so one
    gate's pair list is capped at ``MAX_PAIRS_PER_GATE`` with a trailing ``"... and N more"`` --
    bounding what goes into the batched LLM request, which the Markdown report has no such reason
    to do."""
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


def pairs_not_in(pairs_by_gate: dict, other_by_gate: dict) -> dict:
    """``pairs_by_gate`` minus every pair already present in ``other_by_gate``, per gate -- drops a
    gate entirely once nothing is left. Used by ``eval.recommendations.under_grant_cases`` and
    ``scale_mistake_cases`` so ``incorrectly_denied`` (normally a SUBSET of ``under_grants``) only
    ever adds evidence for the genuinely distinct edge case -- a pair that landed in BOTH --
    instead of restating the same pairs twice."""
    result: dict = {}
    for gate, pairs in pairs_by_gate.items():
        other = set(other_by_gate.get(gate, []))
        remaining = [pair for pair in pairs if pair not in other]
        if remaining:
            result[gate] = remaining
    return result
