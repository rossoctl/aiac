"""LLM enrichment of a structural ``ConflictReport`` (#2503).

``detect_conflicts`` (#2502, :mod:`conflict_detection`) finds allow∩deny ``(role, scope)`` overlaps
**deterministically** and returns a *structural* :class:`ConflictReport`: real ids,
``kind=DIRECT``, a synthesized ``explanation``, and no quotes (``quotes_verified=False``). This
module upgrades EXACTLY those already-found pairs — never a blind full re-survey — by running the
diagnostic ``explain``/quote pass over each one to (1) classify the ``kind`` (``direct`` vs
``coarse_scope``) and (2) extract verbatim, substring-validated ``granting_quotes`` /
``prohibiting_quotes`` from the candidate policy text.

It is invoked by ``ServicePolicyBuilder.build()`` **only when** ``detect_conflicts`` returns
conflicts, so a clean apply makes ZERO explain-LLM calls (the explain seam is
:func:`_explain_pair`). The pairs are fixed (the structural detector's output); each is explained
once against the candidate ``policy_text``. On ANY quote-validation failure the conflict is KEPT
with ``quotes_verified=False`` and the explanation falls back to the structural synthesized
description (ADR 0001: surface, never drop — reversing handoff-07 Q15/Q16, which had decided the
on-``/apply`` report would be quote-less / no-LLM).
"""

from aiac.policy.model.models import PolicyRule

from .diagnostic import ExplainResult, _verify_quote
from .diagnostic_models import Conflict, ConflictReport
from .graph import _role_focal, _scope_focal, _structured_call
from .prompts import build_explain_messages


def _explain_pair(policy_text: str, role, scope, hint: str) -> ExplainResult:
    """THE explain seam for enrichment — one structured LLM call per already-confirmed colliding
    pair. Isolated so a deterministic test can patch it and assert it is NEVER called on a clean
    apply, and so the same ``graph._structured_call`` transport-retry path drives it as the live
    proposer/auditor. ``role`` / ``scope`` are the typed IdP objects (descriptions feed the prompt);
    ``hint`` is the structural synthesized explanation used purely to locate/classify the collision."""
    return _structured_call(
        ExplainResult,
        build_explain_messages(policy_text, _role_focal(role), _scope_focal(scope), hint),
    )


def enrich_report(report: ConflictReport, rules: list[PolicyRule], policy_text: str) -> ConflictReport:
    """Return ``report`` with every conflict enriched with a classified ``kind`` + validated quotes.

    ``rules`` is the assembled rule list — it supplies the full typed ``Role`` / ``Scope`` objects
    (with descriptions) for each colliding ``(role.id, scope.id)`` pair; ``policy_text`` is the
    candidate prose each quote is validated against with the engine's own :func:`_verify_quote`
    (whitespace-normalized substring). Each conflict is explained exactly once (no full re-survey,
    never abort on the first). Quotes are verified only when there is at least one quote AND every
    quote is a verbatim substring; otherwise the conflict is kept with ``quotes_verified=False`` and
    the explanation falls back to the structural synthesized description. ``status`` is unchanged
    (the conflict set is neither grown nor shrunk — enrichment never reconciles)."""
    typed = {(r.role.id, r.scope.id): (r.role, r.scope) for r in rules}
    enriched: list[Conflict] = []
    for c in report.conflicts:
        role, scope = typed[(c.role.id, c.scope.id)]
        result = _explain_pair(policy_text, role, scope, c.explanation)
        granting = list(result.granting_quotes)
        prohibiting = list(result.prohibiting_quotes)
        verified = bool(granting or prohibiting) and all(_verify_quote(q, policy_text) for q in granting + prohibiting)
        enriched.append(
            c.model_copy(
                update={
                    "kind": result.kind,
                    "granting_quotes": granting,
                    "prohibiting_quotes": prohibiting,
                    "explanation": result.explanation if verified else c.explanation,
                    "quotes_verified": verified,
                }
            )
        )
    return report.model_copy(update={"conflicts": enriched})
