"""Cross-service conflict awareness for the assembled service policy (#2504).

``detect_conflicts`` (#2502, :mod:`aiac.agent.policy_rules_builder.conflict_detection`) is a pure
allow∩deny set-intersection over the rules **one** ``build()`` assembles — so it sees only the
service currently being applied. An ``Allow`` produced by one build and a ``Deny`` already applied
by another for the SAME ``(role.id, scope.id)`` pair therefore go unseen: each build looks only at
its own output. This module supplies the missing half — the **already-applied** rules of the OTHER
services, read from the Policy Store — so the builder can run the very same #2502 intersection over
the COMBINED (about-to-be-persisted) state and surface a cross-service overlap with the SAME
:class:`ConflictReport` shape.

It lives in the onboarding **use-case** layer (next to ``builder.py``), NOT in the PRB package:
the PRB stays pure and store-free (guarded by ``test_isolation``), and reading already-applied
state is a use-case concern — the same layer that afterwards drives ``compute_and_apply``.

It never merges, dedupes, or picks a winner (ADR 0001 — *identify, never reconcile*): it only
**widens the input** the deterministic detector sees. There is no LLM here and no new report shape
— the combined list feeds ``detect_conflicts`` (#2502) and, only on a hit, ``enrich_report``
(#2503) unchanged. It is read-only (it mutates no store state), so the atomicity guarantee holds:
the builder still raises **before** ``compute_and_apply``.
"""

import logging

from fastapi import HTTPException

from aiac.policy.model.models import PolicyRule
from aiac.policy.model_store.library.api import get_service_policy

logger = logging.getLogger(__name__)


def applied_rules_for_scopes(rules: list[PolicyRule]) -> list[PolicyRule]:
    """Read every already-applied inbound rule (``Allow`` AND ``Deny``) on the scopes the
    about-to-be-applied ``rules`` touch, from the Policy Store — the OTHER services' contribution
    to the combined state the detector must see.

    The PCE persists every rule as an inbound edge on ``SPM(scope.serviceId)`` — the service that
    *owns* the rule's scope. So the already-applied rules that could collide with a new
    ``(role, scope)`` rule are exactly the inbound edges of the SPMs owning the scopes this build
    touches. We fetch each such SPM **once** (deduped, sorted for determinism) and return its
    combined inbound allow+deny edges. Onboarding applies append-only (``override=False``), so those
    edges are precisely what persists alongside the new rules — making the union the honest
    post-apply state to detect over.

    A brand-new scope owner has no stored SPM (``get_service_policy`` returns a fresh empty SPM on
    404), contributing nothing. Order-independent and side-effect-free (reads only) — it never
    mutates the store, preserving the build's atomic-before-``compute_and_apply`` guarantee."""
    owners = sorted({rule.scope.serviceId for rule in rules if rule.scope.serviceId})
    applied: list[PolicyRule] = []
    for owner in owners:
        try:
            spm = get_service_policy(owner)
        except Exception as exc:
            # Fail CLOSED, never best-effort. A store-read failure (network/auth/malformed row;
            # a genuine 404 is already absorbed as a fresh empty SPM inside get_service_policy)
            # means we are BLIND to this owner's already-applied rules. Silently treating that as
            # "no other services applied" would suppress cross-service detection and let a real
            # ALLOW∩DENY overlap persist -- a false-negative that defeats #2504's whole purpose.
            # So we abort the apply instead. An unreachable Policy Store is a dependency fault, not
            # a policy-input problem, so it surfaces as 502 (mirrors resolve_focal_entities' IdP
            # boundary) rather than the 422 ConflictReport reserved for genuine conflicts, and never
            # as an unhandled 500.
            # The exception (and the owner id) are logged server-side only. The client-facing 502
            # detail is a STABLE, generic string with no ``exc`` text and no id -- a store error can
            # carry an internal URL, host, or credential fragment, so echoing it into the HTTP body
            # would be an information-disclosure leak (CWE-209). ``from exc`` keeps the cause in the
            # server-side traceback without surfacing it to the caller.
            logger.warning(
                "cross-service store read failed for owner %s; aborting apply (fail-closed)", owner, exc_info=True
            )
            raise HTTPException(
                status_code=502,
                detail="policy store unreachable while resolving cross-service rules",
            ) from exc
        applied.extend(spm.inbound_allow_rules)
        applied.extend(spm.inbound_deny_rules)
    return applied
