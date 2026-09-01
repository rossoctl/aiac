"""Inline structural conflict detection for the assembled service policy (#2502).

After a ``build()`` assembles every pass's output (scope-focal grants + the Door B
user-role-focal deny pass) into one ``list[PolicyRule]``, :func:`detect_conflicts` runs a
**pure, deterministic** allow∩deny set-intersection over ``(role.id, scope.id)``: a pair carrying
**both** an ``Allow`` and a ``Deny`` **is** a conflict. There is no LLM anywhere in this module.

Per ADR 0001 (*identify-never-reconcile*) the detector NEVER merges, drops, or picks a winner —
it surfaces the overlap as a :class:`ConflictReport` so the build can **raise before**
``compute_and_apply`` (atomic-by-construction: a conflict leaves persisted state untouched). This
is the *cross-pass* structural **conflict**, distinct from the LLM auditor's *intra-pass*
``PolicyContradictionError`` (``graph.py``); the two are disjoint by construction.

At this ticket the report is the **structural** form: real ids, ``kind=DIRECT``, a synthesized
``explanation``, no quotes (``quotes_verified=False``). ``Conflict.focal`` anchors on the SCOPE
side (settled design Q16). Verbatim-quote enrichment and the 422-body wiring land in #2503.
"""

from aiac.policy.model.models import PolicyRule, RuleEffect

from .diagnostic_models import (
    Conflict,
    ConflictKind,
    ConflictReport,
    EntityRef,
    FocalRef,
    FocalType,
)


class PolicyConflictError(Exception):
    """Raised by the build when the assembled rules both grant and prohibit the same
    ``(role, scope)`` pair. Carries the structural :class:`ConflictReport` (real ids, ``DIRECT``,
    no quotes) so the caller can surface it. Raised **before** ``compute_and_apply`` so nothing is
    persisted (atomic-by-construction). This is a policy finding, not a builder fault — kept
    separate from ``PolicyContradictionError`` (the LLM auditor's intra-pass mechanism)."""

    def __init__(self, report: ConflictReport):
        self.report = report
        pairs = ", ".join(f"({c.role.name}, {c.scope.name})" for c in report.conflicts)
        super().__init__(
            f"Policy conflict: {len(report.conflicts)} (role, scope) pair(s) both "
            f"granted (Allow) and prohibited (Deny): {pairs}"
        )


def detect_conflicts(rules: list[PolicyRule]) -> ConflictReport:
    """Pure, deterministic allow∩deny detection over the assembled rule list — **no LLM**.

    A conflict is a ``(role.id, scope.id)`` pair present in BOTH the ``Allow`` set and the ``Deny``
    set. Detection is keyed on ids only (names are for display), so it is order-independent: the
    same rule list in any order yields the identical set of conflicts. Never reconciles — every
    overlap is surfaced as a :class:`Conflict`.

    Returns a :class:`ConflictReport`; the caller raises iff ``report.conflicts`` is non-empty.
    """
    allow: dict[tuple[str, str], PolicyRule] = {}
    deny: dict[tuple[str, str], PolicyRule] = {}
    for rule in rules:
        key = (rule.role.id, rule.scope.id)
        (deny if rule.effect is RuleEffect.DENY else allow)[key] = rule

    conflicts = [_to_conflict(allow[key]) for key in sorted(allow.keys() & deny.keys())]
    # evaluated_count = distinct (role, scope) pairs examined; non-zero when any pair exists so a
    # clean list derives NO_CONFLICT (not INCOMPLETE). The raise decision only reads ``conflicts``.
    return ConflictReport.from_survey(conflicts, [], evaluated_count=len(allow.keys() | deny.keys()))


def report_from_contradictions(focal: str, contradictions) -> ConflictReport:
    """Map an intra-pass ``PolicyContradictionError`` (the LLM auditor, ``graph.py``) into the SAME
    :class:`ConflictReport` shape the structural detector produces, so the 422 boundary has ONE
    report shape for both mechanisms (settled design Q15). **No LLM** — a shallow, deterministic
    re-shape at the handler.

    Lower-fidelity by nature: an auditor :class:`Contradiction` carries only name-strings (no ids,
    no quotes, no kind). So each colliding pair gets empty ids, ``kind=DIRECT``, empty quotes with
    ``quotes_verified=False``, and the auditor ``description`` as the ``explanation``. ``focal`` is
    parsed from the raise's focal string (``_role_focal`` / ``_scope_focal`` prefix) to recover the
    axis and name; the candidate name goes on the opposite side."""
    if focal.startswith("role name="):
        focal_type = FocalType.ROLE
        focal_name = focal[len("role name=") :].split(":", 1)[0].strip()
    elif focal.startswith("scope name="):
        focal_type = FocalType.SCOPE
        focal_name = focal[len("scope name=") :].split(":", 1)[0].strip()
    else:
        # Unrecognized focal string (e.g. a bare service token in a degenerate raise): anchor on
        # the SCOPE side (Q16) and use the whole string as the focal name.
        focal_type = FocalType.SCOPE
        focal_name = focal
    focal_ref = FocalRef(name=focal_name, id="", type=focal_type)

    conflicts: list[Conflict] = []
    for c in contradictions:
        candidate = EntityRef(name=c.candidate_name, id="")
        focal_entity = EntityRef(name=focal_name, id="")
        role, scope = (focal_entity, candidate) if focal_type is FocalType.ROLE else (candidate, focal_entity)
        conflicts.append(
            Conflict(
                focal=focal_ref,
                role=role,
                scope=scope,
                kind=ConflictKind.DIRECT,
                granting_quotes=[],
                prohibiting_quotes=[],
                explanation=c.description,
                quotes_verified=False,
            )
        )
    # evaluated_count=1: the focal entity WAS evaluated (the auditor ruled on it), so a non-empty
    # mapping derives CONFLICTS_FOUND (conflicts non-empty wins the precedence regardless).
    return ConflictReport.from_survey(conflicts, [], evaluated_count=1)


def _to_conflict(rule: PolicyRule) -> Conflict:
    """Build the structural :class:`Conflict` for one colliding ``(role, scope)`` pair. ``focal``
    anchors on the SCOPE side (Q16); quotes are empty and unverified (enrichment is #2503)."""
    role, scope = rule.role, rule.scope
    return Conflict(
        focal=FocalRef(name=scope.name, id=scope.id, type=FocalType.SCOPE),
        role=EntityRef(name=role.name, id=role.id),
        scope=EntityRef(name=scope.name, id=scope.id),
        kind=ConflictKind.DIRECT,
        granting_quotes=[],
        prohibiting_quotes=[],
        explanation=(
            f"Role '{role.name}' is both granted (Allow) and prohibited (Deny) on "
            f"scope '{scope.name}' — a direct grant/deny conflict on the same (role, scope) pair."
        ),
        quotes_verified=False,
    )
