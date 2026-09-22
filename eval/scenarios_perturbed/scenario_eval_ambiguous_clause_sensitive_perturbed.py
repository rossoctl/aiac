"""Semantic-sensitivity sibling of ``scenario_eval_ambiguous_clause.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Realizes the same edit as the mechanical tier's ``SENSITIVITY_EDITS["ambiguous_clause"]``
(negation — enrollment advisors lose all enrollment-lookup access), expressed as a full natural
paraphrase. Everything else is copied verbatim from ``scenario_eval_ambiguous_clause_perturbed.py``.
The truth delta is reused directly from ``SENSITIVITY_EDITS["ambiguous_clause"].removed``.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-ambiguous-clause"
POLICY_FILE = "policy.eval_ambiguous_clause_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_ambiguous_clause_perturbed.py.

AGENTS: dict[str, dict] = {
    "registrar-agent": {
        "description": (
            "An autonomous agent that acts for a user against the student enrollment system, "
            "looking up a student's current enrollment status and past enrollment record."
        ),
        "inbound_scopes": {
            "agent-scope-registrar": (
                "Lets a holder use the registrar agent's current-enrollment-status lookup ability."
            ),
            "agent-scope-archivist": ("Lets a holder use the registrar agent's enrollment-history lookup ability."),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-registrar": (
                "Covers looking up a student's current enrollment status and past enrollment record."
            ),
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_ambiguous_clause_perturbed.py.

TOOLS: dict[str, dict] = {
    "enrollment-tool": {
        "description": (
            "A capability provider for student enrollment records, performing lookups of a "
            "student's current status and past enrollment record."
        ),
        "scopes": {
            "tool-scope-enrollment-status": (
                "Look up a student's current enrollment status (enrolled, withdrawn, or on leave). No write access."
            ),
            "tool-scope-enrollment-history": (
                "Look up a student's past enrollment record across terms, including earlier status "
                "changes. No write access."
            ),
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "advisor-user": "user-role-enrollment-advisor",
}

USER_PASSWORD = "password"

# The edit, in different words than the mechanical tier's "NOT authorized to access enrollment
# information" (SENSITIVITY_EDITS["ambiguous_clause"].description_edits).
USER_ROLES: dict[str, str] = {
    "user-role-enrollment-advisor": (
        "Enrollment Advisor: not permitted to look up enrollment information of any kind, for "
        "advising purposes or otherwise."
    ),
}

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation — kept here, edited, purely for a
# reader's benefit.

INBOUND_PAIRS: list[tuple[str, str]] = []

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-registrar", "tool-scope-enrollment-status"),
    ("agent-role-registrar", "tool-scope-enrollment-history"),
]

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = []
