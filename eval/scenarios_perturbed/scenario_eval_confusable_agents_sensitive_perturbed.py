"""Semantic-sensitivity sibling of ``scenario_eval_confusable_agents.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Realizes the same edit as the mechanical tier's ``SENSITIVITY_EDITS["confusable_agents"]``
(negation — team trainers lose all roster/schedule access), expressed as a full natural
paraphrase. Everything else, including ``IDENTITY_CONFUSION_PROBES``, is copied verbatim from
``scenario_eval_confusable_agents_perturbed.py``. The truth delta is reused directly from
``SENSITIVITY_EDITS["confusable_agents"].removed``.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-confusable-agents"
POLICY_FILE = "policy.eval_confusable_agents_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_confusable_agents_perturbed.py.

AGENTS: dict[str, dict] = {
    "coach-agent": {
        "description": ("An autonomous agent that handles team rosters and practice schedules on a user's behalf."),
        "inbound_scopes": {
            "agent-scope-coach": ("Lets a holder use the coaching agent's roster and scheduling abilities."),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-coach": "Covers looking up the team roster and updating the practice schedule.",
        },
    },
    "coach-review-agent": {
        "description": (
            "An autonomous agent that records and looks up player performance evaluations on a "
            "user's behalf. Has nothing to do with rosters or scheduling — no overlap with "
            "coach-agent."
        ),
        "inbound_scopes": {
            "agent-scope-reviewer": ("Lets a holder use the coach-review agent's performance-evaluation abilities."),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-reviewer": ("Covers looking up and recording player performance evaluations."),
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_confusable_agents_perturbed.py.

TOOLS: dict[str, dict] = {
    "roster-tool": {
        "description": (
            "A capability provider for team rosters and practice schedules, handling lookups of "
            "the roster and updates to the practice schedule."
        ),
        "scopes": {
            "tool-scope-roster-read": "Look up the current team roster without changing anything.",
            "tool-scope-schedule-write": "Create and update the practice schedule.",
        },
    },
    "evaluation-tool": {
        "description": (
            "A capability provider for player performance evaluations, handling both lookups and "
            "updates of evaluation records."
        ),
        "scopes": {
            "tool-scope-evaluation-read": "Look up a player's performance evaluation records without changing anything.",
            "tool-scope-evaluation-write": "Create and update a player's performance evaluation records.",
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "trainer-user": "user-role-team-trainer",
    "analyst-user": "user-role-performance-analyst",
}

USER_PASSWORD = "password"

USER_ROLES: dict[str, str] = {
    # The edit, in different words than the mechanical tier's "NOT authorized to read the team
    # roster or update the practice schedule at all" (SENSITIVITY_EDITS["confusable_agents"].
    # description_edits).
    "user-role-team-trainer": (
        "Team Trainer: has no access to the team roster or the practice schedule at all. Still "
        "has nothing to do with performance evaluations."
    ),
    "user-role-performance-analyst": (
        "Performance Analyst: may look up and record player performance evaluations via the "
        "coach-review agent. Has nothing to do with rosters or scheduling."
    ),
}

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation — kept here, edited, purely for a
# reader's benefit.

INBOUND_PAIRS: list[tuple[str, str]] = [
    ("user-role-performance-analyst", "agent-scope-reviewer"),
]

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-coach", "tool-scope-roster-read"),
    ("agent-role-coach", "tool-scope-schedule-write"),
    ("agent-role-reviewer", "tool-scope-evaluation-read"),
    ("agent-role-reviewer", "tool-scope-evaluation-write"),
]

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = [
    ("user-role-performance-analyst", "tool-scope-evaluation-read"),
    ("user-role-performance-analyst", "tool-scope-evaluation-write"),
]

# --- Identity/boundary-confusion probes --------------------------------------------------------
#
# Byte-identical to scenario_eval_confusable_agents_perturbed.py — unrelated to this edit.

IDENTITY_CONFUSION_PROBES: list[tuple[str, str, bool]] = [
    ("service-account-coach-agent", "coach-review-agent", False),
    ("service-account-coach-review-agent", "coach-agent", False),
]
