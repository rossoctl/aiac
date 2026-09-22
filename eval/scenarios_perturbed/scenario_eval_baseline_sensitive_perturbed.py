"""Semantic-sensitivity sibling of ``scenario_eval_baseline.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Unlike ``scenario_eval_baseline_perturbed.py`` (meaning-*preserving* reword), this sibling is
meaning-*changing*: it realizes the exact same edit as the mechanical tier's
``SENSITIVITY_EDITS["baseline"]`` (restriction_word — developers lose issue-tracker access,
narrowed to testers only) but expressed as a full natural paraphrase using "solely" rather than a
literal "only" insertion. Every entity NOT touched by the edit is copied verbatim from
``scenario_eval_baseline_perturbed.py`` — only ``user-role-developer``'s description and the paired
policy text change. The truth delta is identical to, and reused directly from,
``SENSITIVITY_EDITS["baseline"].removed``/``.added`` (see
``test_policy_pipeline_robustness.py``) — the delta is a property of the meaning change, not of
how it's expressed.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-baseline"
POLICY_FILE = "policy.eval_baseline_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_baseline_perturbed.py — the edit touches only the
# user-facing policy sentence and user-role-developer's own description below.

AGENTS: dict[str, dict] = {
    "repo-agent": {
        "description": (
            "An autonomous agent that acts for a user against a source-code repository, able to "
            "look at and change what's stored in it."
        ),
        "inbound_scopes": {
            "agent-scope-coder": (
                "Lets a holder use the repo agent's source-code abilities: looking at repository "
                "contents and changing them."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-coder": (
                "Covers both reading and writing source repository contents: listing files, "
                "reading them, creating new ones, and editing existing ones."
            ),
        },
    },
    "tracker-agent": {
        "description": (
            "An autonomous agent that acts for a user against an issue tracker, handling reading, "
            "filing, and updating issues along with their comment threads."
        ),
        "inbound_scopes": {
            "agent-scope-triager": (
                "Lets a holder use the tracker agent's issue-tracking abilities: reading and updating issues."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-triager": (
                "Covers both reading and writing on the issue tracker: reading, filing, updating, "
                "and commenting on issues and their threads."
            ),
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_baseline_perturbed.py.

TOOLS: dict[str, dict] = {
    "repo-tool": {
        "description": (
            "A capability provider for a source repository, carrying out read and write "
            "operations against what's stored in it."
        ),
        "scopes": {
            "tool-scope-repo-read": "Look at repository contents — file listings and file bodies — without changing anything.",
            "tool-scope-repo-write": "Add, edit, or remove repository contents, including committing file changes.",
        },
    },
    "tracker-tool": {
        "description": (
            "A capability provider for an issue tracker, carrying out read and write operations "
            "on issues and their comment threads."
        ),
        "scopes": {
            "tool-scope-tracker-read": "Look at issues and their comment threads without changing anything.",
            "tool-scope-tracker-write": "Open, edit, comment on, and close issues.",
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "dev-user": "user-role-developer",
    "test-user": "user-role-tester",
    "devops-user": "user-role-devops",
}

USER_PASSWORD = "password"

# The edit: user-role-developer's own description now disclaims tracker involvement, in different
# words than the mechanical tier's "works exclusively in source, with no involvement in the issue
# tracker" (SENSITIVITY_EDITS["baseline"].description_edits).
USER_ROLES: dict[str, str] = {
    "user-role-developer": (
        "Developer: an engineer who builds out the codebase and resolves bugs logged elsewhere. "
        "Works solely within the source tree — the issue tracker isn't part of the job."
    ),
    "user-role-tester": (
        "Tester: a QA specialist whose job is verifying quality and following defects through the "
        "issue tracker — filing them, triaging them, and keeping them updated. Doesn't touch the "
        "source tree."
    ),
    "user-role-devops": (
        "DevOps: handles deployment infrastructure and the runtime environment. Doesn't write "
        "source code and doesn't manage the issue tracker."
    ),
}

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation (it recomputes the expected truth from
# truth(scenario_eval_baseline) + SENSITIVITY_EDITS["baseline"]'s delta directly) — kept here,
# edited, purely so a reader isn't misled into thinking this module still grants developer
# tracker access.

INBOUND_PAIRS: list[tuple[str, str]] = [
    ("user-role-developer", "agent-scope-coder"),
    ("user-role-tester", "agent-scope-triager"),
]

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-coder", "tool-scope-repo-read"),
    ("agent-role-coder", "tool-scope-repo-write"),
    ("agent-role-triager", "tool-scope-tracker-read"),
    ("agent-role-triager", "tool-scope-tracker-write"),
]

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = [
    ("user-role-developer", "tool-scope-repo-read"),
    ("user-role-developer", "tool-scope-repo-write"),
    ("user-role-tester", "tool-scope-tracker-read"),
    ("user-role-tester", "tool-scope-tracker-write"),
]
