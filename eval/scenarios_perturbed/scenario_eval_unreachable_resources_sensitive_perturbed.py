"""Semantic-sensitivity sibling of ``scenario_eval_unreachable_resources.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Realizes the same edit as the mechanical tier's ``SENSITIVITY_EDITS["unreachable_resources"]``
(negation — front desk clerks lose all patient-records access), expressed as a full natural
paraphrase. As in the mechanical edit, ``agent-role-receptionist``'s own description is also
revoked directly (not left to an inferred cascade) — same rationale: a faithful PRB reading its
own unedited, still-granting description would have no textual reason to revoke it. Everything
else is copied verbatim from ``scenario_eval_unreachable_resources_perturbed.py``, including
``EXPECT_NO_REGO`` (``insurance-tool``'s unreachability is unrelated to this edit). The truth
delta is reused directly from ``SENSITIVITY_EDITS["unreachable_resources"].removed``.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-unreachable-resources"
POLICY_FILE = "policy.eval_unreachable_resources_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------

AGENTS: dict[str, dict] = {
    "intake-agent": {
        "description": (
            "An autonomous agent that handles patient intake on a user's behalf: booking "
            "appointments and reading and updating patient records."
        ),
        "inbound_scopes": {
            "agent-scope-receptionist": (
                "Lets a holder use the intake agent's patient-intake abilities — booking "
                "appointments and reading and updating patient records."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            # The edit: revoked directly, in different words than the mechanical tier's "Covers no
            # access to patient records" (SENSITIVITY_EDITS["unreachable_resources"].
            # description_edits) — grounds the outbound_target revoke in real text, not a cascade.
            "agent-role-receptionist": (
                "Covers no access to patient records whatsoever — neither reading them nor updating them."
            ),
        },
    },
    "billing-agent": {
        "description": (
            "An autonomous agent meant to handle patient billing and invoicing, stood up before "
            "the access policy that was supposed to cover it — no policy language yet says who "
            "may call it or what it may reach."
        ),
        "inbound_scopes": {
            "agent-scope-biller": (
                "Lets a holder use the billing agent's invoicing abilities — creating and reading "
                "patient invoices. Not yet handed to any user role in the policy text."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-biller": (
                "Covers both reading and writing patient invoices. Not yet handed to any target in the policy text."
            ),
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_unreachable_resources_perturbed.py.

TOOLS: dict[str, dict] = {
    "records-tool": {
        "description": (
            "A capability provider for patient records, carrying out read and write operations on "
            "what's stored in them."
        ),
        "scopes": {
            "tool-scope-records-read": "Look at patient records — demographics and visit history — without changing anything.",
            "tool-scope-records-write": "Create and update patient records.",
        },
    },
    "insurance-tool": {
        "description": (
            "A capability provider for insurance-coverage verification, performing lookups against "
            "a patient's insurance details. No agent role is ever handed its scope anywhere in the "
            "policy text — it's unreachable on purpose."
        ),
        "scopes": {
            "tool-scope-insurance-verify": (
                "Look up a patient's insurance coverage details. No agent role is ever handed this "
                "scope anywhere in the policy text — it's unreachable on purpose."
            ),
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "clerk-user": "user-role-front-desk-clerk",
}

USER_PASSWORD = "password"

# The edit, in different words than the mechanical tier's "NOT authorized to schedule appointments
# or access patient records at all" (SENSITIVITY_EDITS["unreachable_resources"].description_edits).
USER_ROLES: dict[str, str] = {
    "user-role-front-desk-clerk": (
        "Front Desk Clerk: entirely blocked from patient records — may neither read nor update "
        "them. Still has nothing to do with billing or insurance verification."
    ),
}

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation — kept here, edited, purely for a
# reader's benefit.

INBOUND_PAIRS: list[tuple[str, str]] = []

OUTBOUND_PAIRS: list[tuple[str, str]] = []

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = []

# --- Emergent unreachability -----------------------------------------------------------------
#
# Byte-identical to scenario_eval_unreachable_resources_perturbed.py — unrelated to this edit.

EXPECT_NO_REGO: frozenset[str] = frozenset({"billing-agent"})
