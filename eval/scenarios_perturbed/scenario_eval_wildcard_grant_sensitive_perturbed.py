"""Semantic-sensitivity sibling of ``scenario_eval_wildcard_grant.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Realizes the same edit as the mechanical tier's ``SENSITIVITY_EDITS["wildcard_grant"]``
(negation — inventory managers lose the wildcard grant entirely), expressed as a full natural
paraphrase. Everything else is copied verbatim from ``scenario_eval_wildcard_grant_perturbed.py``.
The truth delta is reused directly from ``SENSITIVITY_EDITS["wildcard_grant"].removed``.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-wildcard-grant"
POLICY_FILE = "policy.eval_wildcard_grant_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_wildcard_grant_perturbed.py.

AGENTS: dict[str, dict] = {
    "inventory-agent": {
        "description": (
            "An autonomous agent that acts for a user against the retail inventory system, "
            "handling every inventory operation the inventory tool offers: stock-level checks, "
            "count adjustments, and reorders."
        ),
        "inbound_scopes": {
            "agent-scope-stocker": (
                "Lets a holder use the inventory agent's complete set of inventory abilities — "
                "stock-level checks, count adjustments, and reorders."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-stocker": (
                "Covers every inventory operation against the inventory tool — stock-level "
                "checks, count adjustments, and reorders."
            ),
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_wildcard_grant_perturbed.py.

TOOLS: dict[str, dict] = {
    "inventory-tool": {
        "description": (
            "A capability provider for retail inventory management, handling stock-level checks, "
            "count adjustments, and reorders."
        ),
        "scopes": {
            "tool-scope-inventory-check": "Look up current stock levels for a product without changing anything.",
            "tool-scope-inventory-adjust": "Change the recorded stock count for a product.",
            "tool-scope-inventory-reorder": "Place a reorder for a product.",
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "manager-user": "user-role-inventory-manager",
}

USER_PASSWORD = "password"

# The edit, in different words than the mechanical tier's "NOT authorized to perform any
# inventory operations" (SENSITIVITY_EDITS["wildcard_grant"].description_edits).
USER_ROLES: dict[str, str] = {
    "user-role-inventory-manager": (
        "Inventory Manager: blocked from every inventory operation there is — no stock-level "
        "checks, no count adjustments, no reorders."
    ),
}

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation — kept here, edited, purely for a
# reader's benefit.

INBOUND_PAIRS: list[tuple[str, str]] = []

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-stocker", "tool-scope-inventory-check"),
    ("agent-role-stocker", "tool-scope-inventory-adjust"),
    ("agent-role-stocker", "tool-scope-inventory-reorder"),
]

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = []
