"""Semantic-perturbation sibling of ``scenario_eval_empty_descriptions.py`` (spec:
``docs/evaluation/policy-eval-robustness-consistency.md``).

Unlike every other scenario in this directory, this module's descriptions are NOT reworded — they
are empty in the original by design (that scenario's whole point is that no semantic content is
available beyond the bare identifiers), so there is nothing to reword there. Only the paired policy
text (``policy.eval_empty_descriptions_perturbed.md``) is reworded, to exercise the same "policy
text is the only source of meaning" property under different phrasing. Every name, ``USERS``
entry, and pair-list is byte-identical to the original.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-empty-descriptions"
POLICY_FILE = "policy.eval_empty_descriptions_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------

AGENTS: dict[str, dict] = {
    "irrigation-agent": {
        "description": "",
        "inbound_scopes": {
            "agent-scope-grounds-worker": "",
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-grounds-worker": "",
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "valve-tool": {
        "description": "",
        "scopes": {
            "tool-scope-valve-open": "",
            "tool-scope-valve-close": "",
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "worker-user": "user-role-grounds-worker",
}

USER_PASSWORD = "password"

USER_ROLES: dict[str, str] = {
    "user-role-grounds-worker": "",
}

# --- Role -> access facts (name-level; the single source of truth) --------------------------

INBOUND_PAIRS: list[tuple[str, str]] = [
    ("user-role-grounds-worker", "agent-scope-grounds-worker"),
]

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-grounds-worker", "tool-scope-valve-open"),
    ("agent-role-grounds-worker", "tool-scope-valve-close"),
]

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = [
    ("user-role-grounds-worker", "tool-scope-valve-open"),
    ("user-role-grounds-worker", "tool-scope-valve-close"),
]
