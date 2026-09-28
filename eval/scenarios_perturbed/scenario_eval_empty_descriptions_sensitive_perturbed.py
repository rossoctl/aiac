"""Semantic-sensitivity sibling of ``scenario_eval_empty_descriptions.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Realizes the same edit as the mechanical tier's ``SENSITIVITY_EDITS["empty_descriptions"]``
(negation — grounds workers lose all valve access), expressed as a full natural paraphrase in the
policy text only. Like its `_perturbed` sibling, every description stays empty — this scenario's
whole point is that no semantic content is available beyond the bare identifiers, so the policy
text is the only signal, exactly as ``SENSITIVITY_EDITS["empty_descriptions"].description_edits``
is itself empty. Unlike an earlier revision (when the user role and agent role were named
``user-role-field-operator``/``agent-role-groundskeeper`` — two different words for the same
worker), the two roles now share one name, ``grounds-worker``, so the policy text's "Grounds
workers may not ..." phrasing directly names ``agent-role-grounds-worker`` too, with no apposition
trick needed to ground the cascade. The truth delta is reused directly from
``SENSITIVITY_EDITS["empty_descriptions"].removed``.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-empty-descriptions"
POLICY_FILE = "policy.eval_empty_descriptions_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_empty_descriptions_perturbed.py — every description stays "".

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

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation — kept here, edited, purely for a
# reader's benefit.

INBOUND_PAIRS: list[tuple[str, str]] = []

OUTBOUND_PAIRS: list[tuple[str, str]] = []

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = []
