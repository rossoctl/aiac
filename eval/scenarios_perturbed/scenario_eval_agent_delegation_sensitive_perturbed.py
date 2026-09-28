"""Semantic-sensitivity sibling of ``scenario_eval_agent_delegation.py`` (spec: #2467,
``docs/evaluation/policy-eval-robustness-consistency.md``).

Realizes the same edit as the mechanical tier's ``SENSITIVITY_EDITS["agent_delegation"]``
(role_swap — which of the two roles may have customs clearance carried out on the shipment's
behalf), expressed as a full natural paraphrase rather than a literal text swap. Everything not
touched by the swap is copied verbatim from ``scenario_eval_agent_delegation_perturbed.py``
(including ``agent-role-dispatcher``'s own description — unaffected, since the swap moves which
*user* role gets the capability, not what the agent role itself covers). The truth delta is
reused directly from ``SENSITIVITY_EDITS["agent_delegation"].removed``/``.added``.

Like its `_perturbed` sibling, lives under ``eval/scenarios_perturbed/`` even though the original
lives at ``test/system/`` top level, for the same uniformity reason.

Requires human sign-off before entering the corpus (spec §4) — see ``eval/scenarios_perturbed/
SIGNOFF.md``.

Pure data: no imports beyond ``__future__``, mirroring the original.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-agent-delegation"
POLICY_FILE = "policy.eval_agent_delegation_sensitive_perturbed.md"

# --- Agents -------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_agent_delegation_perturbed.py — the swap only touches which USER
# role's own description mentions customs clearance, below.

AGENTS: dict[str, dict] = {
    "dispatch-agent": {
        "description": (
            "An autonomous agent that coordinates shipment dispatch on a user's behalf: creating "
            "and updating shipment manifests, and able to hand off agent-scope-broker work to the "
            "customs agent as part of a coordinated shipment."
        ),
        "inbound_scopes": {
            "agent-scope-dispatcher": (
                "Lets a holder use the dispatch agent's shipment-coordination abilities — "
                "creating and updating manifests, and coordinating customs clearance for a "
                "shipment."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-dispatcher": (
                "Covers reading, creating, and updating shipment manifests, and handing off "
                "agent-scope-broker work to the customs agent as part of a coordinated shipment."
            ),
        },
    },
    "customs-agent": {
        "description": (
            "An autonomous agent that clears shipments through customs on a user's behalf, taking "
            "on clearance work handed off from the dispatch agent as part of a coordinated "
            "shipment. Has no tools of its own."
        ),
        "inbound_scopes": {},
        "delegation_scopes": {
            "agent-scope-broker": (
                "Lets a coordinating agent get a shipment cleared through customs on its behalf. "
                "Owned by the customs agent itself, not by a tool."
            ),
        },
        "roles": {},
    },
}

# --- Tools --------------------------------------------------------------------------------------
#
# Byte-identical to scenario_eval_agent_delegation_perturbed.py.

TOOLS: dict[str, dict] = {
    "manifest-tool": {
        "description": (
            "A capability provider for shipment manifests, handling both reads and writes of "
            "manifest contents and status."
        ),
        "scopes": {
            "tool-scope-manifest-read": "Look up shipment manifests — contents and status — without changing anything.",
            "tool-scope-manifest-write": "Create and update shipment manifests.",
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "coordinator-user": "user-role-shipment-coordinator",
    "dock-user": "user-role-dock-worker",
}

USER_PASSWORD = "password"

# The edit: swapped which role's description claims the customs-clearance capability, in
# different words than the mechanical tier's literal text swap.
USER_ROLES: dict[str, str] = {
    "user-role-shipment-coordinator": (
        "Shipment Coordinator: may create and update shipment manifests via the dispatch agent "
        "for routine loading and unloading. May not have customs clearance carried out on the "
        "shipment's behalf."
    ),
    "user-role-dock-worker": (
        "Dock Worker: may create and update shipment manifests via the dispatch agent, and may "
        "have customs clearance carried out on the shipment's behalf as part of that coordinated "
        "process."
    ),
}

# --- Role -> access facts (name-level; reflects the EDITED meaning) --------------------------
#
# Not read by test_prb_sensitive_to_semantic_perturbation — kept here, edited, purely for a
# reader's benefit.

INBOUND_PAIRS: list[tuple[str, str]] = [
    ("user-role-shipment-coordinator", "agent-scope-dispatcher"),
    ("user-role-dock-worker", "agent-scope-dispatcher"),
]

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-dispatcher", "tool-scope-manifest-read"),
    ("agent-role-dispatcher", "tool-scope-manifest-write"),
    ("agent-role-dispatcher", "agent-scope-broker"),
]

OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = [
    ("user-role-shipment-coordinator", "tool-scope-manifest-read"),
    ("user-role-shipment-coordinator", "tool-scope-manifest-write"),
    ("user-role-dock-worker", "tool-scope-manifest-read"),
    ("user-role-dock-worker", "tool-scope-manifest-write"),
    ("user-role-dock-worker", "agent-scope-broker"),
]
