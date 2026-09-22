"""Scenario 8 — misleading descriptions: 2 users, 1 agent, 1 tool, hospitality/hotel domain.

Companion to ``scenario_eval_baseline.py`` (Scenario 1) for ``test_policy_pipeline_eval.py`` (spec:
``docs/evaluation/policy-eval-scenarios.md``). Isolates one aspect: names lie,
descriptions are truth. Two misdirection devices, both name-level, neither backed by any real
extra access:

- **``user-role-vip-manager`` is a name-bait role.** The name suggests broad or elevated authority, but its
  description confines it to the same guest-service reads as any other front-desk role. The PRB
  must resolve access from the grant text, not the role name.
- **``tool-scope-master-override`` is an inert, scary-named scope.** It reads like a bypass/elevation
  capability but is a no-op diagnostic hook that grants nothing beyond itself — holding it would not
  unlock any additional real capability even if granted. It is *not* granted to anyone here (policy
  text: "...they may not invoke the master override control") — deliberately phrased as an explicit
  denial rather than a silent omission, so a future robustness sensitivity edit can remove the "not"
  (granting the inert scope back) as a meaning-changing edit in the opposite direction from this
  suite's other, revoke-something edits. ``user-role-vip-manager`` and ``user-role-front-desk-staff``
  end up with *identical* real access (``tool-scope-reservation-read`` + ``tool-scope-guest-notes-read``).

Pure data: no imports beyond ``__future__``, mirroring ``scenario_eval_baseline.py``.
"""

from __future__ import annotations

# --- Realm ------------------------------------------------------------------------------------

REALM_DEFAULT = "aiac-pp-eval-misleading-descriptions"
POLICY_FILE = "policy.eval_misleading_descriptions.md"

# --- Agents -------------------------------------------------------------------------------------

AGENTS: dict[str, dict] = {
    "team1/guest-services-agent": {
        "description": (
            "Autonomous Agent acting on a user's behalf against the hotel guest-services system. "
            "It reads reservation details and guest notes, and exposes a diagnostic no-op hook "
            "used for internal testing."
        ),
        "inbound_scopes": {
            "agent-scope-concierge": (
                "Scope granting use of the guest-services agent's reservation and guest-notes read capability."
            ),
        },
        "delegation_scopes": {},
        "roles": {
            "agent-role-concierge": (
                "Covers reading reservation details and guest notes, and invoking the diagnostic "
                "no-op hook."
            ),
        },
    },
}

# --- Tools --------------------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "reservation-tool": {
        "description": (
            "Capability provider Tool for hotel reservations and guest notes. It performs read "
            "operations on reservation details and guest notes, and exposes an inert diagnostic "
            "hook."
        ),
        "scopes": {
            "tool-scope-reservation-read": "Read a guest's reservation details. Read-only.",
            "tool-scope-guest-notes-read": "Read staff notes attached to a guest's profile. Read-only.",
            "tool-scope-master-override": (
                "Inert diagnostic hook used for internal testing."
            ),
        },
    },
}

# --- Users ----------------------------------------------------------------------------------

USERS: dict[str, str] = {
    "vip-user": "user-role-vip-manager",
    "frontdesk-user": "user-role-front-desk-staff",
}

USER_PASSWORD = "password"

USER_ROLES: dict[str, str] = {
    "user-role-vip-manager": (
        "VIP Manager — reads reservation details and guest notes via the "
        "guest-services agent."
    ),
    "user-role-front-desk-staff": (
        "Front Desk Staff — reads reservation details and guest notes through the guest-services agent."
    ),
}

# --- Role -> access facts (name-level; the single source of truth) --------------------------

INBOUND_PAIRS: list[tuple[str, str]] = [
    ("user-role-vip-manager", "agent-scope-concierge"),
    ("user-role-front-desk-staff", "agent-scope-concierge"),
]

OUTBOUND_PAIRS: list[tuple[str, str]] = [
    ("agent-role-concierge", "tool-scope-reservation-read"),
    ("agent-role-concierge", "tool-scope-guest-notes-read"),
    ("agent-role-concierge", "tool-scope-master-override"),
]

# user-role-vip-manager's name suggests elevated authority; its real access (below) is identical to
# user-role-front-desk-staff's. tool-scope-master-override is explicitly denied to everyone (no row
# here for it) despite being structurally reachable via agent-role-concierge (OUTBOUND_PAIRS above)
# — the inert scope is real and delegable, just not granted to any user role by this policy.
OUTBOUND_SUBJECT_PAIRS: list[tuple[str, str]] = [
    ("user-role-vip-manager", "tool-scope-reservation-read"),
    ("user-role-vip-manager", "tool-scope-guest-notes-read"),
    ("user-role-front-desk-staff", "tool-scope-reservation-read"),
    ("user-role-front-desk-staff", "tool-scope-guest-notes-read"),
]
