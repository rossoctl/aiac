#!/usr/bin/env python3
"""Provision the demo's Keycloak users/roles, mount the PRB's policy.md on the Controller, run the
token-exchange Keycloak setup, and resolve + print both workloads' internal client UUIDs (the
trigger ids ``04-onboard-agent.py``/``05-onboard-tool.py`` need — the ``clientId`` is a slash-bearing
SPIFFE URI the single-segment ``/apply/service/{id}`` route can't carry).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import scenario as scn
import setup_keycloak
from _lib import connect_admin, ensure_agent_policy, explain, load_config, note, ok, pause, provision_realm_and_users, resolve_service_id, say


def main() -> None:
    cfg = load_config()

    say("1", "4", "Provision users + roles (with the login-profile fix)")
    explain(f"""
        {scn.USERS!r}: three Keycloak users, one realm role each. These are the demo's FIXED
        human personas — the policy AIAC generates later grants/denies access by ROLE, so
        `dev-user` never needs its own rule, only `developer`'s does. Each realm role's
        DESCRIPTION (in scn.USER_ROLES) is exactly what the Policy Rules Builder reads later to
        match a role's capability against the policy text — this step is the PRB's future input,
        not just bookkeeping.
    """)
    admin = connect_admin(cfg)
    provision_realm_and_users(admin, cfg)
    for username, role in scn.USERS.items():
        ok(f"{username} -> {role}")
    pause()

    say("2", "4", "Mount policy.md on the Controller")
    explain(f"""
        This is the ENTIRE human input to the whole demo — two lines of plain English
        (scn.POLICY_ABSTRACT) mounted at /etc/aiac/policy.md on the Controller deployment. No
        YAML, no per-scope tables: the Policy Rules Builder reads this file verbatim at
        onboarding time and turns it into Rego. Mounting it now, before either workload is
        onboarded, means `make agent`/`make tool` later see the SAME policy text — this step
        only runs once per demo, not once per workload.
    """)
    ensure_agent_policy(cfg)
    ok(f"policy.md mounted ({len(scn.POLICY_ABSTRACT.splitlines())} lines)")
    pause()

    say("3", "4", "Resolve client UUIDs + configure token exchange")
    explain("""
        Two things the LATER onboarding calls need: (a) each workload's Keycloak-internal
        client UUID — the `/apply/service/{id}` route takes this UUID, not the slash-bearing
        SPIFFE-URI clientId; (b) RFC 8693 token exchange enabled on the agent's client, so a
        user's token can later be exchanged for one audienced at the tool. Both are Keycloak
        admin-API configuration — no AIAC component is involved yet.
    """)
    agent_uuid = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.AGENT_WORKLOAD}")
    tool_uuid = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.TOOL_WORKLOAD}")
    note(f"{scn.AGENT_WORKLOAD} client uuid: {agent_uuid}")
    note(f"{scn.TOOL_WORKLOAD} client uuid: {tool_uuid}")
    setup_keycloak.run(admin, cfg, agent_uuid=agent_uuid)
    ok("token exchange configured")
    pause()

    say("4", "4", "Done")
    print(f"\nAgent service id: {agent_uuid}")
    print(f"Tool service id:  {tool_uuid}")
    print("\nNext: make agent")


if __name__ == "__main__":
    main()
