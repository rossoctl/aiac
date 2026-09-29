#!/usr/bin/env python3
"""Provision the demo's Keycloak users/roles, mount the PRB's policy.md on the Controller, run the
token-exchange Keycloak setup, and resolve + print both workloads' internal client UUIDs (the
trigger ids ``04-onboard-agent.py``/``05-onboard-tool.py`` need — the ``clientId`` is a slash-bearing
SPIFFE URI the single-segment ``/apply/service/{id}`` route can't carry).

``--skip-service-ids`` (``make users``) stops after steps 1-2, which need **no** deployed workload.
Steps 3-4 resolve the workloads' Keycloak clients and abort if they don't exist yet, so the live
path in ``demo.md`` — where deploying the workloads is itself the onboarding trigger, and therefore
must happen *after* the realm holds the users/roles/policy the PRB reads — runs this script flagged
first, and unflagged later (Part 6) once ``driver.sh``'s DEPLOY phase has registered both clients.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import scenario as scn
import setup_keycloak
from _lib import (
    connect_admin,
    ensure_agent_policy,
    load_config,
    note,
    ok,
    provision_realm_and_users,
    resolve_service_id,
    say,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-service-ids",
        action="store_true",
        help="stop after users/roles/policy.md; skip the steps that need the workloads deployed",
    )
    args = parser.parse_args()
    total = "2" if args.skip_service_ids else "4"

    cfg = load_config()

    say("1", total, "Provision users + roles (with the login-profile fix)")
    admin = connect_admin(cfg)
    provision_realm_and_users(admin, cfg)
    for username, role in scn.USERS.items():
        ok(f"{username} -> {role}")

    say("2", total, "Mount policy.md on the Controller")
    ensure_agent_policy(cfg)
    ok(f"policy.md mounted ({len(scn.POLICY_ABSTRACT.splitlines())} lines)")

    if args.skip_service_ids:
        note(
            f"skipping client-UUID resolution + token exchange — {scn.AGENT_WORKLOAD}/"
            f"{scn.TOOL_WORKLOAD} are not deployed yet, by design"
        )
        print("\nNext: ./driver.sh — its DEPLOY phase is the live onboarding trigger (demo.md Part 4)")
        return

    say("3", total, "Resolve client UUIDs + configure token exchange")
    agent_uuid = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.AGENT_WORKLOAD}")
    tool_uuid = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.TOOL_WORKLOAD}")
    note(f"{scn.AGENT_WORKLOAD} client uuid: {agent_uuid}")
    note(f"{scn.TOOL_WORKLOAD} client uuid: {tool_uuid}")
    setup_keycloak.run(admin, cfg, agent_uuid=agent_uuid)
    ok("token exchange configured")

    say("4", total, "Done")
    print(f"\nAgent service id: {agent_uuid}")
    print(f"Tool service id:  {tool_uuid}")
    print("\nNext: make onboard-agent")


if __name__ == "__main__":
    main()
