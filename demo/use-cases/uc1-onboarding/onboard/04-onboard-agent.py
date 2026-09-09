#!/usr/bin/env python3
"""Onboard the ``github-agent`` workload: ``POST /apply/service/{uuid}`` behind a port-forward to
the Controller, then capture the generated rego from the agent's ``AuthorizationPolicy`` CR into
``generated/01-after-agent/`` — the first pause's evidence (before the tool exists, the agent's
outbound gate is still empty)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import scenario as scn
from _lib import (
    GENERATED, capture_rego, cmd, connect_admin, explain, load_config, note, ok, onboard,
    pause, port_forward, print_state_before, print_state_diff, resolve_service_id, say,
    snapshot_state, tail_component_logs,
)


def main() -> None:
    cfg = load_config()
    admin = connect_admin(cfg)
    rego_dir = GENERATED / "01-after-agent"

    before = snapshot_state(cfg, admin, rego_dir)

    say("1", "3", f"Resolve {scn.AGENT_WORKLOAD} service id")
    explain(f"""
        `/apply/service/{{id}}` (the route step 2 calls) takes {scn.AGENT_WORKLOAD}'s
        Keycloak-INTERNAL client UUID, not its clientId — {cfg.namespace}/{scn.AGENT_WORKLOAD}
        is a slash-bearing SPIFFE URI the single-segment URL path can't carry.
    """)
    print_state_before(before)
    service_id = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.AGENT_WORKLOAD}")
    note(f"service id: {service_id}")
    pause()

    say("2", "3", "Onboard (POST /apply/service/{id}) — this drives the PRB and can take minutes")
    explain(f"""
        This ONE HTTP call triggers the whole onboarding pipeline inside the Controller:
        (1) Service Provision classifies {scn.AGENT_WORKLOAD} (an agent, from its
        `rossoctl.io/type` pod label) and discovers its roles/scopes from its AgentCard CR's
        skills; (2) the Policy Rules Builder reads policy.md plus every realm role's
        description, and calls the LLM to decide, per candidate role/scope pair, whether the
        two-line policy grants or denies it — this is the only LLM call in the whole demo;
        (3) the Policy Writer renders the PRB's rules into two Rego files and server-side-applies
        them as the {scn.AGENT_WORKLOAD} AuthorizationPolicy CR. Because {scn.TOOL_WORKLOAD}
        isn't onboarded yet, the outbound gate comes back with every map still EMPTY — there is
        no tool for the agent to act on.

        The Controller and Policy Writer pods now stream their own logs below (added narration,
        Part 1) — watch for classify_service, PRB _propose/_audit, and PolicyWriter apply lines
        as this call is in flight.
    """)
    cmd("Input", f"POST /apply/service/{service_id}  (Controller, port-forwarded)")
    with tail_component_logs([
        ("controller", "aiac-agent", "aiac-system", None),
        ("policy-writer", "aiac-interface", "aiac-system", "aiac-pdp-policy-opa"),
    ]):
        with port_forward(cfg.controller_target, namespace=cfg.controller_namespace, local_port=cfg.controller_local_port, remote_port=cfg.controller_remote_port, ready_url=f"http://127.0.0.1:{cfg.controller_local_port}/health") as base_url:
            onboard(cfg, base_url, service_id)
    ok("onboarding call returned 200")
    pause()

    say("3", "3", "Capture generated Rego (from the AuthorizationPolicy CR)")
    explain(f"""
        The Policy Writer wrote CRs only (no `.rego` file dump in production) — this reads the
        SAME artifact a live enforcement point would (`kubectl get authorizationpolicies... -o
        json`) and copies `spec.policies[].content` locally, so the rest of this demo can `opa
        eval` against it.
    """)
    cmd("Input", f"kubectl get authorizationpolicies.agent.rossoctl.dev {cfg.cr_name} -n {cfg.namespace} -o json")
    capture_rego(cfg, rego_dir)
    for f in (cfg.inbound_rego, cfg.outbound_rego):
        ok(f"{rego_dir / f}")

    after = snapshot_state(cfg, admin, rego_dir)
    print_state_diff(before, after)

    print(f"\nAgent onboarded. Snapshot: {rego_dir}")
    print("Next: make show   (or: make tool)")


if __name__ == "__main__":
    main()
