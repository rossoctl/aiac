#!/usr/bin/env python3
"""Onboard the ``github-tool`` workload: ``POST /apply/service/{uuid}`` behind a port-forward to
the Controller, then capture the agent's rego from its ``AuthorizationPolicy`` CR into
``generated/02-after-tool/`` — the second pause's evidence. Onboarding the tool retroactively
completes the agent's outbound gate (the tool is a pure target: no CR is emitted for it directly),
so only the agent's CR is captured, into a directory separate from ``01-after-agent/`` — the
before/after diff is the point."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import scenario as scn
import setup_keycloak
from _lib import (
    GENERATED, abort, capture_rego, cmd, connect_admin, explain, load_config, note, ok,
    onboard, pause, port_forward, print_state_before, print_state_diff, resolve_service_id,
    say, snapshot_state, tail_component_logs,
)


def main() -> None:
    cfg = load_config()
    admin = connect_admin(cfg)
    rego_dir = GENERATED / "02-after-tool"
    prior_dir = GENERATED / "01-after-agent"

    # Snapshot against 01-after-agent's rego (the last complete snapshot) so the "before" grant
    # sets reflect what's actually true right now, not an empty 02-after-tool that doesn't exist yet.
    before = snapshot_state(cfg, admin, prior_dir)

    say("1", "4", f"Resolve {scn.TOOL_WORKLOAD} service id")
    explain(f"""
        Same reason as the agent step: `/apply/service/{{id}}` needs {scn.TOOL_WORKLOAD}'s
        Keycloak-internal client UUID.
    """)
    print_state_before(before)
    service_id = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.TOOL_WORKLOAD}")
    note(f"service id: {service_id}")
    pause()

    say("2", "4", "Onboard (POST /apply/service/{id}) — this drives the PRB and can take minutes")
    explain(f"""
        {scn.TOOL_WORKLOAD} is a TOOL, not an agent, so Service Provision takes the OTHER branch
        this time: it queries {scn.TOOL_WORKLOAD}'s live MCP endpoint (`tools/list`) to discover
        its scopes directly from the tool's own manifest — no LLM involved in discovery itself.
        The Policy Rules Builder then re-reads the SAME policy.md against these newly-discovered
        tool scopes, and — because {scn.AGENT_WORKLOAD} already exists — this RETROACTIVELY
        completes {scn.AGENT_WORKLOAD}'s outbound gate: `target_scopes` gets keyed by
        {scn.TOOL_WORKLOAD}'s SPIFFE identity, and every role gets its per-scope grant. No CR is
        written for the tool itself — a tool is a pure target, so only {scn.AGENT_WORKLOAD}'s CR
        changes.

        Watch the component logs below for analyze_tool's discovered-scopes line and the PRB
        rebuilding {scn.AGENT_WORKLOAD}'s outbound rules against them.
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

    say("3", "4", "Capture generated Rego (agent's, retroactively completed — from the CR)")
    explain(f"""
        Reading {scn.AGENT_WORKLOAD}'s CR again — same mechanism as step 3 of the agent
        onboarding — but this time its outbound gate's maps are populated.
    """)
    cmd("Input", f"kubectl get authorizationpolicies.agent.rossoctl.dev {cfg.cr_name} -n {cfg.namespace} -o json")
    capture_rego(cfg, rego_dir)
    for f in (cfg.inbound_rego, cfg.outbound_rego):
        ok(f"{rego_dir / f}")
    pause()

    # The tool's ``*-aud`` audience client scope only exists once the tool is onboarded, so 03-setup.py
    # could not yet assign it as a default scope on the agent client. Do it now, so an exchanged token's
    # ``aud`` reaches the tool without the caller requesting the scope explicitly. Idempotent.
    say("4", "4", "Assign the tool-audience default scope to the agent client")
    explain(f"""
        This is Keycloak plumbing, not AIAC policy generation: it makes the agent's client
        request {scn.TOOL_WORKLOAD}'s audience scope BY DEFAULT, so the RFC 8693 token exchange
        `make dev`/`make test` perform later reaches the tool's audience without the caller
        asking for it explicitly. It could only run now — the `*-aud` scope is created by the
        operator once {scn.TOOL_WORKLOAD} exists.
    """)
    agent_uuid = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.AGENT_WORKLOAD}")
    tool_aud_scope = f"agent-{cfg.namespace}-{scn.TOOL_WORKLOAD}-aud"
    # Unlike 03-setup.py (which runs before the tool exists, so a missing scope is expected), here the
    # tool has just been onboarded — the ``*-aud`` scope must exist now. If it doesn't, the exchanged
    # token would lack the tool audience and downstream calls would silently fail, so abort rather
    # than report a success the token exchange can't back up.
    if not setup_keycloak.ensure_default_audience_scope(admin, cfg, agent_uuid, scn.AGENT_WORKLOAD, tool_aud_scope):
        abort(f"tool-audience scope {tool_aud_scope!r} not found after onboarding {scn.TOOL_WORKLOAD} — "
              "the agent's exchanged tokens would lack the tool audience; check the onboarding call above")

    after = snapshot_state(cfg, admin, rego_dir)
    print_state_diff(before, after)

    print(f"\nTool onboarded. Snapshot: {rego_dir}")
    print("Next: make show   (or: make dev / make test / make devops)")


if __name__ == "__main__":
    main()
