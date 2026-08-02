#!/usr/bin/env python3
"""Onboard the ``github-tool`` workload: ``POST /apply/service/{uuid}`` behind a port-forward to
the Controller, then capture the agent's ``.rego`` into ``generated/02-after-tool/`` — the second
pause's evidence. Onboarding the tool retroactively completes the agent's outbound gate (the tool
is a pure target: no ``.rego`` is emitted for it directly), so only the agent's two files are
copied, into a directory separate from ``01-after-agent/`` — the before/after diff is the point."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import scenario as scn
from _lib import GENERATED, capture_rego, connect_admin, load_config, note, ok, onboard, port_forward, resolve_service_id, say, writer_pod


def main() -> None:
    cfg = load_config()
    admin = connect_admin(cfg)

    say("1", "3", f"Resolve {scn.TOOL_WORKLOAD} service id")
    service_id = resolve_service_id(admin, cfg, f"{cfg.namespace}/{scn.TOOL_WORKLOAD}")
    note(f"service id: {service_id}")

    say("2", "3", "Onboard (POST /apply/service/{id}) — this drives the PRB and can take minutes")
    with port_forward(cfg.controller_target, namespace=cfg.controller_namespace, local_port=cfg.controller_local_port, remote_port=cfg.controller_remote_port) as base_url:
        onboard(cfg, base_url, service_id)
    ok("onboarding call returned 200")

    say("3", "3", "Capture generated Rego (agent's, retroactively completed)")
    rego_dir = GENERATED / "02-after-tool"
    pod = writer_pod(cfg)
    capture_rego(cfg, pod, rego_dir)
    for f in (cfg.inbound_rego, cfg.outbound_rego):
        ok(f"{rego_dir / f}")

    print(f"\nTool onboarded. Snapshot: {rego_dir}")
    print("Next: make show   (or: make dev / make test / make devops)")


if __name__ == "__main__":
    main()
