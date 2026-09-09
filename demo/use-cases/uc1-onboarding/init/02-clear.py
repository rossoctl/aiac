#!/usr/bin/env python3
"""Reset the demo to a clean slate: delete UC-1's provisioned Keycloak roles/scopes, clear the
Policy Store (non-optional — its SQLite survives on a PV and onboarding appends with
``override=False``), delete the agent's ``AuthorizationPolicy`` CR (the reworked writer is
CR-backed — there is no ``/rego`` file to wipe), and clear the local ``generated/`` copy.

Kept separate from ``03-setup.py`` so a presenter can re-run just the reset between takes.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from _lib import GENERATED, cleanup_provisioned, clear_policy_store, clear_writer_rego, cmd, connect_admin, explain, load_config, ok, pause, say


def main() -> None:
    cfg = load_config()

    say("1", "4", "Clear Keycloak: delete github-agent.*/github-tool.* roles + scopes")
    explain("""
        Every prior onboarding run left realm roles/client scopes prefixed
        `github-agent.`/`github-tool.` in Keycloak — this is AIAC's own provisioned state, not
        the demo's fixed users/roles (developer/tester/devops stay untouched). Wiping it first
        is what makes "Pause 1 — baseline" in demo.md true: no github-* roles or scopes yet.
    """)
    admin = connect_admin(cfg)
    cleanup_provisioned(admin, cfg)
    ok("Keycloak provisioned entities cleared")
    pause()

    say("2", "4", "Clear Policy Store: DELETE /policy/services")
    explain("""
        The Policy Model Store's SQLite persists on a PV and onboarding appends
        (override=False), so a stale entry here would make the next onboard look like it built
        LESS than it should — this call is non-optional for a clean re-run.
    """)
    cmd("Input", f"DELETE {{store}}/policy/services  (port-forwarded to {cfg.store_target})")
    clear_policy_store(cfg)
    ok("Policy Store cleared")
    pause()

    say("3", "4", "Delete the agent's AuthorizationPolicy CR")
    explain("""
        This is the Policy Writer's own artifact — deleting it is what makes the NEXT `make
        agent` produce a genuinely fresh CR (server-side-apply) instead of merging onto
        yesterday's rules. There is no `.rego` file to delete separately; production writes CRs
        only.
    """)
    cmd("Input", f"kubectl delete authorizationpolicies.agent.rossoctl.dev {cfg.cr_name} -n {cfg.namespace} --ignore-not-found")
    clear_writer_rego(cfg)
    ok(f"deleted AuthorizationPolicy {cfg.cr_name!r} in {cfg.namespace!r} (if present)")
    pause()

    say("4", "4", "Clear local generated/ snapshots")
    explain("""
        generated/ is this demo's OWN evidence trail (the Rego copied out of the CR at each
        onboarding step) — clearing it keeps `make show`/`make diff` from reading a snapshot
        that no longer matches the cluster's actual state.
    """)
    if GENERATED.exists():
        shutil.rmtree(GENERATED)
    GENERATED.mkdir(parents=True, exist_ok=True)
    ok(f"cleared {GENERATED}")

    print("\nBaseline is clean.")


if __name__ == "__main__":
    main()
