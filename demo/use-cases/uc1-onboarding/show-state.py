#!/usr/bin/env python3
"""Show the demo's current state: live Keycloak roles/scopes, and the generated Rego for a
snapshot. Serves all three pauses (baseline, after-agent, after-tool) from one implementation.

    show-state.py                    # latest snapshot (or "no policy generated yet" at baseline)
    show-state.py --snapshot NAME    # a specific generated/<NAME> snapshot
    show-state.py --diff PRIOR       # diff the current default snapshot against generated/<PRIOR>

A snapshot holds one CR per managed service (D20): the agent's, and the tool's once the tool is
onboarded. Under target side (the default) the agent's outbound is a pass-through and the tool's
inbound decides each tool call; under agent side the agent's outbound decides it and the tool's CR
is a pass-through. The tool-call grants are read from the package that decides.

The diff narrates the raw ``.rego`` text (line-oriented, so a presenter can see it) but only
*asserts* on order-independent ``(role, scope)`` sets — the writer's list ordering is not stable
across runs, and a text diff on unstable ordering would show noise, not signal.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

import scenario as scn
from _lib import GENERATED, abort, connect_admin, is_pass_through, load_config, note, opa_eval, rule, say, table


def latest_snapshot() -> Path | None:
    if not GENERATED.exists():
        return None
    snapshots = sorted(p for p in GENERATED.iterdir() if p.is_dir())
    return snapshots[-1] if snapshots else None


def show_keycloak(admin, cfg) -> None:
    admin.change_current_realm(cfg.realm)
    say("A", "B", "Live Keycloak state")

    print("  Users + roles:")
    for username, role in scn.USERS.items():
        print(f"    {username:14s} -> {role}")

    all_roles = {r["name"]: r.get("description", "") for r in admin.get_realm_roles()}
    prefixes = (f"{scn.AGENT_WORKLOAD}.", f"{scn.TOOL_WORKLOAD}.")
    provisioned_roles = {n: d for n, d in all_roles.items() if n.startswith(prefixes)}
    print(f"\n  Provisioned operator roles ({scn.AGENT_WORKLOAD}.*): {len(provisioned_roles) or 'none yet'}")
    for name, desc in sorted(provisioned_roles.items()):
        note(f"{name} — {desc}")

    all_scopes = {s["name"]: s.get("description", "") for s in admin.get_client_scopes()}
    provisioned_scopes = {n: d for n, d in all_scopes.items() if n.startswith(prefixes)}
    print(
        f"\n  Provisioned client scopes ({scn.AGENT_WORKLOAD}.*/{scn.TOOL_WORKLOAD}.*): {len(provisioned_scopes) or 'none yet'}"
    )
    for name, desc in sorted(provisioned_scopes.items()):
        note(f"{name} — {desc}")


def snapshot_files(cfg) -> tuple[str, ...]:
    """The snapshot-relative Rego paths: the agent's CR, then the tool's CR."""
    return (cfg.inbound_rego, cfg.outbound_rego, cfg.tool_inbound_rego, cfg.tool_outbound_rego)


def grant_sets(cfg, rego_dir: Path) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """The ``(user role, agent scope)`` inbound grants and the ``(user role, tool)`` tool-call grants."""
    inbound_rego = rego_dir / cfg.inbound_rego
    outbound_rego = rego_dir / cfg.outbound_rego
    # Inbound values stay FULL agent-scope names (not de-prefixed) — the inbound gate compares
    # subject_role_allow_scopes against agent_scopes internally, never against input.mcp.params.name.
    role_scopes = opa_eval([inbound_rego], "data.authbridge.client.inbound.request.subject_role_allow_scopes", {}) or {}
    agent_scopes = set(opa_eval([inbound_rego], "data.authbridge.client.inbound.request.agent_scopes", {}) or [])
    inbound = {(role, scope) for role, scopes in role_scopes.items() for scope in scopes if scope in agent_scopes}

    # The tool-call user gate: under target side in the tool's inbound (absent until the tool is
    # onboarded), under agent side in the agent's outbound. Its values are BARE de-prefixed tools.
    if is_pass_through(outbound_rego, "outbound"):
        tool_inbound_rego = rego_dir / cfg.tool_inbound_rego
        if not tool_inbound_rego.is_file():
            return inbound, set()
        query = "data.authbridge.client.inbound.request.subject_role_allow_scopes"
        subj_scopes = opa_eval([tool_inbound_rego], query, {}) or {}
        return inbound, {(role, tool) for role, tools in subj_scopes.items() for tool in tools}
    # Agent side: the agent's outbound map is keyed by role and then by the full target service id
    # (LIM-02), so only the tool's own target gives its grants, as the tool's inbound does above.
    query = "data.authbridge.client.outbound.request.subject_role_allow_scopes"
    by_role = opa_eval([outbound_rego], query, {}) or {}
    tool_calls = {
        (role, tool)
        for role, by_target in by_role.items()
        for target, tools in by_target.items()
        if _is_tool_target(cfg, target)
        for tool in tools
    }
    return inbound, tool_calls


def _is_tool_target(cfg, service_id: str) -> bool:
    """True when ``service_id`` (a target key of the agent's outbound) is the demo tool's clientId:
    the CR that it names (the SPIFFE ``ns``/``sa`` segments, or a plain ``<ns>/<name>``) is
    ``cfg.namespace``/``cfg.tool_cr_name``."""
    match = re.fullmatch(r"spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)", service_id)
    return (match.groups() if match else tuple(service_id.split("/"))) == (cfg.namespace, cfg.tool_cr_name)


def show_snapshot(cfg, rego_dir: Path) -> None:
    say("B", "B", f"Generated policy: {rego_dir.relative_to(GENERATED.parent)}")
    files_present = [f for f in snapshot_files(cfg) if (rego_dir / f).is_file()]
    if not files_present:
        print("  (no policy generated yet)")
        return

    for f in files_present:
        rule()
        print(f"  {f}:")
        print((rego_dir / f).read_text())

    # grant_sets loads BOTH Rego files of the agent's CR; an interrupted capture that left only one
    # would abort here after printing partial state. Only tally grants when the snapshot is complete.
    if not _complete(cfg, rego_dir):
        rule()
        print("  (incomplete snapshot — grant tallies need both Rego files of the agent's CR; skipping)")
        return

    inbound, tool_calls = grant_sets(cfg, rego_dir)
    rule()
    print(f"  inbound grants (who may call {scn.AGENT_WORKLOAD}):  {len(inbound)}")
    table(sorted(inbound), headers=("role", "agent scope"))
    print(f"\n  tool-call grants (who may call which {scn.TOOL_WORKLOAD} tool): {len(tool_calls)}")
    if tool_calls:
        table(sorted(tool_calls), headers=("role", "tool scope"))


def _complete(cfg, d: Path) -> bool:
    """True only when both Rego files of the agent's CR are present — grant_sets loads both, so a
    half-captured snapshot cannot be diffed. (The tool's CR exists only after the tool is onboarded.)"""
    return (d / cfg.inbound_rego).is_file() and (d / cfg.outbound_rego).is_file()


def _read_lines(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.is_file() else []


def show_diff(cfg, prior_name: str, current_dir: Path) -> None:
    prior_dir = GENERATED / prior_name
    if not _complete(cfg, prior_dir):
        abort(
            f"prior snapshot {prior_name!r} is incomplete under {prior_dir} — need both "
            f"{cfg.inbound_rego} and {cfg.outbound_rego}. Run the earlier onboarding step first, "
            "or pass a snapshot that exists."
        )
    if not _complete(cfg, current_dir):
        abort(
            f"current snapshot {current_dir} is incomplete — need both {cfg.inbound_rego} and "
            f"{cfg.outbound_rego}. Re-run the onboarding step that captures it."
        )
    say("B", "B", f"Diff: {prior_dir.name} -> {current_dir.name}")

    # Narrate the raw Rego text first (line-oriented, so a presenter can see exactly what changed),
    # then assert on the order-independent (role, scope) sets below. A file that one snapshot does
    # not have (the tool's CR before the tool is onboarded) diffs as empty.
    for f in snapshot_files(cfg):
        rule()
        print(f"  {f}:")
        diff = difflib.unified_diff(
            _read_lines(prior_dir / f),
            _read_lines(current_dir / f),
            fromfile=f"{prior_dir.name}/{f}",
            tofile=f"{current_dir.name}/{f}",
            lineterm="",
        )
        lines = list(diff)
        print("\n".join(lines) if lines else "  (no textual change)")
    rule()

    prior_in, prior_out = grant_sets(cfg, prior_dir)
    cur_in, cur_out = grant_sets(cfg, current_dir)

    print("  inbound:")
    print(f"    + added:   {sorted(cur_in - prior_in) or 'none'}")
    print(f"    - removed: {sorted(prior_in - cur_in) or 'none'}")
    print("  tool calls:")
    print(f"    + added:   {sorted(cur_out - prior_out) or 'none'}")
    print(f"    - removed: {sorted(prior_out - cur_out) or 'none'}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", help="generated/<NAME> to show (default: latest)")
    parser.add_argument("--diff", help="prior generated/<NAME> to diff against the default snapshot")
    args = parser.parse_args()

    cfg = load_config()
    admin = connect_admin(cfg)
    show_keycloak(admin, cfg)

    if args.snapshot:
        rego_dir = GENERATED / args.snapshot
    else:
        rego_dir = latest_snapshot() or GENERATED / "baseline"

    show_snapshot(cfg, rego_dir)

    if args.diff:
        show_diff(cfg, args.diff, rego_dir)


if __name__ == "__main__":
    main()
