"""Onboard a DAM agent with aiac: description -> per-MCP-tool ALLOW/DENY.

The DAM counterpart of aiac's UC1 role path. DAM has no Keycloak roles or
AuthBridge sidecars, so this adapter builds aiac's own typed inputs from DAM
facts and calls aiac's unmodified Policy Rules Builder:

- Role: the DAM agent (Agent CR ``spec.name`` / ``spec.description``), kind AGENT.
- Scopes: one per tool of an MCP connection the agent holds, named
  ``<connection>.<tool>``, with the tool's own description.
- Policy: the organisation policy in ``AIAC_POLICY_FILE`` (demo/dam/policy.md).

The PRB's rules become a decision document for the MCP policy service (the PDP
behind DAM's MCP policy enforcement point): one entry per tool, allow or deny,
with the PRB's reasoning. A tool no rule mentions is denied.

Usage (from the aiac repo root, LLM_BASE_URL / LLM_MODEL / LLM_API_KEY set):
  .venv/bin/python demo/dam/onboard_dam_agent.py --agent-json agent.json \
      --tools demo/dam/github-mcp-tools.json --connection github-mcp --out decisions.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_agent(path: Path) -> dict:
    """An Agent CR as JSON (``kubectl get agents.agent-platform.ai <id> -o json``)."""
    return load_agent_cr(json.loads(path.read_text()))


_NEGATION = re.compile(r"\b(never|not|no|without|only|must not|cannot)\b", re.IGNORECASE)


def _clause(sentence: str) -> str:
    """A description sentence as a clause about the agent:
    "It reports ..." -> "it reports ...", "Reads and summarizes ..." -> "it reads and
    summarizes ...", and a label such as "Issue triage assistant." -> "it is an issue triage
    assistant"."""
    text = sentence.strip().rstrip(".")
    first, _, rest = text.partition(" ")
    word = first.lower()
    if word == "it":
        return "it " + rest
    if word.endswith("s") and not word.endswith("ss"):
        # a verb in the third person: "Reads", "Summarizes", "Writes"
        return "it " + word + (" " + rest if rest else "")
    label = text[0].lower() + text[1:]
    if word in {"a", "an", "the"}:
        return "it is " + label
    return "it is " + ("an " if label[0] in "aeiou" else "a ") + label


def statements(description: str) -> tuple[str, str]:
    """What the agent says it does, and what it says it does not, from its description.

    A sentence with a verb-less label ("Issue triage assistant.") says neither. A sentence that
    carries a negation ("never", "not", ...) is the agent's own limit; the others are its purpose.
    """
    sentences = [x for x in re.split(r"(?<=[.!?])\s+", description.strip()) if x.strip(" .!?")]
    limits = [_clause(x) for x in sentences if _NEGATION.search(x)]
    purpose = [_clause(x) for x in sentences if not _NEGATION.search(x)]
    return " and ".join(purpose), " and ".join(limits)


def reason_for(connection: str, tool: str, agent_name: str, effect: str, basis: str, description: str) -> str:
    """The reason the agent is told: the policy's ground and the agent's own words, never the
    mechanism that derived the decision."""
    purpose, limits = statements(description)
    subject = f"{connection}.{tool} for agent {agent_name}"
    if effect == "allow":
        return f"{subject} is allowed: agent states that {purpose or description}."
    if basis == "rule":
        said = f"agent specifically states that {limits}" if limits else f"agent states that {purpose or description}"
        return f"{subject} is denied: the policy prohibits it, {said}."
    return f"{subject} is denied: no rule grants it, agent states only that {purpose or description}."


def load_agent_cr(cr: dict) -> dict:
    """The facts aiac reasons from, out of an Agent CR."""
    spec = cr.get("spec", {})
    return {
        "id": cr["metadata"]["name"],
        "name": spec.get("name") or cr["metadata"]["name"],
        "description": (spec.get("description") or "").strip(),
    }


def decide(agent: dict, tools: dict, connection: str, host: str) -> dict:
    """Run aiac's Policy Rules Builder for one agent and return its decision document.

    ``AIAC_POLICY_FILE`` must name the organisation policy. A tool no rule mentions is denied.
    """
    from aiac.agent.policy_rules_builder.graph import build_role_rules
    from aiac.idp.configuration.models import Role, RoleKind, Scope
    from aiac.policy.model.models import RuleEffect

    role = Role(
        id=agent["id"],
        name=agent["name"],
        description=agent["description"],
        composite=False,
        kind=RoleKind.AGENT,
        actorIds=[agent["id"]],
    )
    scopes = [
        Scope(id=f"{connection}.{name}", name=f"{connection}.{name}", description=meta["description"])
        for name, meta in sorted(tools.items())
    ]
    rules = build_role_rules(role, scopes)

    effect: dict[str, str] = {}
    for rule in rules:
        tool = rule.scope.name.split(".", 1)[1]
        # deny-overrides, as in aiac's own policy model
        if rule.effect == RuleEffect.DENY or effect.get(tool) != "deny":
            effect[tool] = "deny" if rule.effect == RuleEffect.DENY else "allow"

    def entry(name: str) -> dict:
        eff = effect.get(name, "deny")
        basis = "rule" if name in effect else "no rule grants it"
        return {
            "effect": eff,
            "basis": basis,
            "reason": reason_for(connection, name, agent["name"], eff, basis, agent["description"]),
            "readOnlyHint": tools[name].get("readOnlyHint"),
        }

    return {
        "agent": agent,
        "connection": connection,
        "host": host,
        "policy_file": os.environ.get("AIAC_POLICY_FILE", ""),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "default": "deny",
        "tools": {name: entry(name) for name in sorted(tools)},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent-json", type=Path, required=True)
    ap.add_argument("--tools", type=Path, default=HERE / "github-mcp-tools.json")
    ap.add_argument("--connection", default="github-mcp", help="the MCP connection's name in DAM")
    ap.add_argument("--host", default="api.githubcopilot.com", help="the MCP server's host")
    ap.add_argument("--policy", type=Path, default=HERE / "policy.md")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    os.environ.setdefault("AIAC_POLICY_FILE", str(args.policy))
    agent = load_agent(args.agent_json)
    if not agent["description"]:
        print(f"agent {agent['name']} has no description: aiac has nothing to reason from", file=sys.stderr)
        return 2
    tools = json.loads(args.tools.read_text())
    decisions = decide(agent, tools, args.connection, args.host)
    args.out.write_text(json.dumps(decisions, indent=1) + "\n")
    allowed = sorted(n for n, d in decisions["tools"].items() if d["effect"] == "allow")
    print(f"{agent['name']}: {len(allowed)} allowed, {len(tools) - len(allowed)} denied")
    print("allowed:", ", ".join(allowed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
