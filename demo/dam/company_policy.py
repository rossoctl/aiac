"""The company security policy, for Sentry on DAM: one plain-language text, written once by an
operator in DAM, split into the rules Sentry can enforce on an agent's MCP tool calls.

- **Role rules** (aiac): who may make which operations, or use which agent. Each names the
  operations (``github-mcp.issue_write.close``, ``github-mcp.add_issue_comment``) or the agents it
  covers, and the Keycloak realm roles a person must hold. Their holders come from Keycloak, so a
  change of who holds a role needs no new split.
- **Data rules** (dg): which data may go where. Each maps onto rules of dg's own catalog
  (``DG-001`` ...), so dg's verdict decides them as it decides its shipped rules.
- **Unmatched**: sentences neither kind expresses, kept for review, never silently dropped.

One LLM pass per policy version (``split``); ``render`` then joins in the holders, with no LLM.
The split is kept beside the decisions, so a reviewer sees why a sentence went where.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from pydantic import BaseModel, Field


class RoleRule(BaseModel):
    text: str = Field(description="The policy sentence this rule comes from, verbatim.")
    operations: list[str] = Field(
        default_factory=list,
        description="The operations it covers, by their exact catalogue names; empty: every operation.",
    )
    agents: list[str] = Field(
        default_factory=list,
        description="The agents it covers, by their exact names; empty: every agent.",
    )
    roles: list[str] = Field(description="The realm roles, any one of which a person must hold.")


class DataRule(BaseModel):
    text: str = Field(description="The policy sentence this rule comes from, verbatim.")
    dg_rules: list[str] = Field(description="The ids of the data governance catalogue rules that express it.")


class Split(BaseModel):
    role_rules: list[RoleRule] = Field(default_factory=list)
    data_rules: list[DataRule] = Field(default_factory=list)
    unmatched: list[str] = Field(
        default_factory=list, description="Sentences no role rule or data rule can express, verbatim."
    )


INSTRUCTIONS = """You split a company security policy into rules a policy decision point enforces on an AI agent's tool calls.

A role rule says who may make some operations: for a call that is one of its operations (every operation, when it lists none) through one of its agents (every agent, when it lists none), the person who asked must hold one of its roles.
- "Developers and testers may read issues, comment on them and label them" is one role rule: the operations that read issues, comment on issues and label issues; no agents; roles developer and tester.
- "Only testers close an issue" is one role rule: the close operation; roles tester.
- "The QA sign-off agent is used by testers only" is one role rule: no operations; the agent whose name or description matches; roles tester.
Use only the operation names, agent names and role names given below, exactly as written. A sentence that names a role not given is unmatched.

A data rule says which data may go where. Map it onto the data governance catalogue rules below that express it, by id. A data sentence no catalogue rule expresses is unmatched.

Copy each sentence verbatim into the rule's text. Every sentence of the policy ends up in exactly one rule or in unmatched."""


def split(text: str, operations: dict[str, str], agents: dict[str, str], roles: list[str], dg_catalog: list[dict]) -> Split:
    """One LLM pass over the policy text, with aiac's own LLM settings (``LLM_*``)."""
    if not text.strip():
        return Split()
    from langchain_core.messages import HumanMessage, SystemMessage

    from aiac.agent.llm import build_llm, call_with_retry, load_llm_settings

    settings = load_llm_settings()
    runnable = build_llm(settings).with_structured_output(Split)
    facts = {
        "operations": operations,
        "agents": agents,
        "roles": roles,
        "data_governance_catalogue": dg_catalog,
    }
    messages = [
        SystemMessage(content=INSTRUCTIONS),
        HumanMessage(content=f"Facts:\n{json.dumps(facts, indent=1)}\n\nPolicy:\n{text}"),
    ]
    result = call_with_retry(runnable, messages, settings=settings)
    return result if isinstance(result, Split) else Split.model_validate(result)


def checked(found: Split, operations: dict[str, str], agents: dict[str, str], roles: list[str], dg_ids: set[str]) -> Split:
    """The split with every name checked against the facts: a rule naming an operation, agent,
    role or catalogue rule that does not exist is moved to unmatched, never enforced in part."""
    out = Split(unmatched=list(found.unmatched))
    for rule in found.role_rules:
        if (set(rule.operations) - set(operations)) or (set(rule.agents) - set(agents)) or not rule.roles or (set(rule.roles) - set(roles)):
            out.unmatched.append(rule.text)
        else:
            out.role_rules.append(rule)
    for rule in found.data_rules:
        if not rule.dg_rules or set(rule.dg_rules) - dg_ids:
            out.unmatched.append(rule.text)
        else:
            out.data_rules.append(rule)
    return out


def render(found: Split, version: int, holders: dict[str, list[str]], agent_ids: dict[str, str]) -> dict:
    """The company rules as OPA data (``data.dam.company``): each role rule with the usernames that
    hold its roles now, and the agents it covers by id as well as name."""
    return {
        "version": version,
        "role_rules": [
            {
                "id": f"R{i + 1}",
                "text": r.text,
                "operations": sorted(r.operations),
                "agents": sorted(agent_ids[a] for a in r.agents),
                "roles": sorted(r.roles),
                "holders": sorted({u for role in r.roles for u in holders.get(role, [])}),
            }
            for i, r in enumerate(found.role_rules)
        ],
        "data_rules": [{"text": r.text, "dg_rules": sorted(r.dg_rules)} for r in found.data_rules],
        "dg_rules": sorted({d for r in found.data_rules for d in r.dg_rules}),
        "unmatched": found.unmatched,
    }


class Keycloak:
    """The realm's roles and who holds them, read with a confidential client's service account
    (``KEYCLOAK_URL``, ``KEYCLOAK_REALM``, ``KEYCLOAK_CLIENT_ID``, ``KEYCLOAK_CLIENT_SECRET``)."""

    def __init__(self) -> None:
        self.url = os.environ["KEYCLOAK_URL"].rstrip("/")
        self.realm = os.environ.get("KEYCLOAK_REALM", "platform")
        self.client_id = os.environ["KEYCLOAK_CLIENT_ID"]
        self.secret = os.environ["KEYCLOAK_CLIENT_SECRET"]

    def _token(self) -> str:
        body = urllib.parse.urlencode(
            {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.secret}
        ).encode()
        url = f"{self.url}/realms/{self.realm}/protocol/openid-connect/token"
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=10) as response:
            return json.load(response)["access_token"]

    def _get(self, token: str, path: str) -> Any:
        request = urllib.request.Request(
            f"{self.url}/admin/realms/{self.realm}{path}", headers={"authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def roles(self) -> list[str]:
        """The realm's roles a person can hold: Keycloak's own built-ins left out."""
        token = self._token()
        built_in = {"offline_access", "uma_authorization", f"default-roles-{self.realm}"}
        return sorted(r["name"] for r in self._get(token, "/roles") if r["name"] not in built_in)

    def holders(self, roles: list[str]) -> dict[str, list[str]]:
        """The usernames of the people who hold each role, service accounts left out."""
        token = self._token()
        out: dict[str, list[str]] = {}
        for role in roles:
            members = self._get(token, f"/roles/{urllib.parse.quote(role)}/users?max=500")
            out[role] = sorted(
                m["username"] for m in members if not m.get("username", "").startswith("service-account-")
            )
        return out


def dg_catalog(path: str) -> list[dict]:
    """What the LLM needs of dg's rule catalogue: each rule's id, name and what it guards."""
    source = json.loads(open(path).read())
    return [
        {
            "id": r["rule_id"],
            "name": r.get("rule_name", ""),
            "explanation": r.get("rule_decision", {}).get("explanation", ""),
            "event_type": r.get("event_type", ""),
        }
        for r in source.get("rules", [])
    ]
