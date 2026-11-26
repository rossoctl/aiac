"""Automatic aiac onboarding for DAM agents (Sentry's aiac component).

Watches DAM's Agent resources and keeps the MCP policy decision point's data
current: every agent with ``spec.mcpPolicyEnforcement`` gets a decision per
MCP tool from aiac's Policy Rules Builder, derived from the agent's own
description and the organisation policy (``AIAC_POLICY_FILE``). An agent is
onboarded again when its name, its description, the tool catalogue, the
policy or the code that renders its reasons changes, and dropped when it is deleted.

It runs beside OPA in the policy service's pod and writes OPA's
``data.dam.agents`` over OPA's REST API on localhost. While an agent is being
decided, its entry is ``pending`` and every tool call is denied; a failed
onboarding is ``failed``, denied too, and retried. The decided set is also
kept in a ConfigMap, so a restart does not lose it.

It also keeps OPA's ``data.dam.company`` current: the company security policy an
operator writes in DAM, read from DAM's in-cluster MCP policy API, split once per
version into role rules and data rules (``company_policy.py``), with the role
rules' holders read from Keycloak on every loop. A tool such as ``issue_write``
is decided per operation (``issue_write.close``, ``issue_write.assign``, ...).

Standard library only (beyond aiac itself): the Kubernetes API is read with the
pod's ServiceAccount token.

Environment:
  AGENT_NAMESPACE (platform-agents), DATA_NAMESPACE (sentry-dam),
  DATA_CONFIGMAP (mcp-policy-data), OPA_URL (http://127.0.0.1:8181),
  POLL_SECONDS (5), RETRY_SECONDS (60), TOOLS_FILE, CONNECTION (github-mcp),
  MCP_HOST (api.githubcopilot.com), AIAC_POLICY_FILE, LLM_BASE_URL, LLM_MODEL,
  LLM_API_KEY, DAM_API_URL, MCP_POLICY_SERVICE_TOKEN, DG_RULES_FILE,
  KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import company_policy  # noqa: E402
from onboard_dam_agent import decide, load_agent_cr, operations, to_rego  # noqa: E402

LOG = logging.getLogger("aiac-dam-onboarder")

AGENT_NAMESPACE = os.environ.get("AGENT_NAMESPACE", "platform-agents")
DATA_NAMESPACE = os.environ.get("DATA_NAMESPACE", "sentry-dam")
DATA_CONFIGMAP = os.environ.get("DATA_CONFIGMAP", "mcp-policy-data")
OPA_URL = os.environ.get("OPA_URL", "http://127.0.0.1:8181").rstrip("/")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))
RETRY_SECONDS = float(os.environ.get("RETRY_SECONDS", "60"))
TOOLS_FILE = Path(os.environ.get("TOOLS_FILE", Path(__file__).resolve().parent / "github-mcp-tools.json"))
CONNECTION = os.environ.get("CONNECTION", "github-mcp")
MCP_HOST = os.environ.get("MCP_HOST", "api.githubcopilot.com")
POLICY_FILE = Path(os.environ.get("AIAC_POLICY_FILE", Path(__file__).resolve().parent / "policy.md"))
# The company security policy an operator writes in DAM, read from DAM's in-cluster MCP policy API.
DAM_API_URL = os.environ.get("DAM_API_URL", "").rstrip("/")
DAM_API_TOKEN = os.environ.get("MCP_POLICY_SERVICE_TOKEN", "")
DG_RULES_FILE = os.environ.get("DG_RULES_FILE", "/dg/rules_source.json")

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
API = "https://kubernetes.default.svc"


def log(event: str, **fields: Any) -> None:
    LOG.info(json.dumps({"event": event, **fields}))


class Kube:
    """The few Kubernetes API calls the onboarder makes, with the pod's ServiceAccount."""

    def __init__(self) -> None:
        self.ctx = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt"))

    def _call(self, method: str, path: str, body: Any = None, content_type: str = "application/json") -> Any:
        token = (SA_DIR / "token").read_text().strip()
        request = urllib.request.Request(
            API + path,
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"authorization": f"Bearer {token}", "content-type": content_type, "accept": "application/json"},
        )
        with urllib.request.urlopen(request, context=self.ctx, timeout=15) as response:
            return json.load(response)

    def agents(self) -> list[dict]:
        return self._call("GET", f"/apis/agent-platform.ai/v1/namespaces/{AGENT_NAMESPACE}/agents")["items"]

    def load_data(self) -> dict:
        try:
            cm = self._call("GET", f"/api/v1/namespaces/{DATA_NAMESPACE}/configmaps/{DATA_CONFIGMAP}")
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return {}
            raise
        raw = (cm.get("data") or {}).get("data.json") or "{}"
        return json.loads(raw).get("dam", {}).get("agents", {})

    def save_data(self, agents: dict) -> None:
        decided = {k: v for k, v in agents.items() if v.get("status") == "decided"}
        doc = json.dumps({"dam": {"agents": decided}}, indent=1, sort_keys=True)
        self._patch_data({"data.json": doc})

    def load_company(self) -> dict:
        """The last company policy split (its version, text hash and split), so a restart does
        not split the same version again."""
        try:
            cm = self._call("GET", f"/api/v1/namespaces/{DATA_NAMESPACE}/configmaps/{DATA_CONFIGMAP}")
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return {}
            raise
        return json.loads((cm.get("data") or {}).get("company.json") or "{}")

    def save_company(self, company: dict) -> None:
        self._patch_data({"company.json": json.dumps(company, indent=1, sort_keys=True)})

    def _patch_data(self, data: dict) -> None:
        self._call(
            "PATCH",
            f"/api/v1/namespaces/{DATA_NAMESPACE}/configmaps/{DATA_CONFIGMAP}",
            {"data": data},
            content_type="application/merge-patch+json",
        )


def opa_put(path: str, value: dict) -> None:
    request = urllib.request.Request(
        OPA_URL + "/v1/data/dam/" + path,
        method="PUT",
        data=json.dumps(value).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5):
        pass


def opa_put_agents(agents: dict) -> None:
    """Each agent's onboarding status for the policy; its tools live in its generated module."""
    status = {i: {k: v for k, v in e.items() if k not in ("rego", "tools")} for i, e in agents.items()}
    request = urllib.request.Request(
        OPA_URL + "/v1/data/dam/agents",
        method="PUT",
        data=json.dumps(status).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5):
        pass


def policy_id(agent_id: str) -> str:
    return f"aiac-{agent_id}"


def opa_policies() -> set[str]:
    with urllib.request.urlopen(OPA_URL + "/v1/policies", timeout=5) as response:
        return {p["id"] for p in json.load(response).get("result", [])}


def opa_put_policy(agent_id: str, rego: str) -> None:
    """Load the Rego module aiac generated for the agent into OPA."""
    request = urllib.request.Request(
        f"{OPA_URL}/v1/policies/{policy_id(agent_id)}",
        method="PUT",
        data=rego.encode(),
        headers={"content-type": "text/plain"},
    )
    with urllib.request.urlopen(request, timeout=5):
        pass


def opa_delete_policy(agent_id: str) -> None:
    request = urllib.request.Request(f"{OPA_URL}/v1/policies/{policy_id(agent_id)}", method="DELETE")
    try:
        with urllib.request.urlopen(request, timeout=5):
            pass
    except urllib.error.HTTPError as err:
        if err.code != 404:
            raise


# The code that renders each decision's reason: a change to it re-onboards every agent.
RENDER_CODE = (Path(__file__).resolve().parent / "onboard_dam_agent.py").read_text()


def fingerprint(agent: dict, catalogue: str, policy: str) -> str:
    material = json.dumps([agent["name"], agent["description"], catalogue, policy, CONNECTION, MCP_HOST, RENDER_CODE])
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def opa_entry(agent: dict, status: str, fp: str, decided: dict | None = None, error: str | None = None) -> dict:
    entry: dict[str, Any] = {
        "name": agent["name"],
        "connection": CONNECTION,
        "host": MCP_HOST,
        "status": status,
        "fingerprint": fp,
        "tools": {},
    }
    if decided:
        entry["generated_at"] = decided["generated_at"]
        entry["tools"] = {
            n: {"effect": t["effect"], "basis": t["basis"], "reason": t["reason"]} for n, t in decided["tools"].items()
        }
    if error:
        entry["error"] = error
        entry["failed_at"] = time.time()
    return entry


def dam_company_policy() -> dict:
    """The company security policy from DAM: {text, version, updatedAt, updatedByEmail}."""
    request = urllib.request.Request(
        DAM_API_URL + "/internal/mcp-policy/company-policy",
        headers={"authorization": f"Bearer {DAM_API_TOKEN}", "accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def company_step(kube: Kube, keycloak: company_policy.Keycloak, state: dict, tools: dict, enforcing: dict) -> dict:
    """Keep OPA's ``data.dam.company`` current. A new policy version is split once (one LLM
    pass); the holders of the rules' roles are read from Keycloak on every loop, with no LLM. While
    a version is being split, or when it could not be, every call a company rule could cover is
    denied (``status`` pending or failed): a rule is never assumed applied."""
    policy = dam_company_policy()
    names = {a["name"]: i for i, a in enforcing.items()}
    material = hashlib.sha256(json.dumps([policy["text"], sorted(names), RENDER_COMPANY]).encode()).hexdigest()[:16]
    if state.get("material") != material:
        opa_put("company", {"version": policy["version"], "status": "pending"})
        log("company-policy-splitting", version=policy["version"], chars=len(policy["text"]))
        ops = {f"{CONNECTION}.{n}": m["description"] for n, m in operations(tools).items()}
        agents = {a["name"]: a["description"] for a in enforcing.values()}
        roles = keycloak.roles()
        catalog = company_policy.dg_catalog(DG_RULES_FILE)
        try:
            found = company_policy.split(policy["text"], ops, agents, roles, catalog)
        except Exception as err:  # noqa: BLE001 - a failed split keeps every covered call denied
            opa_put("company", {"version": policy["version"], "status": "failed", "error": type(err).__name__})
            log("company-policy-failed", version=policy["version"], error=type(err).__name__, detail=str(err)[:300])
            return state
        found = company_policy.checked(found, ops, agents, roles, {r["id"] for r in catalog})
        state = {"material": material, "version": policy["version"], "split": found.model_dump()}
        kube.save_company(state)
        log("company-policy-split", version=policy["version"], role_rules=len(found.role_rules),
            data_rules=len(found.data_rules), unmatched=found.unmatched)
    found = company_policy.Split.model_validate(state["split"])
    roles = sorted({r for rule in found.role_rules for r in rule.roles})
    rendered = company_policy.render(found, state["version"], keycloak.holders(roles), names)
    opa_put("company", {**rendered, "status": "applied"})
    return state


# The code that splits and renders the company policy: a change to it splits the policy again.
RENDER_COMPANY = (Path(__file__).resolve().parent / "company_policy.py").read_text()


def main() -> None:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
    kube = Kube()
    agents: dict[str, dict] = kube.load_data()
    company: dict = kube.load_company()
    keycloak = company_policy.Keycloak()
    log("started", decided=sorted(agents), namespace=AGENT_NAMESPACE, company_version=company.get("version"))
    while True:
        try:
            catalogue = TOOLS_FILE.read_text()
            policy = POLICY_FILE.read_text()
            tools = json.loads(catalogue)
            live = {cr["metadata"]["name"]: cr for cr in kube.agents()}

            for gone in sorted(set(agents) - set(live)):
                agents.pop(gone)
                opa_delete_policy(gone)
                log("dropped", agent=gone)
                opa_put_agents(agents)
                kube.save_data(agents)

            enforcing = {i: load_agent_cr(cr) for i, cr in live.items() if cr.get("spec", {}).get("mcpPolicyEnforcement")}
            # Every enforcing agent's name, so the policy service can apply per-agent config by name.
            opa_put("names", {i: a["name"] for i, a in enforcing.items()})

            for agent_id, cr in sorted(live.items()):
                if agent_id not in enforcing:
                    continue
                agent = enforcing[agent_id]
                fp = fingerprint(agent, catalogue, policy)
                known = agents.get(agent_id)
                if known and known.get("fingerprint") == fp:
                    if known.get("status") != "failed" or time.time() - known.get("failed_at", 0) < RETRY_SECONDS:
                        continue
                if not agent["description"]:
                    agents[agent_id] = opa_entry(agent, "failed", fp, error="the agent has no description")
                    opa_put_agents(agents)
                    log("no-description", agent=agent_id, name=agent["name"])
                    continue

                agents[agent_id] = opa_entry(agent, "pending", fp)
                opa_put_agents(agents)
                log("onboarding", agent=agent_id, name=agent["name"], reason="new" if not known else "changed")
                started = time.time()
                try:
                    decided = decide(agent, tools, CONNECTION, MCP_HOST)
                except Exception as err:  # noqa: BLE001 - any PRB failure keeps the agent denied
                    agents[agent_id] = opa_entry(agent, "failed", fp, error=type(err).__name__)
                    opa_put_agents(agents)
                    log("onboarding-failed", agent=agent_id, error=type(err).__name__, detail=str(err)[:300])
                    continue
                rego = to_rego({**decided, "agent": agent})
                opa_put_policy(agent_id, rego)
                agents[agent_id] = {**opa_entry(agent, "decided", fp, decided=decided), "rego": rego}
                opa_put_agents(agents)
                kube.save_data(agents)
                allowed = sorted(n for n, t in decided["tools"].items() if t["effect"] == "allow")
                log("onboarded", agent=agent_id, name=agent["name"], seconds=round(time.time() - started, 1),
                    allowed=allowed, denied=len(decided["tools"]) - len(allowed))

            # Every loop: OPA keeps no data or generated policy of its own, so a restarted OPA is
            # filled again, and an agent decided before generated modules existed gets one.
            loaded = opa_policies()
            for agent_id, entry in agents.items():
                if entry.get("status") != "decided":
                    continue
                if not entry.get("rego") and entry.get("tools") and agent_id in enforcing:
                    entry["rego"] = to_rego({"agent": enforcing[agent_id], "connection": entry["connection"],
                                             "host": entry["host"], "generated_at": entry.get("generated_at", ""),
                                             "tools": entry["tools"]})
                    kube.save_data(agents)
                if entry.get("rego") and policy_id(agent_id) not in loaded:
                    opa_put_policy(agent_id, entry["rego"])
                    log("policy-loaded", agent=agent_id, policy=policy_id(agent_id))
            opa_put_agents(agents)
            try:
                company = company_step(kube, keycloak, company, tools, enforcing)
            except Exception as err:  # noqa: BLE001 - DAM or Keycloak unreachable: no rule is applied
                opa_put("company", {"version": company.get("version", -1), "status": "unavailable"})
                log("company-policy-unavailable", error=type(err).__name__, detail=str(err)[:300])
        except Exception as err:  # noqa: BLE001 - keep watching; the next loop retries
            log("loop-error", error=type(err).__name__, detail=str(err)[:300])
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
