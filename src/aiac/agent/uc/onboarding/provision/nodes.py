"""Nodes for the Service Provision sub-agent (UC1).

All nodes are **non-LLM**. Graph:

    START -> classify_service -> [analyze_agent | analyze_tool] -> provision_service -> END

IdP access is via the **idp-library** `Configuration` (the `_config` seam), never the IdP
service directly. Kubernetes access is via the `kube` seam module (`list_pods`,
`read_service`, `list_agentcards`), which retries internally. Any upstream failure surfaces
as an `HTTPException(502, ...)` whose message names the workload and the specific
missing/invalid label — actionable, never silent.
"""

import os
import time
import logging

from dataclasses import dataclass

from fastapi import HTTPException

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ServiceType
from aiac.shared.upstream import run_upstream

from .kube import list_agentcards, list_pods, read_service
from .state import OnboardingProvisionState
from .types import RoleDefinition, ScopeDefinition, ServiceProvision

logger = logging.getLogger(__name__)

_TYPE_LABEL = "rossoctl.io/type"
_MCP_LABEL = "protocol.rossoctl.io/mcp"

def _loggable(value: object) -> str:
    """Neutralize a value for single-line logging (drop CR/LF); see
    ``uc.onboarding.orchestrator._loggable``. Applied to any name sourced from Kubernetes
    labels/CRs or an MCP tool manifest — external input, not this process's own naming."""
    return str(value).replace("\r", "").replace("\n", "")


@dataclass(frozen=True)
class _WaitConfig:
    """A bounded deploy->onboard race-tolerance poll. ``attempts_env``/``backoff_env`` name the
    environment knobs (read at poll time, falling back to the defaults on an unset / non-numeric /
    below-minimum value). Bundled so the two onboarding races below share one poll mechanic
    (``_poll_until_ready``) instead of each repeating the read-env + range + backoff loop."""

    attempts_env: str
    backoff_env: str
    default_attempts: int
    default_backoff: float


# Deploy->onboard race tolerance for the operator-applied ``rossoctl.io/type`` label. The onboarding
# event is triggered by a DIFFERENT operator action (Keycloak client registration -> admin event), so
# ``classify_service`` can run BEFORE the operator has patched the label onto the pod. A briefly-absent
# label is therefore a transient not-ready state, re-polled before we give up with a 502. Defaults
# ≈ 30s of slack (well under the NATS ACK_WAIT and the system-test convergence poll); tests set fast.
_LABEL_WAIT = _WaitConfig("ONBOARD_LABEL_WAIT_ATTEMPTS", "ONBOARD_LABEL_WAIT_BACKOFF", 15, 2.0)

# Deploy->onboard race tolerance for the AgentCard skill sync — a SECOND, later race than the label one
# above. The operator syncs the fetched A2A card onto ``status.card.skills`` only AFTER the agent pod is
# Ready, which lags the Keycloak-client registration that triggers onboarding. So ``analyze_agent`` can
# run while ``status.card.skills`` is still empty. An absent card / empty skill list is therefore a
# transient not-ready state, re-polled before we fall back to a default access scope. Same ≈30s slack.
_CARD_WAIT = _WaitConfig("ONBOARD_CARD_WAIT_ATTEMPTS", "ONBOARD_CARD_WAIT_BACKOFF", 15, 2.0)


def _env_num(name: str, default, cast, minimum):
    """Read ``name`` from the environment, tolerant of an unset / non-numeric / below-``minimum``
    value — a bad value must not crash onboarding, it falls back to the default."""
    try:
        value = cast(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _poll_until_ready(probe, cfg: _WaitConfig):
    """Re-poll ``probe`` up to ``cfg`` attempts, backing off between looks (skipped after the last).
    ``probe`` returns a non-``None`` 'ready' result to stop, or ``None`` to retry; it may raise to fail
    the whole wait immediately (a real error, never a race). Returns the ready result, or ``None`` once
    the attempt budget is exhausted — the caller then decides what an exhausted wait means."""
    attempts = _env_num(cfg.attempts_env, cfg.default_attempts, int, minimum=1)
    backoff = _env_num(cfg.backoff_env, cfg.default_backoff, float, minimum=0.0)
    for attempt in range(attempts):
        result = probe()
        if result is not None:
            return result
        if attempt + 1 < attempts:
            time.sleep(backoff)
    return None


# --------------------------------------------------------------------------- #
# Seams (patched in unit tests)                                                #
# --------------------------------------------------------------------------- #
def _config() -> Configuration:
    return Configuration.for_default_realm()


def _discovery_token(service_id: str) -> str:
    """Mint a tool-audienced discovery bearer token via the idp-library `Configuration` seam
    (never Keycloak directly). The config service holds the admin creds and does the minting."""
    return _config().mint_discovery_token(service_id)


# (connect, read) timeouts for the MCP discovery probe — an unreachable/hanging tool must not
# block the onboarding request indefinitely (there was previously no timeout).
_MCP_TIMEOUT = (5, 30)


def _mcp_tools_list(endpoint: str, token: str | None = None) -> list[dict]:
    """POST a JSON-RPC `tools/list` to an MCP endpoint and return the tool manifest list.
    Each tool is a dict with `name` and (optional) `description`. When `token` is provided it is
    sent as an `Authorization: Bearer` header (the tool's MCP endpoint is fronted by an AuthBridge
    sidecar that validates inbound JWTs). Bounded transport retries are applied here so callers
    just map the final failure to a 502."""
    import requests

    def _do():
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.post(
            endpoint,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers=headers,
            timeout=_MCP_TIMEOUT,
        )
        resp.raise_for_status()
        return (resp.json().get("result") or {}).get("tools", [])

    return run_upstream(_do)


def _select_pod(pods, workload_name: str):
    """The pod owned by ``workload_name``: a Deployment's ReplicaSet (name prefix
    ``{workload}-``), or a StatefulSet / Sandbox whose name equals ``workload``."""
    for pod in pods:
        for owner in getattr(pod.metadata, "owner_references", None) or []:
            if owner.kind == "ReplicaSet" and owner.name.startswith(f"{workload_name}-"):
                return pod
            if owner.kind in ("StatefulSet", "Sandbox") and owner.name == workload_name:
                return pod
    return None


# --------------------------------------------------------------------------- #
# Nodes                                                                        #
# --------------------------------------------------------------------------- #
def classify_service(state: OnboardingProvisionState) -> dict:
    """Resolve identity and determine service type from the operator's `rossoctl.io/type`
    pod label (authoritative — not the entity_id format)."""
    service_id = state.trigger.entity_id

    try:
        service = _config().get_service(service_id)
    except Exception as e:
        raise HTTPException(502, f"IdP config unavailable resolving service {service_id!r}: {e}")

    name = service.name or ""
    if "/" not in name:
        raise HTTPException(
            502,
            f"client.name {name!r} for service {service_id!r} has no '/': namespace/workload_name unrecoverable",
        )
    namespace, workload_name = name.split("/", 1)

    service_type = _await_service_type(namespace, workload_name)

    logger.info(
        "classify_service: service_id=%s -> namespace=%s workload=%s type=%s",
        _loggable(service_id), _loggable(namespace), _loggable(workload_name), service_type.value,
    )
    return {
        "service_id": service_id,
        "namespace": namespace,
        "workload_name": workload_name,
        "service_type": service_type,
    }


def _await_service_type(namespace: str, workload_name: str) -> ServiceType:
    """Resolve the service type from the operator's ``rossoctl.io/type`` pod label, tolerating the
    deploy->onboard RACE (the label may not be patched yet — see the module knobs above).

    A briefly-absent label — or a not-yet-created pod — is a transient not-ready state, re-polled
    a bounded number of times. A label present with an INVALID value (not ``agent``/``tool``) is a
    real misconfiguration that no wait can fix, so it fails immediately. Retries exhausted -> 502
    naming the workload and the label (unchanged contract for a genuinely never-labelled workload)."""
    no_pod_detail = f"no pod owned by workload {workload_name!r} in namespace {namespace!r}"
    detail = no_pod_detail

    def _probe():
        nonlocal detail
        # Re-derive per attempt so the exhausted-wait 502 reflects the LAST-seen state: a pod that
        # disappears mid-poll must report "no pod", not a stale "label missing" from an earlier attempt.
        detail = no_pod_detail
        try:
            pods = list_pods(namespace)
        except Exception as e:
            raise HTTPException(502, f"Kubernetes pod LIST failed in namespace {namespace!r}: {e}")

        pod = _select_pod(pods, workload_name)
        if pod is not None:
            label = (getattr(pod.metadata, "labels", None) or {}).get(_TYPE_LABEL)
            if label:
                try:
                    return ServiceType(label.capitalize())
                except ValueError:
                    # Present but not agent/tool: a real misconfiguration, never a race — fail now.
                    raise HTTPException(
                        502,
                        f"workload {workload_name!r}: {_TYPE_LABEL} label invalid "
                        f"(got {label!r}, expected 'agent' or 'tool')",
                    )
            detail = (
                f"workload {workload_name!r}: {_TYPE_LABEL} label missing or invalid "
                f"(got {label!r}, expected 'agent' or 'tool')"
            )
        return None

    service_type = _poll_until_ready(_probe, _LABEL_WAIT)
    if service_type is None:
        raise HTTPException(502, detail)
    return service_type


def _await_agent_skills(namespace: str, workload: str):
    """Resolve an agent's AgentCard + its synced skills, tolerating the deploy->onboard RACE on the
    card sync (see the module knobs above).

    The operator syncs the fetched A2A card onto ``status.card.skills`` only AFTER the agent pod is
    Ready — a DIFFERENT, later operator action than the Keycloak-client registration that triggers
    onboarding. So this node can run before the skills are synced. An absent card, or a card whose
    ``status.card.skills`` is still empty, is therefore a transient not-ready state, re-polled a
    bounded number of times. Returns ``(card, skills)`` as soon as skills are present, or the
    last-seen ``(card, [])`` once the attempt budget is exhausted — the caller then applies the
    legacy card-less / skill-less fallback (a genuinely card-less workload never converges here)."""

    # Link the card to the workload by its ``spec.targetRef`` (the Deployment it describes), since the
    # operator names the CR after the Deployment (e.g. ``<workload>-deployment-card``), not the
    # workload. Fall back to ``metadata.name == workload`` for hand-authored/legacy cards.
    def _targets_workload(c: dict) -> bool:
        target = ((c.get("spec") or {}).get("targetRef") or {}).get("name")
        return target == workload or (c.get("metadata") or {}).get("name") == workload

    last_card = None

    def _probe():
        nonlocal last_card
        try:
            resp = list_agentcards(namespace)
        except Exception as e:
            raise HTTPException(502, f"Kubernetes AgentCard LIST failed in namespace {namespace!r}: {e}")

        last_card = next((c for c in resp.get("items", []) if _targets_workload(c)), None)
        skills = (((last_card or {}).get("status") or {}).get("card") or {}).get("skills", [])
        return (last_card, skills) if skills else None

    result = _poll_until_ready(_probe, _CARD_WAIT)
    return result if result is not None else (last_card, [])


def analyze_agent(state: OnboardingProvisionState) -> dict:
    """Derive an agent's roles + scopes from its AgentCard CR (non-LLM).

    The operator fetches the agent's A2A card and syncs it onto the CR's ``status.card``; each skill
    there carries a machine ``id`` (a stable identifier, e.g. ``source_operations``) plus a display
    ``name`` (which may contain spaces). Scope names are built from the skill ``id`` so they are
    usable Keycloak scope names, and each skill also gets a **per-skill operator role** mirroring the
    scope (same name + description): the role's description is what the PRB capability-match reads to
    confine and grant the agent's outbound access on a domain basis.

    Because the operator syncs the card only after the agent pod is Ready — later than the event that
    triggers onboarding — the skills are awaited with a bounded retry (``_await_agent_skills``). Falls
    back to a default access scope + a default operator role only once that wait is exhausted: for a
    genuinely card-less legacy deployment, or a CR whose skills never sync."""
    namespace, workload = state.namespace, state.workload_name

    card, skills = _await_agent_skills(namespace, workload)
    if not skills:
        provision = ServiceProvision(
            roles=[RoleDefinition(name=f"{workload}.access", description="Default access scope")],
            scopes=[ScopeDefinition(name=f"{workload}.access", description="Default access scope")],
            reasoning=(
                "partial: no AgentCard found, default scope assigned"
                if card is None
                else "partial: AgentCard has no synced skills, default scope assigned"
            ),
        )
        logger.info("analyze_agent: workload=%s no skills discovered (%s) -> default scope %s.access",
                    _loggable(workload), provision.reasoning, _loggable(workload))
        return {"service_provision": provision}

    # One operator role per skill, mirroring the scope (same name + description). The role name ==
    # scope name is fine — a realm role and a client scope are distinct Keycloak objects. The role's
    # description drives the PRB capability-match (see generic_policy.md).
    def _skill_key(s: dict) -> str:
        key = s.get("id") or s.get("name")
        if not key:
            raise HTTPException(
                502,
                f"AgentCard for workload {workload!r} in namespace {namespace!r} has a skill "
                f"with neither 'id' nor 'name'; cannot derive a scope/role name (skill: {s!r})",
            )
        return key

    scopes = [ScopeDefinition(name=f"{workload}.{_skill_key(s)}", description=s.get("description", "")) for s in skills]
    roles = [RoleDefinition(name=f"{workload}.{_skill_key(s)}", description=s.get("description", "")) for s in skills]
    provision = ServiceProvision(
        roles=roles,
        scopes=scopes,
        reasoning=f"derived from AgentCard: {len(skills)} skills",
    )
    logger.info(
        "analyze_agent: workload=%s discovered %d skill(s) from its AgentCard -> scopes/roles %s",
        _loggable(workload), len(skills), _loggable([s.name for s in scopes]),
    )
    return {"service_provision": provision}


def analyze_tool(state: OnboardingProvisionState) -> dict:
    """Discover a tool's scopes from its MCP `tools/list` manifest (non-LLM). Endpoint is
    resolved via the hybrid Keycloak->K8s strategy (issue 6.2): identity from `classify_service`,
    reachable endpoint from the K8s Service."""
    namespace, workload = state.namespace, state.workload_name

    try:
        svc = read_service(workload, namespace)
    except Exception as e:
        raise HTTPException(502, f"Kubernetes Service GET failed for {workload!r} in namespace {namespace!r}: {e}")

    labels = getattr(svc.metadata, "labels", None) or {}
    if _MCP_LABEL not in labels:
        raise HTTPException(
            502,
            f"Service {workload!r} in namespace {namespace!r} is missing the {_MCP_LABEL!r} "
            "label (deploy-time prerequisite for MCP tool discovery)",
        )

    ports = getattr(svc.spec, "ports", None) or []
    if not ports:
        raise HTTPException(
            502,
            f"Service {workload!r} in namespace {namespace!r} exposes no ports; cannot resolve an MCP endpoint",
        )
    port = ports[0].port
    endpoint = f"http://{workload}.{namespace}.svc.cluster.local:{port}/mcp"

    # The MCP endpoint is fronted by the tool's AuthBridge sidecar, which validates inbound JWTs
    # against the tool's own clientId as the audience. Mint a tool-audienced discovery token first;
    # a failure here surfaces as an actionable 502 rather than a downstream 401.
    try:
        token = _discovery_token(state.service_id)
    except Exception as e:
        raise HTTPException(502, f"discovery token minting failed for service {state.service_id!r}: {e}")

    try:
        tools = _mcp_tools_list(endpoint, token=token)
    except Exception as e:
        raise HTTPException(502, f"MCP tools/list failed at {endpoint}: {e}")

    def _tool_name(t: dict) -> str:
        name = t.get("name")
        if not name:
            raise HTTPException(
                502,
                f"MCP tools/list at {endpoint} returned a tool with no 'name'; "
                f"cannot derive a scope name (tool: {t!r})",
            )
        return name

    scopes = [ScopeDefinition(name=f"{workload}.{_tool_name(t)}", description=t.get("description", "")) for t in tools]
    provision = ServiceProvision(
        roles=[],
        scopes=scopes,
        reasoning=f"derived from MCP manifest: {len(tools)} tools",
    )
    logger.info(
        "analyze_tool: workload=%s queried MCP tools/list at %s -> discovered %d tool(s), scopes %s",
        _loggable(workload), endpoint, len(tools), _loggable([s.name for s in scopes]),
    )
    return {"service_provision": provision}


def provision_service(state: OnboardingProvisionState) -> dict:
    """Write the derived roles + scopes into the IdP (idempotent create-or-get + map) and
    persist the discovered service type onto the Keycloak client, via the idp-library.

    Returns the `ServiceProvision` + `service_type` to the Orchestrator, plus the
    **created-manifest** (`created_roles` / `created_scopes`): exactly the entities this run
    *created*, not the ones it *reused by name*. The idempotent `create_service_role` /
    `create_service_scope` return the resolved entity whether they created or reused it, so a
    name is classified as created only when it was **absent** from the realm before this run
    (snapshot taken before the create loop). The Orchestrator's compensating rollback deletes
    only this manifest, so a role/scope another service already owns is never torn down."""
    config = _config()
    provision = state.service_provision
    service_id = state.service_id

    created_roles = []
    created_scopes = []
    try:
        existing_role_names = {r.name for r in config.get_roles()} if provision.roles else set()
        for role in provision.roles:
            resolved = config.create_service_role(service_id, role)
            if role.name not in existing_role_names:
                created_roles.append(resolved)
        existing_scope_names = {s.name for s in config.get_scopes()} if provision.scopes else set()
        for scope in provision.scopes:
            resolved = config.create_service_scope(service_id, scope)
            if scope.name not in existing_scope_names:
                created_scopes.append(resolved)
        service = config.get_service(service_id)
        config.set_service_type(service, state.service_type)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"IdP Configuration Service unavailable provisioning {service_id!r}: {e}")

    return {
        "service_provision": provision,
        "service_type": state.service_type,
        "created_roles": created_roles,
        "created_scopes": created_scopes,
    }
