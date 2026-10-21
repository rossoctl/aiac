"""Nodes for the Service Provision sub-agent (UC1).

All nodes are **non-LLM**. Graph:

    START -> classify_service -> [analyze_agent | analyze_tool] -> provision_service -> END

IdP access is via the **idp-library** `Configuration` (the `_config` seam), never the IdP
service directly. Kubernetes access is via the `kube` seam module (`list_pods`,
`read_deployment`, `read_service`, `list_agentcards`), which retries internally. Any upstream failure surfaces
as an `HTTPException(502, ...)` whose message names the workload and the specific
missing/invalid label — actionable, never silent.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import HTTPException

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ServiceType
from aiac.shared.env import env_num
from aiac.shared.upstream import run_upstream

from .kube import is_not_found, list_agentcards, list_pods, read_deployment, read_service
from .state import OnboardingProvisionState
from .types import RoleDefinition, ScopeDefinition, ServiceProvision

_TYPE_LABEL = "rossoctl.io/type"
_MCP_LABEL = "protocol.rossoctl.io/mcp"


@dataclass(frozen=True)
class WaitConfig:
    """A bounded onboarding race-tolerance poll. ``attempts_env``/``backoff_env`` name the
    environment knobs (read at poll time, falling back to the defaults on an unset / non-numeric /
    non-finite / below-minimum value). Bundled so the onboarding races (the two below, and the orchestrator's
    ``CLIENT_WAIT``) share one poll mechanic (``poll_until_ready``) instead of each repeating the
    read-env + range + backoff loop."""

    attempts_env: str
    backoff_env: str
    default_attempts: int
    default_backoff: float


# Deploy->onboard race tolerance for the operator-applied ``rossoctl.io/type`` label. The onboarding
# event is triggered by a DIFFERENT operator action (Keycloak client registration -> admin event), so
# ``classify_service`` can run BEFORE the operator has patched the label onto the pod. A briefly-absent
# label is therefore a transient not-ready state, re-polled before we give up with a 502. Budgeted at
# 30 attempts after a ~30s budget was observed losing this race by about a second: a tool's pod was
# created at 14:28:17Z and the wait gave up at 14:28:46Z, because the operator had not yet reconciled
# its AgentRuntime. The same budget covers the wait for the rollout of the workload's Deployment: the
# operator rolls it more than once after a deploy (the type label, then the client-credentials annotation),
# and the event comes before the last rollout. A wait that ends not ready raises ``WorkloadNotReadyError``,
# which the NATS consumer naks, so a later delivery waits again. Still well under the NATS ACK_WAIT; tests
# set fast.
_LABEL_WAIT = WaitConfig("ONBOARD_LABEL_WAIT_ATTEMPTS", "ONBOARD_LABEL_WAIT_BACKOFF", 30, 2.0)

# Deploy->onboard race tolerance for the AgentCard sync — a SECOND, later race than the label one above.
# The operator fetches the agent's A2A card only AFTER the workload is Available, and writes it onto
# ``status.card`` together with the card's ``Synced=True`` condition. That lags the Keycloak-client
# registration that triggers onboarding (after a failed fetch the operator tries again after 1 min, or
# earlier on a watch event). So ``analyze_agent`` can run before the card is synced, and it waits for
# ``Synced=True``. This budget bounds ONE delivery's wait, not the correctness of the role set: a card
# that is still not synced raises ``AgentCardNotReadyError``, which the NATS consumer naks, and the
# redelivery waits again. ≈28s; tests set fast.
_CARD_WAIT = WaitConfig("ONBOARD_CARD_WAIT_ATTEMPTS", "ONBOARD_CARD_WAIT_BACKOFF", 15, 2.0)

# Deploy->onboard race tolerance for the tool's MCP manifest — the THIRD race. A tool can answer
# ``tools/list`` with an EMPTY manifest while it is still starting, so an empty answer is re-polled
# before we give up with a 502. This wait covers the empty manifest ONLY: an endpoint that is not
# listening yet (refused / 5xx) is waited for inside ``_mcp_tools_list`` (bounded by
# ``AIAC_MCP_DISCOVERY_READY_TIMEOUT``), and any failure it raises is final — nesting this poll around
# that wait multiplied the worst case past the NATS ACK_WAIT. ≈60s of backoff, plus one quick call
# per look; well under ACK_WAIT.
_MCP_WAIT = WaitConfig("ONBOARD_MCP_WAIT_ATTEMPTS", "ONBOARD_MCP_WAIT_BACKOFF", 30, 2.0)


def poll_until_ready(probe, cfg: WaitConfig):
    """Re-poll ``probe`` up to ``cfg`` attempts, backing off between looks (skipped after the last).
    ``probe`` returns a non-``None`` 'ready' result to stop, or ``None`` to retry; it may raise to fail
    the whole wait immediately (a real error, never a race). Returns the ready result, or ``None`` once
    the attempt budget is exhausted — the caller then decides what an exhausted wait means."""
    attempts = env_num(cfg.attempts_env, cfg.default_attempts, int, minimum=1)
    backoff = env_num(cfg.backoff_env, cfg.default_backoff, float, minimum=0.0)
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

# How long discovery waits for the tool's MCP endpoint to become ready. The operator registers the
# tool's Keycloak client (which fires the onboarding event) while it still rolls the tool pod onto
# the AuthBridge-injected template, so the Service can have no ready endpoint for some seconds
# ("connection refused"), or the sidecar can answer 502/503/504 while the app starts. Also, the
# tool's OPA loads the bootstrap CR (written just before Provision, checkpoint B1) only at its next
# bundle poll (10 s to 120 s); until then the tool's inbound denies the discovery call with 403
# (D20). Failing here is retryable, but the NATS redelivery comes only after ACK_WAIT (600 s), so
# discovery waits for the endpoint instead. The default covers the bundle poll.
# Read from the env at call time; keep it well below ACK_WAIT.
_MCP_READY_TIMEOUT_ENV = "AIAC_MCP_DISCOVERY_READY_TIMEOUT"
_MCP_READY_TIMEOUT_DEFAULT = 180.0
_MCP_READY_INTERVAL = 3.0  # seconds between readiness attempts (patched in unit tests)


def _mcp_ready_timeout() -> float:
    """The discovery readiness budget in seconds; an unset, non-numeric, non-finite or negative
    value falls back to the default."""
    return env_num(_MCP_READY_TIMEOUT_ENV, _MCP_READY_TIMEOUT_DEFAULT, float, minimum=0.0)


def _endpoint_not_ready(exc: Exception) -> bool:
    """True for the failures of an MCP endpoint that is not ready yet: a connection-level error
    (refused, reset, connect timeout), a 502/503/504 from the sidecar, or a 403 from the tool's
    inbound OPA before it loads the bootstrap CR. A read timeout (the tool accepted the connection
    and hangs) and any other status are not waited for."""
    import requests

    if isinstance(exc, requests.ConnectionError):  # includes ConnectTimeout
        return True
    response = getattr(exc, "response", None)
    return isinstance(exc, requests.HTTPError) and getattr(response, "status_code", None) in (403, 502, 503, 504)


def _mcp_tools_list(endpoint: str, token: str | None = None) -> list[dict]:
    """POST a JSON-RPC `tools/list` to an MCP endpoint and return the tool manifest list.
    Each tool is a dict with `name` and (optional) `description`. When `token` is provided it is
    sent as an `Authorization: Bearer` header (the tool's MCP endpoint is fronted by an AuthBridge
    sidecar that validates inbound JWTs). Bounded transport retries are applied here so callers
    just map the final failure to a 502. Around them, an endpoint that is not ready yet (see
    ``_endpoint_not_ready``) is tried again every ``_MCP_READY_INTERVAL`` seconds until the
    ``AIAC_MCP_DISCOVERY_READY_TIMEOUT`` budget ends (default 180 s)."""
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

    deadline = time.monotonic() + _mcp_ready_timeout()
    while True:
        try:
            return run_upstream(_do)
        except requests.RequestException as exc:
            if not _endpoint_not_ready(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(_MCP_READY_INTERVAL)


def _owned_by(pod, workload_name: str) -> bool:
    """True if ``workload_name`` owns ``pod``: a Deployment's ReplicaSet (``{workload}-{hash}``: the
    name before its last ``-`` equals ``workload``, so ``github-tool-5d8f9`` is not a ReplicaSet of
    ``github``; the pod-template hash has no ``-``), or a StatefulSet / Sandbox whose name equals
    ``workload``."""
    for owner in getattr(pod.metadata, "owner_references", None) or []:
        if owner.kind == "ReplicaSet" and owner.name.rsplit("-", 1)[0] == workload_name:
            return True
        if owner.kind in ("StatefulSet", "Sandbox") and owner.name == workload_name:
            return True
    return False


def _owned_pods(pods, workload_name: str) -> list:
    """Every pod owned by ``workload_name`` (see ``_owned_by``), in list order."""
    return [pod for pod in pods if _owned_by(pod, workload_name)]


def split_client_name(service_id: str, name: str | None) -> tuple[str, str]:
    """``(namespace, workload_name)`` from the Keycloak ``client.name`` (``<namespace>/<workload>``).
    A name with no ``/`` raises ``HTTPException(502)``: the pod of the service cannot be found."""
    name = name or ""
    if "/" not in name:
        raise HTTPException(
            502,
            f"client.name {name!r} for service {service_id!r} has no '/': namespace/workload_name unrecoverable",
        )
    namespace, workload_name = name.split("/", 1)
    return namespace, workload_name


def _pod_service_type(pod, workload_name: str) -> ServiceType | None:
    """The service type from the operator's ``rossoctl.io/type`` label of ``pod``, or ``None`` while
    the label is absent (a deploy->onboard race). A label that is present with a value other than
    ``agent``/``tool`` is a real misconfiguration that no wait can fix: ``HTTPException(502)`` now."""
    label = (getattr(pod.metadata, "labels", None) or {}).get(_TYPE_LABEL)
    if not label:
        return None
    try:
        return ServiceType(label.capitalize())
    except ValueError:
        raise HTTPException(
            502,
            f"workload {workload_name!r}: {_TYPE_LABEL} label invalid (got {label!r}, expected 'agent' or 'tool')",
        )


def _label_missing_detail(workload_name: str, pod) -> str:
    """The 502 detail of an exhausted wait for the ``rossoctl.io/type`` label of ``pod``."""
    label = (getattr(pod.metadata, "labels", None) or {}).get(_TYPE_LABEL)
    return (
        f"workload {workload_name!r}: {_TYPE_LABEL} label missing or invalid "
        f"(got {label!r}, expected 'agent' or 'tool')"
    )


# --------------------------------------------------------------------------- #
# Nodes                                                                        #
# --------------------------------------------------------------------------- #
def classify_service(state: OnboardingProvisionState) -> dict:
    """Resolve identity and determine service type from the operator's `rossoctl.io/type`
    pod label (authoritative — not the entity_id format).

    The UC1 Orchestrator has already read the service and its pod label (the precondition checks run
    first), and gives ``namespace``, ``workload_name`` and ``service_type`` in the state: then this
    node makes no IdP read and no second pod wait."""
    service_id = state.trigger.entity_id
    if state.service_type is not None and state.namespace and state.workload_name:
        return {
            "service_id": service_id,
            "namespace": state.namespace,
            "workload_name": state.workload_name,
            "service_type": state.service_type,
        }

    try:
        service = _config().get_service(service_id)
    except Exception as e:
        raise HTTPException(502, f"IdP config unavailable resolving service {service_id!r}: {e}")

    namespace, workload_name = split_client_name(service_id, service.name)

    service_type, _ = await_labelled_pods(namespace, workload_name)

    return {
        "service_id": service_id,
        "namespace": namespace,
        "workload_name": workload_name,
        "service_type": service_type,
    }


class WorkloadNotReadyError(HTTPException):
    """The workload is still not ready for the pod checks after the bounded pod wait (see
    :func:`await_labelled_pods`): the rollout of its Deployment is not complete, or it has no live pod
    with the ``rossoctl.io/type`` label. It is an ``HTTPException(502)``, so the HTTP route answers
    ``502``, and the NATS consumer naks it with a delay. ``template`` is the Deployment's pod template
    when the last look found the rollout not complete (the precondition checks run #6 on it), else
    ``None``."""

    def __init__(self, detail: str, template=None) -> None:
        super().__init__(502, detail)
        self.template = template


def _rollout_pending(deployment) -> str | None:
    """``None`` when the rollout of ``deployment`` is complete, else its counters. The test is the
    Deployment controller's own ``DeploymentComplete``: the controller saw the latest generation, and
    every replica is updated and available, with no old pod left. ``status.replicas`` does not count a
    terminating pod, so the caller still skips those. The API omits a zero counter (``None`` here)."""
    status = deployment.status
    generation = deployment.metadata.generation or 0
    observed = getattr(status, "observed_generation", None) or 0
    # The API server defaults a missing spec.replicas to 1.
    want = deployment.spec.replicas if deployment.spec.replicas is not None else 1
    replicas = getattr(status, "replicas", None) or 0
    updated = getattr(status, "updated_replicas", None) or 0
    available = getattr(status, "available_replicas", None) or 0
    if observed >= generation and updated == want and replicas == updated and available == want:
        return None
    return (
        f"the rollout of its Deployment is not complete (generation {generation}, observedGeneration "
        f"{observed}, spec.replicas {want}, replicas {replicas}, updatedReplicas {updated}, "
        f"availableReplicas {available})"
    )


def await_labelled_pods(
    namespace: str, workload_name: str, settled: Callable[[ServiceType, list], bool] | None = None
) -> tuple[ServiceType, list]:
    """The service type (from the operator's ``rossoctl.io/type`` pod label) and the live (not
    terminating) pods of ``workload_name``, tolerating the deploy->onboard RACE (the rollout may not be
    complete, and the pod or its label may not be there yet — see the module knobs above).

    Each look reads the workload's Deployment first. The operator rolls it more than once after a
    deploy, so the pods are read only when its rollout is complete (``_rollout_pending``); then they are
    the pods of the final template. A Deployment that is not there (``404``: a StatefulSet or a
    ``Sandbox``, or a Deployment deleted since the event) gives the pod list with no rollout gate. Any
    other Deployment read error, a pod LIST failure, or a label present with an INVALID value (not
    ``agent``/``tool``) is a real failure that no wait can fix: a plain ``HTTPException(502)`` at once.
    A rollout in progress, a not-yet-created pod or a briefly-absent label is a not-ready state,
    re-polled a bounded number of times. The poll ends at the first look that finds a labelled pod for
    which ``settled(service_type, pods)`` is true (with no ``settled``, at the first labelled pod).
    Retries exhausted -> the labelled ``(service_type, pods)`` of the last look if it had one (the
    caller reports them), else :class:`WorkloadNotReadyError`, which names the state of the last look.
    Provision's ``classify_service`` and the UC1 precondition checks (D30) share this wait."""
    no_pod_detail = f"no pod owned by workload {workload_name!r} in namespace {namespace!r}"
    detail = no_pod_detail
    last: tuple[ServiceType, list] | None = None
    template = None

    def _probe():
        nonlocal detail, last, template
        # Re-derive per attempt so the exhausted wait reflects the LAST-seen state: a pod that
        # disappears mid-poll must report "no pod", not a stale "label missing" from an earlier attempt.
        detail, last, template = no_pod_detail, None, None
        # The Deployment first: a pod list read before the status can be older than that status.
        try:
            deployment = read_deployment(workload_name, namespace)
        except Exception as e:
            if not is_not_found(e):
                raise HTTPException(
                    502, f"Kubernetes Deployment GET failed for {workload_name!r} in namespace {namespace!r}: {e}"
                )
            deployment = None
        if deployment is not None:
            pending = _rollout_pending(deployment)
            if pending:
                detail = f"workload {workload_name!r} in namespace {namespace!r}: {pending}"
                template = deployment.spec.template
                return None
        try:
            items = list_pods(namespace)
        except Exception as e:
            raise HTTPException(502, f"Kubernetes pod LIST failed in namespace {namespace!r}: {e}")

        pods = [p for p in _owned_pods(items, workload_name) if getattr(p.metadata, "deletion_timestamp", None) is None]
        if not pods:
            return None
        # Present but not agent/tool raises now: a real misconfiguration, never a race.
        service_type = _pod_service_type(pods[0], workload_name)
        if service_type is None:
            detail = _label_missing_detail(workload_name, pods[0])
            return None
        last = (service_type, pods)
        return last if settled is None or settled(service_type, pods) else None

    ready = poll_until_ready(_probe, _LABEL_WAIT)
    if ready is not None:
        return ready
    if last is not None:
        return last
    raise WorkloadNotReadyError(detail, template)


class AgentCardNotReadyError(HTTPException):
    """The agent's AgentCard is still not ``Synced=True`` after the bounded card wait (see
    :func:`_await_agent_skills`). It is an ``HTTPException(502)``, so the HTTP route answers ``502``,
    and the NATS consumer can tell it from the other retryable failures (it naks it with a delay)."""

    def __init__(self, detail: str) -> None:
        super().__init__(502, detail)


def _await_agent_skills(namespace: str, workload: str) -> list[dict]:
    """The skills of an agent's synced AgentCard, tolerating the deploy->onboard RACE on the card sync
    (see the module knobs above).

    The operator writes the fetched A2A card onto ``status.card`` and sets the card's ``Synced``
    condition in one status update, only AFTER the workload is Available and a fetch succeeds — a
    DIFFERENT, later operator action than the Keycloak-client registration that triggers onboarding.
    So the card is ready only when ``Synced`` is ``True``. Skills alone are not proof: a card keeps its
    old skills when a later fetch fails, and holds the rejected skills on a failed signature check. An
    absent card, or a card that is not ``Synced=True`` (for any reason), is a not-ready state, re-polled
    a bounded number of times. Returns the skills of the first ``Synced=True`` look (the list may be
    empty). Budget exhausted -> :class:`AgentCardNotReadyError`, naming the state of the last look."""

    # Link the card to the workload by its ``spec.targetRef`` (the Deployment it describes), since the
    # operator names the CR after the Deployment (e.g. ``<workload>-deployment-card``), not the
    # workload. Fall back to ``metadata.name == workload`` for hand-authored/legacy cards.
    def _targets_workload(c: dict) -> bool:
        target = ((c.get("spec") or {}).get("targetRef") or {}).get("name")
        return target == workload or (c.get("metadata") or {}).get("name") == workload

    detail = ""

    def _probe():
        nonlocal detail
        try:
            resp = list_agentcards(namespace)
        except Exception as e:
            raise HTTPException(502, f"Kubernetes AgentCard LIST failed in namespace {namespace!r}: {e}")

        card = next((c for c in resp.get("items", []) if _targets_workload(c)), None)
        if card is None:
            detail = (
                "no AgentCard targets the workload (the operator creates one only for a workload with the "
                "'rossoctl.io/type=agent' label and a 'protocol.rossoctl.io/<name>' label)"
            )
            return None
        name = (card.get("metadata") or {}).get("name")
        status = card.get("status") or {}
        synced = next((c for c in status.get("conditions") or [] if c.get("type") == "Synced"), None)
        if synced is None:
            detail = f"AgentCard {name!r} has no Synced condition yet"
            return None
        if synced.get("status") != "True":
            detail = (
                f"AgentCard {name!r} is Synced={synced.get('status')} ({synced.get('reason')}): {synced.get('message')}"
            )
            return None
        return (status.get("card") or {}).get("skills") or []

    skills = poll_until_ready(_probe, _CARD_WAIT)
    if skills is None:
        raise AgentCardNotReadyError(
            f"AgentCard of workload {workload!r} in namespace {namespace!r} is not Synced=True within the "
            f"{_CARD_WAIT.attempts_env} budget: {detail}"
        )
    return skills


def analyze_agent(state: OnboardingProvisionState) -> dict:
    """Derive an agent's roles + scopes from its AgentCard CR (non-LLM).

    The operator fetches the agent's A2A card and syncs it onto the CR's ``status.card``; each skill
    there carries a machine ``id`` (a stable identifier, e.g. ``source_operations``) plus a display
    ``name`` (which may contain spaces). Scope names are built from the skill ``id`` so they are
    usable Keycloak scope names, and each skill also gets a **per-skill operator role** mirroring the
    scope (same name + description): the role's description is what the PRB capability-match reads to
    confine and grant the agent's outbound access on a domain basis.

    Because the operator syncs the card only after the workload is Available and a fetch succeeds —
    later than the event that triggers onboarding — the card is awaited with a bounded retry until it
    is ``Synced=True`` (``_await_agent_skills``). A card that is still not synced (or no card) raises
    :class:`AgentCardNotReadyError`, which the NATS consumer naks, so a later delivery waits again.
    Falls back to a default access scope + a default operator role only for a ``Synced=True`` card
    with no skills."""
    namespace, workload = state.namespace, state.workload_name

    skills = _await_agent_skills(namespace, workload)
    if not skills:
        provision = ServiceProvision(
            roles=[RoleDefinition(name=f"{workload}.access", description="Default access scope")],
            scopes=[ScopeDefinition(name=f"{workload}.access", description="Default access scope")],
            reasoning="partial: AgentCard has no synced skills, default scope assigned",
        )
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

    # ``_mcp_tools_list`` already waits for a not-listening-yet endpoint and applies its own transport
    # retries, so any exception it raises is final and maps straight to a 502 — re-polling it here
    # would nest a third retry loop and run the worst case far past the NATS ACK_WAIT. The outer poll
    # (see _MCP_WAIT) is for an EMPTY manifest only: a tool contributing zero scopes yields a tool
    # inbound with no tool scopes (no grant can pass; only the self-discovery rule stays), which is the
    # silent half-policy this wait exists to prevent, so it is better to keep looking and then fail
    # loudly than to accept it.
    def _probe():
        try:
            return _mcp_tools_list(endpoint, token=token) or None
        except Exception as e:
            raise HTTPException(502, f"MCP tools/list failed at {endpoint}: {e}")

    tools = poll_until_ready(_probe, _MCP_WAIT)
    if tools is None:
        raise HTTPException(
            502,
            f"MCP tools/list at {endpoint} never returned a non-empty tool manifest within the "
            f"{_MCP_WAIT.attempts_env} budget (tool not serving, or it exposes no tools)",
        )

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
    return {"service_provision": provision}


def provision_service(state: OnboardingProvisionState) -> dict:
    """Write the derived roles + scopes into the IdP (idempotent create-or-get + map), link the
    shared subject scope ``aiac-username-sub`` to the client (D31), and persist the discovered
    service type onto the Keycloak client, via the idp-library.

    The subject-scope link (``link_subject_scope``, idempotent) runs for agents and tools alike,
    before ``set_service_type``. It makes an exchanged token have ``sub`` = username. A failure of
    the link is a ``502`` and the type is then not set.

    Returns the `ServiceProvision` + `service_type` to the Orchestrator, plus the
    **created-manifest** (`created_roles` / `created_scopes`): exactly the entities this run
    *created*, not the ones it *reused by name*. The idempotent `create_service_role` /
    `create_service_scope` return `(entity, created)`, and an entity goes into the manifest only
    when `created` is true. A reuse is not created: an entity that was there before this run, and
    also one that a concurrent Provision of another service with the same workload name created
    after this run's check (its create then answers `409`, and the library reuses the entity,
    REJ-02). The Orchestrator's compensating rollback deletes only this manifest, so a role/scope
    that another service created is never torn down. The subject scope is shared by all managed
    clients, so it is never in the manifest."""
    config = _config()
    provision = state.service_provision
    service_id = state.service_id

    created_roles = []
    created_scopes = []
    try:
        for role in provision.roles:
            resolved_role, created = config.create_service_role(service_id, role)
            if created:
                created_roles.append(resolved_role)
        for scope in provision.scopes:
            resolved_scope, created = config.create_service_scope(service_id, scope)
            if created:
                created_scopes.append(resolved_scope)
        service = config.get_service(service_id)
        # D31: an exchanged token gets sub = username only from the scopes of the agent client
        # (the requester), so every managed client links aiac-username-sub. Link it before
        # set_service_type, so that every client with client.type has the link. The scope is
        # shared by all managed clients, so it is never in the created-manifest.
        config.link_subject_scope(service)
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
