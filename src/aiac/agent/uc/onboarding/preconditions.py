"""UC1 enforcement precondition checks (D30).

The Orchestrator runs these checks first in ``onboard_service``: after the one IdP read that
resolves the clientId, and before Provision and the PRB. Each check tells whether the pod of the
focus service can enforce its CR:

- **#1 — the sidecar:** every pod of the service has the AuthBridge sidecar container
  ``authbridge-proxy``. Without it, no OPA is in front of the service, and its CR has no effect.
- **#2 — the pipeline:** the namespace ConfigMap ``authbridge-runtime-config`` (key
  ``config.yaml``, ``pipeline.inbound.plugins[].name``) has ``opa`` in the inbound pipeline, and
  also ``mcp-parser`` for a tool (the tool's inbound package checks ``input.mcp.params.name``).
  Under agent side, ``opa`` must also be in the outbound pipeline
  (``pipeline.outbound.plugins[].name``), because the agent's outbound checks its calls to tools.
  A missing ConfigMap fails the check. One #2 failure names each missing plugin.
- **#6 — the probes:** no app container (every container except ``authbridge-proxy``) has an
  ``httpGet`` readiness, liveness or startup probe. A kubelet probe carries no identity, and no
  request without identity passes a rules-based inbound package (D27).

**Scope for each side (D30).** The checks read the enforcement side with the PCE
``enforcement_side()``, once per onboarding. Under target side they run for every service, agent or
tool. Under agent side they run for agents only: a tool gets a pass-through CR (D24), which needs no
check, so a tool gets no #1, #2 or #6 failure (and its pipeline ConfigMap is not read). The type of
a tool is still read from its pod label, because the Orchestrator needs it for the bootstrap of the
tool's CR (the catalog type is not set before Provision).

The checks find the pods of the service and its type as Provision's ``classify_service`` does: the
``client.name`` split, the pod selection by ``ownerReferences``, the ``rossoctl.io/type`` label and
the same bounded re-poll (``ONBOARD_LABEL_WAIT_*``). A pod or a label that is not there yet is a
deploy->onboard race, not a failed check: an exhausted wait is ``HTTPException(502)``, as in
Provision. A pod that fails #1 or #6 is re-polled in the same window too, because the operator can
still roll the workload onto the AuthBridge-injected template (an old pod without the sidecar is
then still there); a terminating pod is not checked. When the checks do not apply (a tool under
agent side), the first labelled pod ends the poll. A Kubernetes API failure is a ``502``.

A failed check raises :class:`EnforcementPreconditionError`, which names each failed check.
"""

import yaml
from fastapi import HTTPException

from aiac.idp.configuration.models import Service, ServiceType
from aiac.policy.computation import enforcement_side
from aiac.policy.model.models import EnforcementSide

from .provision.kube import is_not_found, list_pods, read_configmap
from .provision.nodes import (
    LABEL_WAIT,
    label_missing_detail,
    owned_pods,
    pod_service_type,
    poll_until_ready,
    split_client_name,
)

SIDECAR_CONTAINER = "authbridge-proxy"
PIPELINE_CONFIGMAP = "authbridge-runtime-config"
PIPELINE_CONFIG_KEY = "config.yaml"

_PROBE_ATTRS = (("readiness_probe", "readiness"), ("liveness_probe", "liveness"), ("startup_probe", "startup"))


class EnforcementPreconditionError(Exception):
    """One or more UC1 precondition checks (D30) failed: the pod of the service cannot enforce its CR.

    ``failures`` has one item for each failed check, and each item names that check (``#1``,
    ``#2`` or ``#6``). The checks run before Provision, so nothing exists yet that needs
    compensation: this is not a rollback error (no rollback, no client disable, no quarantine). The
    Controller maps it to HTTP 409, and the NATS consumer treats it as permanent (DLQ at the first
    delivery). After a fix in the cluster, the operator starts the onboarding again."""

    def __init__(self, failures: list[str]) -> None:
        self.failures = list(failures)
        super().__init__("enforcement precondition checks failed: " + "; ".join(self.failures))


def check_preconditions(service: Service) -> ServiceType:
    """Run the checks #1, #2 and #6 on ``service`` and return its type (from the pod label).

    The side is read once (``enforcement_side()``; an unknown value raises ``ValueError``). Under
    agent side a tool gets no check (its pass-through CR needs none), but its type is still read.
    Every check that applies runs; if one or more fail, raise one
    :class:`EnforcementPreconditionError` that names each failed check (in the order #1, #2, #6).
    The type is returned because the caller needs it before Provision (the catalog type is not set
    yet)."""
    side = enforcement_side()
    namespace, workload = split_client_name(service.id, service.name)
    service_type, pods = _await_pods(namespace, workload, side)
    if not _checks_apply(side, service_type):
        return service_type
    failures = [
        *_check_sidecar(pods, namespace),
        *_check_pipeline(namespace, service_type, side),
        *_check_probes(pods),
    ]
    if failures:
        raise EnforcementPreconditionError(failures)
    return service_type


def _checks_apply(side: EnforcementSide, service_type: ServiceType) -> bool:
    """The scope of the checks (D30): every service under target side, agents only under agent side
    (a tool gets a pass-through CR, which needs no check)."""
    return side is EnforcementSide.TARGET_SIDE or service_type is ServiceType.AGENT


def _await_pods(namespace: str, workload: str, side: EnforcementSide) -> tuple[ServiceType, list]:
    """The type and the live (not terminating) pods of ``workload``, with the bounded re-poll.

    The poll ends early when a labelled pod is there and, if the checks apply to the type (see
    :func:`_checks_apply`), every pod passes #1 and #6. When the budget ends, the last-seen pods are
    returned (so #1 / #6 report them), or, if no labelled pod was seen at the last look,
    ``HTTPException(502)`` (as ``classify_service``)."""
    no_pod_detail = f"no pod owned by workload {workload!r} in namespace {namespace!r}"
    detail = no_pod_detail
    last: tuple[ServiceType, list] | None = None

    def _probe():
        nonlocal detail, last
        detail, last = no_pod_detail, None
        try:
            items = list_pods(namespace)
        except Exception as e:
            raise HTTPException(502, f"Kubernetes pod LIST failed in namespace {namespace!r}: {e}")
        pods = [p for p in owned_pods(items, workload) if getattr(p.metadata, "deletion_timestamp", None) is None]
        if not pods:
            return None
        service_type = pod_service_type(pods[0], workload)  # an invalid label raises 502 now
        if service_type is None:
            detail = label_missing_detail(workload, pods[0])
            return None
        last = (service_type, pods)
        if not _checks_apply(side, service_type):
            return last
        return None if _check_sidecar(pods, namespace) or _check_probes(pods) else last

    ready = poll_until_ready(_probe, LABEL_WAIT)
    if ready is not None:
        return ready
    if last is not None:
        return last
    raise HTTPException(502, detail)


def _pod_name(pod) -> str:
    return getattr(pod.metadata, "name", None) or "?"


def _check_sidecar(pods, namespace: str) -> list[str]:
    """#1: every pod has the ``authbridge-proxy`` container."""
    missing = [_pod_name(p) for p in pods if not any(c.name == SIDECAR_CONTAINER for c in (p.spec.containers or []))]
    if not missing:
        return []
    return [
        f"#1 sidecar: pod(s) {', '.join(repr(n) for n in missing)} in namespace {namespace!r} "
        f"have no {SIDECAR_CONTAINER!r} container"
    ]


def _check_probes(pods) -> list[str]:
    """#6: no app container (every container except ``authbridge-proxy``) has an ``httpGet`` probe."""
    found = []
    for pod in pods:
        for c in pod.spec.containers or []:
            if c.name == SIDECAR_CONTAINER:
                continue
            kinds = [kind for attr, kind in _PROBE_ATTRS if getattr(getattr(c, attr, None), "http_get", None)]
            if kinds:
                found.append(f"container {c.name!r} of pod {_pod_name(pod)!r} ({', '.join(kinds)})")
    if not found:
        return []
    return [f"#6 probes: httpGet probes on app containers: {'; '.join(found)} (use tcpSocket or exec probes)"]


def _required_inbound_plugins(service_type: ServiceType) -> list[str]:
    """The plugins #2 needs in the inbound pipeline: ``opa``, and also ``mcp-parser`` for a tool."""
    return ["mcp-parser", "opa"] if service_type is ServiceType.TOOL else ["opa"]


def _required_outbound_plugins(side: EnforcementSide) -> list[str]:
    """The plugins #2 needs in the outbound pipeline: ``opa`` under agent side (the agent's outbound
    checks its calls to tools), none under target side (every outbound is a pass-through, D24)."""
    return ["opa"] if side is EnforcementSide.AGENT_SIDE else []


def _plugin_names(config, direction: str) -> set | None:
    """The plugin names of ``pipeline.<direction>.plugins`` in ``config``, or ``None`` if that list
    cannot be read."""
    try:
        plugins = config["pipeline"][direction]["plugins"] or []
        return {p.get("name") for p in plugins if isinstance(p, dict)}
    except (KeyError, TypeError, AttributeError):
        return None


def _check_pipeline(namespace: str, service_type: ServiceType, side: EnforcementSide) -> list[str]:
    """#2: the namespace pipeline (``authbridge-runtime-config``) has the required inbound plugins,
    and under agent side also the required outbound plugins. One failure names every problem."""
    where = f"ConfigMap {PIPELINE_CONFIGMAP!r} in namespace {namespace!r}"
    try:
        configmap = read_configmap(PIPELINE_CONFIGMAP, namespace)
    except Exception as e:
        if is_not_found(e):
            return [f"#2 pipeline: {where} not found"]
        raise HTTPException(502, f"Kubernetes ConfigMap GET failed for {where}: {e}")
    try:
        config = yaml.safe_load((getattr(configmap, "data", None) or {}).get(PIPELINE_CONFIG_KEY) or "") or {}
    except (yaml.YAMLError, AttributeError):
        config = None
    kind = "an agent" if service_type is ServiceType.AGENT else "a tool"
    required = {
        "inbound": (_required_inbound_plugins(service_type), f"needed for {kind}"),
        "outbound": (_required_outbound_plugins(side), f"needed for {kind} under agent side"),
    }
    problems = []
    for direction, (plugins, reason) in required.items():
        if not plugins:
            continue
        names = _plugin_names(config, direction)
        if names is None:
            problems.append(f"no readable pipeline.{direction}.plugins in {PIPELINE_CONFIG_KEY!r}")
            continue
        missing = [name for name in plugins if name not in names]
        if missing:
            problems.append(f"the {direction} pipeline has no {', '.join(repr(n) for n in missing)} plugin ({reason})")
    if not problems:
        return []
    return [f"#2 pipeline: {where}: " + "; ".join(problems)]
