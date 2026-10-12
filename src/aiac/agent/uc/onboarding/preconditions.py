"""UC1 enforcement precondition checks (D30).

The Orchestrator runs these checks first in ``onboard_and_apply``: after the one IdP read that
resolves the clientId, and before Provision and the PRB. Each check tells whether the pod of the
focus service can enforce its CR:

- **#1 — the sidecar:** every pod of the service has the AuthBridge sidecar container
  ``authbridge-proxy``. Without it, no OPA is in front of the service, and its CR has no effect.
- **#2 — the pipeline:** the namespace ConfigMap ``authbridge-runtime-config`` (key
  ``config.yaml``, ``pipeline.inbound.plugins[].name``) has ``jwt-validation`` in the inbound
  pipeline of every service (it is the only plugin that validates the token and sets
  ``input.identity``), ``opa`` in the inbound pipeline of every agent and of a tool under target
  side, and also ``mcp-parser`` for a tool under target side (the tool's inbound package checks
  ``input.mcp.params.name``). Under agent side a tool needs only
  ``jwt-validation`` (its pass-through CR, D24, needs no ``opa`` and no ``mcp-parser``, but without
  ``jwt-validation`` the tool is open to every caller). Under agent side, ``mcp-parser`` and ``opa``
  must also be in the outbound pipeline of an agent (``pipeline.outbound.plugins[].name``), because
  the agent's outbound checks its calls to tools (its package reads ``input.mcp.method`` and
  ``input.mcp.params.name``). A required plugin counts only if its entry enforces: an entry with
  ``on_error: off`` (cortex takes the plugin out of the running pipeline) or ``on_error: observe``
  (cortex turns its Reject into a pass-through) fails the check. A missing ConfigMap fails the
  check. One #2 failure names each missing or not-enforcing plugin.
- **#6 — the probes:** no app container (every container except ``authbridge-proxy``) has an
  ``httpGet`` readiness, liveness or startup probe. A kubelet probe carries no identity, and no
  request without identity passes a rules-based inbound package (D27).

**Scope for each side (D30).** The checks read the enforcement side with the PCE
``enforcement_side()``, once per onboarding. #1 and #2 run for every service, agent or tool, under
both sides (#2 needs other plugins for each side and type, see above). #6 runs for every service
under target side, and for agents only under agent side: a tool then gets a pass-through CR (D24),
which needs no identity, so a kubelet probe opens nothing. The type is read from the pod label,
because the Orchestrator needs it for the bootstrap of a tool's CR (the catalog type is not set
before Provision).

The checks find the pods of the service and its type as Provision's ``classify_service`` does: the
``client.name`` split, the pod selection by ``ownerReferences``, the ``rossoctl.io/type`` label and
the same bounded re-poll (``ONBOARD_LABEL_WAIT_*``). A pod or a label that is not there yet is a
deploy->onboard race, not a failed check: an exhausted wait is ``HTTPException(502)``, as in
Provision. A pod that fails #1 or #6 is re-polled in the same window too, because the operator can
still roll the workload onto the AuthBridge-injected template (an old pod without the sidecar is
then still there); a terminating pod is not checked. A Kubernetes API failure is a ``502``.

A failed check raises :class:`EnforcementPreconditionError`, which names each failed check.
"""

import yaml
from fastapi import HTTPException

from aiac.idp.configuration.models import Service, ServiceType
from aiac.policy.computation import enforcement_side
from aiac.policy.model.models import EnforcementSide

from .provision.kube import is_not_found, read_configmap
from .provision.nodes import await_labelled_pods, split_client_name

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

    The side is read once (``enforcement_side()``; an unknown value raises ``ValueError``). #1 and
    #2 run for every service; #6 only where it applies (:func:`_probes_apply`: not for a tool under
    agent side). Every check that applies runs; if one or more fail, raise one
    :class:`EnforcementPreconditionError` that names each failed check (in the order #1, #2, #6).
    The type is returned because the caller needs it before Provision (the catalog type is not set
    yet)."""
    side = enforcement_side()
    namespace, workload = split_client_name(service.id, service.name)
    service_type, pods = _await_pods(namespace, workload, side)
    failures = [
        *_check_sidecar(pods, namespace),
        *_check_pipeline(namespace, service_type, side),
        *(_check_probes(pods) if _probes_apply(side, service_type) else []),
    ]
    if failures:
        raise EnforcementPreconditionError(failures)
    return service_type


def _probes_apply(side: EnforcementSide, service_type: ServiceType) -> bool:
    """#6 applies to every service under target side, and to agents only under agent side. A tool then
    has a pass-through CR (D24), which needs no identity, so a probe opens nothing; a probe on a path
    that ``jwt-validation`` does not bypass only keeps the pod not ready."""
    return side is EnforcementSide.TARGET_SIDE or service_type is ServiceType.AGENT


def _await_pods(namespace: str, workload: str, side: EnforcementSide) -> tuple[ServiceType, list]:
    """The type and the live (not terminating) pods of ``workload``, with Provision's bounded
    re-poll (:func:`await_labelled_pods`).

    The poll ends early when a labelled pod is there and every pod passes #1 and, where it applies
    (:func:`_probes_apply`), #6. When the budget ends, the last-seen pods are
    returned (so #1 / #6 report them), or, if no labelled pod was seen at the last look,
    ``HTTPException(502)`` (as ``classify_service``)."""

    def _settled(service_type: ServiceType, pods: list) -> bool:
        return not (_check_sidecar(pods, namespace) or (_probes_apply(side, service_type) and _check_probes(pods)))

    return await_labelled_pods(namespace, workload, _settled)


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


def _required_inbound_plugins(service_type: ServiceType, side: EnforcementSide) -> list[str]:
    """The plugins #2 needs in the inbound pipeline. Every service needs ``jwt-validation``: it is the only
    plugin that validates the token and sets ``input.identity``. Without it, every rules-based package
    denies (D27), and under agent side a tool (pass-through CR) is open to every caller. ``opa`` for
    every service except a tool under agent side (its pass-through CR, D24), and also ``mcp-parser`` for
    a tool under target side (the tool's inbound package checks ``input.mcp.params.name``)."""
    if service_type is ServiceType.AGENT:
        return ["jwt-validation", "opa"]
    if side is EnforcementSide.AGENT_SIDE:
        return ["jwt-validation"]
    return ["jwt-validation", "mcp-parser", "opa"]


def _required_outbound_plugins(service_type: ServiceType, side: EnforcementSide) -> list[str]:
    """The plugins #2 needs in the outbound pipeline: ``mcp-parser`` and ``opa`` for an agent under agent
    side (the agent's outbound checks its calls to tools, and its Rego reads ``input.mcp.method`` and
    ``input.mcp.params.name``, which ``mcp-parser`` sets), none under target side (every outbound is
    a pass-through, D24), and none for a tool (its outbound is a pass-through under both sides, D24)."""
    return ["mcp-parser", "opa"] if side is EnforcementSide.AGENT_SIDE and service_type is ServiceType.AGENT else []


def _on_error(entry: dict) -> str:
    """The ``on_error`` (cortex ErrorPolicy) of a plugin entry, with the default ``enforce``. An
    unquoted ``off`` is YAML 1.1 false for PyYAML, but cortex (yaml.v3) reads it as ``off``."""
    value = entry.get("on_error")
    if value is None or value == "":
        return "enforce"
    if value is False:
        return "off"
    return str(value)


def _plugin_policies(config, direction: str) -> dict[str, str] | None:
    """The plugins of ``pipeline.<direction>.plugins`` in ``config``, as name -> ``on_error``, or
    ``None`` if that list cannot be read. An entry is a map or a bare name (cortex reads a bare name
    as ``{name: <name>}``, so ``enforce``). If a name has more than one entry, an ``enforce`` one wins."""
    try:
        plugins = config["pipeline"][direction]["plugins"] or []
        policies: dict[str, str] = {}
        for p in plugins:
            if isinstance(p, str):
                name, policy = p, "enforce"
            elif isinstance(p, dict) and isinstance(p.get("name"), str):
                name, policy = p["name"], _on_error(p)
            else:
                continue
            if policies.get(name) != "enforce":
                policies[name] = policy
        return policies
    except (KeyError, TypeError, AttributeError):
        return None


def _check_pipeline(namespace: str, service_type: ServiceType, side: EnforcementSide) -> list[str]:
    """#2: the namespace pipeline (``authbridge-runtime-config``) has the required inbound plugins,
    and for an agent under agent side also the required outbound plugins, each with an enforcing
    ``on_error``. One failure names every problem."""
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
    reason = f"needed for {kind} under {side.value.replace('-', ' ')}"
    required = {
        "inbound": _required_inbound_plugins(service_type, side),
        "outbound": _required_outbound_plugins(service_type, side),
    }
    problems = []
    for direction, plugins in required.items():
        if not plugins:
            continue
        policies = _plugin_policies(config, direction)
        if policies is None:
            problems.append(f"no readable pipeline.{direction}.plugins in {PIPELINE_CONFIG_KEY!r}")
            continue
        missing = [name for name in plugins if name not in policies]
        if missing:
            problems.append(f"the {direction} pipeline has no {', '.join(repr(n) for n in missing)} plugin ({reason})")
        # `off` takes the plugin out of the running pipeline, and `observe` turns its Reject into a
        # pass-through: such an entry is there, but it does not enforce.
        problems += [
            f"the {direction} plugin {name!r} has on_error={policies[name]!r}, so it does not enforce ({reason})"
            for name in plugins
            if name in policies and policies[name] != "enforce"
        ]
    if not problems:
        return []
    return [f"#2 pipeline: {where}: " + "; ".join(problems)]
