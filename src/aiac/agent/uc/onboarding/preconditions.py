"""UC1 enforcement precondition checks (D30).

The Orchestrator runs these checks first in ``onboard_and_apply``: after the one IdP read that
resolves the clientId, and before Provision and the PRB. Each check tells whether the pod of the
focus service can enforce its CR:

- **#1 — the sidecar:** every pod of the service has the AuthBridge sidecar container
  ``authbridge-proxy``. Without it, no OPA is in front of the service, and its CR has no effect.
- **#2 — the pipeline:** the namespace ConfigMap ``authbridge-runtime-config`` (key
  ``config.yaml``, ``pipeline.inbound.plugins[].name``) has ``jwt-validation`` and ``opa`` in the
  inbound pipeline of every service (``jwt-validation`` is the only plugin that validates the token
  and sets ``input.identity``), and also ``mcp-parser`` for a tool (the tool's inbound package
  checks ``input.mcp.params.name``). The outbound pipeline is not checked: every outbound is a
  pass-through (D24). A required plugin counts only if its entry enforces: an entry with
  ``on_error: off`` (cortex takes the plugin out of the running pipeline) or ``on_error: observe``
  (cortex turns its Reject into a pass-through) fails the check. A missing ConfigMap fails the
  check. One #2 failure names each missing or not-enforcing plugin.
- **#6 — the probes:** no app container (every container except ``authbridge-proxy``) has an
  ``httpGet`` readiness, liveness or startup probe. A kubelet probe carries no identity, and no
  request without identity passes a rules-based inbound package (D27).

**Scope (D30).** #1, #2 and #6 run for every service, agent or tool (#2 needs other plugins for
each type, see above). The type is read from the pod label, because the Orchestrator needs it for
the bootstrap of a tool's CR (the catalog type is not set before Provision).

The checks find the pods of the service and its type as Provision's ``classify_service`` does: the
``client.name`` split, the rollout of the workload's Deployment, the pod selection by
``ownerReferences``, the ``rossoctl.io/type`` label and the same bounded re-poll
(``ONBOARD_LABEL_WAIT_*``). The operator rolls the Deployment more than once after a deploy, so the
pods are read only when its rollout is complete. A rollout in progress, or a pod or a label that is
not there yet, is a deploy->onboard race, not a failed check: an exhausted wait is
``WorkloadNotReadyError`` (a ``502`` that the NATS consumer naks). A pod that fails #1 or #6 is
re-polled in the same window too; a terminating pod is not checked. A rollout that is never complete
can be a #6 failure (an ``httpGet`` probe through the sidecar keeps the pod not Ready), so #6 also runs
on the Deployment's pod template at the end of such a wait. A Kubernetes API failure is a ``502``.

A failed check raises :class:`EnforcementPreconditionError`, which names each failed check.
"""

import yaml
from fastapi import HTTPException

from aiac.idp.configuration.models import Service, ServiceType

from .provision.kube import is_not_found, read_configmap
from .provision.nodes import WorkloadNotReadyError, await_labelled_pods, split_client_name

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

    Every check runs; if one or more fail, raise one :class:`EnforcementPreconditionError` that
    names each failed check (in the order #1, #2, #6). The type is returned because the caller
    needs it before Provision (the catalog type is not set yet)."""
    namespace, workload = split_client_name(service.id, service.name)
    service_type, pods = _await_pods(namespace, workload)
    failures = [
        *_check_sidecar(pods, namespace),
        *_check_pipeline(namespace, service_type),
        *_check_probes(_pod_specs(pods)),
    ]
    if failures:
        raise EnforcementPreconditionError(failures)
    return service_type


def _await_pods(namespace: str, workload: str) -> tuple[ServiceType, list]:
    """The type and the live (not terminating) pods of ``workload``, with Provision's bounded
    re-poll (:func:`await_labelled_pods`).

    The poll ends early when the rollout is complete, a labelled pod is there and every pod passes
    #1 and #6. When the budget ends, the last-seen pods are returned (so #1 / #6 report them), or, if
    the last look found no labelled pod of a complete rollout, :class:`WorkloadNotReadyError`. When
    that look found the rollout not complete, #6 runs on the Deployment's pod template first: the
    operator does not change the probes, so a failure there is a failed check, not a race."""

    def _settled(service_type: ServiceType, pods: list) -> bool:
        return not (_check_sidecar(pods, namespace) or _check_probes(_pod_specs(pods)))

    try:
        return await_labelled_pods(namespace, workload, _settled)
    except WorkloadNotReadyError as e:
        if e.template is None:
            raise
        # The template has no pod name: name it after the workload in the #6 failure.
        failures = _check_probes([(f"{workload} (pod template)", e.template.spec)])
        if failures:
            raise EnforcementPreconditionError(failures) from e
        raise


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


def _pod_specs(pods) -> list[tuple[str, object]]:
    """``(name, spec)`` of each pod, the input of :func:`_check_probes`."""
    return [(_pod_name(pod), pod.spec) for pod in pods]


def _check_probes(specs) -> list[str]:
    """#6: no app container (every container except ``authbridge-proxy``) has an ``httpGet`` probe.
    ``specs`` is ``(name, pod spec)`` pairs: the live pods, or the Deployment's pod template."""
    found = []
    for name, spec in specs:
        for c in spec.containers or []:
            if c.name == SIDECAR_CONTAINER:
                continue
            kinds = [kind for attr, kind in _PROBE_ATTRS if getattr(getattr(c, attr, None), "http_get", None)]
            if kinds:
                found.append(f"container {c.name!r} of pod {name!r} ({', '.join(kinds)})")
    if not found:
        return []
    return [f"#6 probes: httpGet probes on app containers: {'; '.join(found)} (use tcpSocket or exec probes)"]


def _required_inbound_plugins(service_type: ServiceType) -> list[str]:
    """The plugins #2 needs in the inbound pipeline. Every service needs ``jwt-validation``: it is the only
    plugin that validates the token and sets ``input.identity``. Without it, every rules-based package
    denies (D27). Every service needs ``opa``, and a tool also needs ``mcp-parser`` (the tool's inbound
    package checks ``input.mcp.params.name``)."""
    if service_type is ServiceType.AGENT:
        return ["jwt-validation", "opa"]
    return ["jwt-validation", "mcp-parser", "opa"]


def _on_error(entry: dict) -> str:
    """The ``on_error`` (cortex ErrorPolicy) of a plugin entry, with the default ``enforce``. An
    unquoted ``off`` is YAML 1.1 false for PyYAML, but cortex (yaml.v3) reads it as ``off``."""
    value = entry.get("on_error")
    if value is None or value == "":
        return "enforce"
    if value is False:
        return "off"
    return str(value)


def _inbound_plugin_policies(config) -> dict[str, str] | None:
    """The plugins of ``pipeline.inbound.plugins`` in ``config``, as name -> ``on_error``, or
    ``None`` if that list cannot be read. An entry is a map or a bare name (cortex reads a bare name
    as ``{name: <name>}``, so ``enforce``). If a name has more than one entry, an ``enforce`` one wins."""
    try:
        plugins = config["pipeline"]["inbound"]["plugins"] or []
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


def _check_pipeline(namespace: str, service_type: ServiceType) -> list[str]:
    """#2: the namespace pipeline (``authbridge-runtime-config``) has the required inbound plugins,
    each with an enforcing ``on_error``. One failure names every problem."""
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
    plugins = _required_inbound_plugins(service_type)
    problems = []
    policies = _inbound_plugin_policies(config)
    if policies is None:
        problems.append(f"no readable pipeline.inbound.plugins in {PIPELINE_CONFIG_KEY!r}")
    else:
        missing = [name for name in plugins if name not in policies]
        if missing:
            problems.append(
                f"the inbound pipeline has no {', '.join(repr(n) for n in missing)} plugin (needed for {kind})"
            )
        # `off` takes the plugin out of the running pipeline, and `observe` turns its Reject into a
        # pass-through: such an entry is there, but it does not enforce.
        problems += [
            f"the inbound plugin {name!r} has on_error={policies[name]!r}, so it does not enforce (needed for {kind})"
            for name in plugins
            if name in policies and policies[name] != "enforce"
        ]
    if not problems:
        return []
    return [f"#2 pipeline: {where}: " + "; ".join(problems)]
