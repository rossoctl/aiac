"""Fake Kubernetes objects for the UC1 precondition-check tests (D30).

The checks read the pods of the workload (``list_namespaced_pod``) and the namespace ConfigMap
``authbridge-runtime-config`` (``read_namespaced_config_map``) through the ``kube._core_v1`` seam.
These builders give objects with the attributes of the real ``kubernetes`` client models that the
checks read. By default they describe a service that passes every check: an ``authbridge-proxy``
sidecar (with its own ``httpGet`` probe, which #6 ignores), an app container with a ``tcpSocket``
probe, and an inbound pipeline with ``mcp-parser`` and ``opa``.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import yaml
from kubernetes.client.exceptions import ApiException

NAMESPACE = "team1"
WORKLOAD = "svc-1"
SERVICE_NAME = f"{NAMESPACE}/{WORKLOAD}"  # Keycloak client.name = "<namespace>/<workload>"
SIDECAR = "authbridge-proxy"
PIPELINE_CONFIGMAP = "authbridge-runtime-config"

_PROBE_KINDS = ("readiness", "liveness", "startup")


def http_get_probe():
    return SimpleNamespace(http_get=SimpleNamespace(path="/health", port=8080), tcp_socket=None)


def tcp_probe():
    return SimpleNamespace(http_get=None, tcp_socket=SimpleNamespace(port=8080))


def container(name: str, **probes):
    """A container. ``probes`` maps a probe kind (``readiness``/``liveness``/``startup``) to a probe;
    an absent kind has no probe."""
    return SimpleNamespace(name=name, **{f"{kind}_probe": probes.get(kind) for kind in _PROBE_KINDS})


def app_container(name: str = "app", **probes):
    return container(name, **(probes or {"readiness": tcp_probe(), "liveness": tcp_probe()}))


def sidecar_container():
    return container(SIDECAR, readiness=http_get_probe(), liveness=http_get_probe())


def pod(
    *,
    type_label: str | None = "agent",
    containers=None,
    name: str = f"{WORKLOAD}-abc123-xyz",
    owner_name: str = f"{WORKLOAD}-abc123",
    terminating: bool = False,
):
    """A pod owned by the workload's ReplicaSet. ``containers`` defaults to an app container plus
    the sidecar (a pod that passes #1 and #6)."""
    labels = {"rossoctl.io/type": type_label} if type_label is not None else {}
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=name,
            labels=labels,
            owner_references=[SimpleNamespace(kind="ReplicaSet", name=owner_name)],
            deletion_timestamp="2026-10-02T00:00:00Z" if terminating else None,
        ),
        spec=SimpleNamespace(
            containers=containers if containers is not None else [app_container(), sidecar_container()]
        ),
    )


def pipeline_configmap(inbound=("jwt-validation", "mcp-parser", "opa"), outbound=("token-exchange", "opa")):
    """The namespace ConfigMap ``authbridge-runtime-config``: ``config.yaml`` holds the pipeline."""
    config = {
        "pipeline": {
            "inbound": {"plugins": [{"name": n} for n in inbound]},
            "outbound": {"plugins": [{"name": n} for n in outbound]},
        }
    }
    return SimpleNamespace(data={"config.yaml": yaml.safe_dump(config)})


def not_found() -> ApiException:
    return ApiException(status=404, reason="Not Found")


def core_v1(pods=None, configmap=None):
    """A fake ``CoreV1Api``: ``pods`` (default: one passing agent pod) and ``configmap`` (default:
    a passing pipeline). Pass a list of pod lists as ``list_namespaced_pod.side_effect`` for a
    re-poll."""
    core = MagicMock()
    core.list_namespaced_pod.return_value = SimpleNamespace(items=pods if pods is not None else [pod()])
    core.read_namespaced_config_map.return_value = configmap if configmap is not None else pipeline_configmap()
    return core


def pod_list(*pods):
    return SimpleNamespace(items=list(pods))
