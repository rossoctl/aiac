"""Manifest-content tests: every AIAC workload in ``k8s/`` can have its log level set.

Each container (init containers included) must receive a ``LOG_LEVEL`` through a ConfigMap in its
``envFrom``, so an operator can change it with ``kubectl patch configmap`` + a restart (see
``k8s/aiac-deployment-guide.md``, "Changing log levels"). The Agent pod loads two ConfigMaps that
both carry the key; ``envFrom`` is last-source-wins, so both of its containers must resolve it
from ``aiac-agent-config``.

These tests parse the manifest YAML directly — they do not require (or talk to) Kubernetes.
"""

from pathlib import Path

import pytest
import yaml

_K8S = Path(__file__).resolve().parents[3] / "k8s"
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "Pod"}


def _docs() -> list[dict]:
    return [d for f in sorted(_K8S.glob("*.yaml")) for d in yaml.safe_load_all(f.read_text()) if d]


def _configmaps() -> dict[str, dict[str, str]]:
    return {d["metadata"]["name"]: d.get("data", {}) for d in _docs() if d["kind"] == "ConfigMap"}


def _containers() -> list[tuple[str, dict]]:
    """``(workload/container, container spec)`` for every container of every workload."""
    out = []
    for d in _docs():
        if d["kind"] not in _WORKLOAD_KINDS:
            continue
        pod = d["spec"] if d["kind"] == "Pod" else d["spec"]["template"]["spec"]
        for c in pod.get("initContainers", []) + pod.get("containers", []):
            out.append((f"{d['metadata']['name']}/{c['name']}", c))
    return out


def _log_level_source(container: dict) -> str | None:
    """Name of the ConfigMap that supplies the container's effective ``LOG_LEVEL`` (last wins)."""
    cms = _configmaps()
    source = None
    for ref in container.get("envFrom", []):
        name = ref.get("configMapRef", {}).get("name")
        if name and "LOG_LEVEL" in cms.get(name, {}):
            source = name
    return source


@pytest.mark.parametrize("label,container", _containers(), ids=[label for label, _ in _containers()])
def test_every_container_receives_log_level(label, container):
    assert _log_level_source(container) is not None, f"{label} gets no LOG_LEVEL from a ConfigMap"


def test_every_shipped_log_level_defaults_to_info():
    levels = {name: data["LOG_LEVEL"] for name, data in _configmaps().items() if "LOG_LEVEL" in data}
    assert levels, "no ConfigMap carries LOG_LEVEL"
    assert set(levels.values()) == {"INFO"}, levels


@pytest.mark.parametrize("container_name", ["aiac-init", "aiac-agent"])
def test_agent_pod_containers_resolve_log_level_from_agent_config(container_name):
    """aiac-pdp-config also carries LOG_LEVEL; aiac-agent-config must come after it and win."""
    container = dict(_containers())[f"aiac-agent/{container_name}"]
    assert _log_level_source(container) == "aiac-agent-config"
