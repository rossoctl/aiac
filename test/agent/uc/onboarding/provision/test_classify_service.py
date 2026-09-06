"""Unit tests for the Service Provision `classify_service` node (UC1, issue 4.3).

The idp-library `Configuration` (via the `_config` seam) and the Kubernetes API (via the
`_core_v1` seam) are mocked — no live services. All provision nodes are non-LLM.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from aiac.agent.uc.onboarding.provision import kube, nodes
from aiac.agent.uc.onboarding.provision.state import OnboardingProvisionState, Trigger
from aiac.idp.configuration.models import Service, ServiceType

ENTITY = "svc-123"


def _state():
    return OnboardingProvisionState(trigger=Trigger(entity_id=ENTITY))


def _service(name="team-a/weather"):
    return Service.model_validate({"id": ENTITY, "clientId": ENTITY, "name": name, "enabled": True})


def _pod(
    labels,
    owner_kind="ReplicaSet",
    owner_name="weather-abc123",
    deletion_timestamp=None,
    creation_timestamp="",
):
    return SimpleNamespace(
        metadata=SimpleNamespace(
            labels=labels,
            owner_references=[SimpleNamespace(kind=owner_kind, name=owner_name)],
            deletion_timestamp=deletion_timestamp,
            creation_timestamp=creation_timestamp,
        )
    )


def _core(pods):
    core = MagicMock()
    core.list_namespaced_pod.return_value = SimpleNamespace(items=pods)
    return core


def _run(service=None, pods=None, get_service_exc=None, list_pods_exc=None):
    with patch.object(nodes, "_config") as cfg, patch.object(kube, "_core_v1") as core_v1:
        if get_service_exc is not None:
            cfg.return_value.get_service.side_effect = get_service_exc
        else:
            cfg.return_value.get_service.return_value = service
        core = _core(pods or [])
        if list_pods_exc is not None:
            core.list_namespaced_pod.side_effect = list_pods_exc
        core_v1.return_value = core
        return nodes.classify_service(_state())


class TestClassifyServiceHappyPaths:
    def test_agent_label_routes_to_agent_and_sets_identity(self):
        result = _run(service=_service(), pods=[_pod({"rossoctl.io/type": "agent"})])
        assert result["service_id"] == ENTITY
        assert result["namespace"] == "team-a"
        assert result["workload_name"] == "weather"
        assert result["service_type"] is ServiceType.AGENT

    def test_tool_label_routes_to_tool(self):
        result = _run(service=_service(), pods=[_pod({"rossoctl.io/type": "tool"})])
        assert result["service_type"] is ServiceType.TOOL
        assert result["namespace"] == "team-a"
        assert result["workload_name"] == "weather"

    def test_service_id_stored_from_trigger_entity_id(self):
        result = _run(service=_service(), pods=[_pod({"rossoctl.io/type": "agent"})])
        assert result["service_id"] == ENTITY

    def test_statefulset_owner_matched_by_exact_name(self):
        pod = _pod({"rossoctl.io/type": "tool"}, owner_kind="StatefulSet", owner_name="weather")
        result = _run(service=_service(), pods=[pod])
        assert result["service_type"] is ServiceType.TOOL

    def test_stale_terminating_pod_from_prior_replicaset_is_skipped(self):
        # A rollout can leave an old ReplicaSet's pod (no rossoctl.io/type label yet, mid-
        # deletion) listed ahead of the fresh one the operator just labeled — API list order
        # is not creation order. The live, labeled pod must win regardless of list position.
        stale = _pod(
            {},
            owner_name="weather-oldrs",
            deletion_timestamp="2026-01-01T00:00:00Z",
            creation_timestamp="2026-01-01T00:00:00Z",
        )
        fresh = _pod(
            {"rossoctl.io/type": "agent"},
            owner_name="weather-newrs",
            creation_timestamp="2026-01-02T00:00:00Z",
        )
        result = _run(service=_service(), pods=[stale, fresh])
        assert result["service_type"] is ServiceType.AGENT

    def test_newest_live_pod_wins_when_none_carry_the_label_yet(self):
        # Neither candidate has the label yet (label not stamped), but both are live — the
        # newest one should be picked rather than an arbitrary/first one, so the 502's "got
        # None" reflects the current rollout, not a pod already on its way out.
        older = _pod(
            {}, owner_name="weather-oldrs", creation_timestamp="2026-01-01T00:00:00Z"
        )
        newer = _pod(
            {}, owner_name="weather-newrs", creation_timestamp="2026-01-02T00:00:00Z"
        )
        with pytest.raises(HTTPException) as ei:
            _run(service=_service(), pods=[older, newer])
        assert ei.value.status_code == 502


class TestClassifyService502s:
    def test_label_absent_is_502_naming_workload_and_label(self):
        with pytest.raises(HTTPException) as ei:
            _run(service=_service(), pods=[_pod({})])
        assert ei.value.status_code == 502
        assert "weather" in ei.value.detail
        assert "rossoctl.io/type" in ei.value.detail

    def test_label_unknown_value_is_502(self):
        with pytest.raises(HTTPException) as ei:
            _run(service=_service(), pods=[_pod({"rossoctl.io/type": "sidecar"})])
        assert ei.value.status_code == 502

    def test_client_name_without_slash_is_502(self):
        with pytest.raises(HTTPException) as ei:
            _run(service=_service(name="no-slash-name"), pods=[_pod({"rossoctl.io/type": "agent"})])
        assert ei.value.status_code == 502

    def test_config_api_down_is_502(self, monkeypatch):
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")
        with pytest.raises(HTTPException) as ei:
            _run(get_service_exc=RuntimeError("HTTP 503"), pods=[])
        assert ei.value.status_code == 502

    def test_k8s_pod_list_failure_is_502(self, monkeypatch):
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")
        with pytest.raises(HTTPException) as ei:
            _run(service=_service(), list_pods_exc=RuntimeError("boom"))
        assert ei.value.status_code == 502

    def test_no_pod_owned_by_workload_is_502(self):
        unrelated = _pod({"rossoctl.io/type": "agent"}, owner_name="other-xyz")
        with pytest.raises(HTTPException) as ei:
            _run(service=_service(), pods=[unrelated])
        assert ei.value.status_code == 502
        assert "weather" in ei.value.detail
