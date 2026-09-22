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


def _pod(labels, owner_kind="ReplicaSet", owner_name="weather-abc123"):
    return SimpleNamespace(
        metadata=SimpleNamespace(
            labels=labels,
            owner_references=[SimpleNamespace(kind=owner_kind, name=owner_name)],
        )
    )


def _core(pods):
    core = MagicMock()
    core.list_namespaced_pod.return_value = SimpleNamespace(items=pods)
    return core


@pytest.fixture(autouse=True)
def _fast_label_wait(monkeypatch):
    # Keep the deploy->onboard label wait instant in unit tests: a single look, no sleep.
    # Tests that exercise the RETRY path override ONBOARD_LABEL_WAIT_ATTEMPTS themselves.
    monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "1")
    monkeypatch.setenv("ONBOARD_LABEL_WAIT_BACKOFF", "0")


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


class TestClassifyServiceLabelRace:
    """The operator applies ``rossoctl.io/type`` asynchronously, AFTER the Keycloak-registration
    event that triggers onboarding — so this node can run before the label is patched. A
    briefly-absent label is a transient race, re-polled a bounded number of times."""

    def _run_with_core(self, monkeypatch, *, attempts, list_side_effect=None, list_return=None):
        # monkeypatch.setattr (not a with-block) so the seams stay patched through the test body,
        # where classify_service is actually invoked.
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", str(attempts))
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_BACKOFF", "0")
        cfg = MagicMock()
        cfg.return_value.get_service.return_value = _service()
        monkeypatch.setattr(nodes, "_config", cfg)
        core = MagicMock()
        if list_side_effect is not None:
            core.list_namespaced_pod.side_effect = list_side_effect
        else:
            core.list_namespaced_pod.return_value = list_return
        monkeypatch.setattr(kube, "_core_v1", MagicMock(return_value=core))
        return core

    def test_label_applied_late_is_retried_then_succeeds(self, monkeypatch):
        core = self._run_with_core(
            monkeypatch,
            attempts=3,
            list_side_effect=[
                SimpleNamespace(items=[_pod({})]),  # operator has not patched the label yet
                SimpleNamespace(items=[_pod({"rossoctl.io/type": "agent"})]),  # now it has
            ],
        )
        result = nodes.classify_service(_state())
        assert result["service_type"] is ServiceType.AGENT
        assert core.list_namespaced_pod.call_count == 2  # re-polled once, then succeeded

    def test_invalid_label_fails_immediately_without_retry(self, monkeypatch):
        core = self._run_with_core(
            monkeypatch, attempts=5, list_return=SimpleNamespace(items=[_pod({"rossoctl.io/type": "sidecar"})])
        )
        with pytest.raises(HTTPException) as ei:
            nodes.classify_service(_state())
        assert ei.value.status_code == 502
        assert "invalid" in ei.value.detail
        assert core.list_namespaced_pod.call_count == 1  # a real misconfig is never re-polled

    def test_never_labelled_502s_after_exhausting_the_attempt_budget(self, monkeypatch):
        core = self._run_with_core(monkeypatch, attempts=3, list_return=SimpleNamespace(items=[_pod({})]))
        with pytest.raises(HTTPException) as ei:
            nodes.classify_service(_state())
        assert ei.value.status_code == 502
        assert "rossoctl.io/type" in ei.value.detail
        assert core.list_namespaced_pod.call_count == 3  # polled the full budget, then gave up

    def test_pod_vanishing_mid_poll_reports_no_pod_not_stale_label_missing(self, monkeypatch):
        # Attempt 1 sees an unlabelled pod (sets the 'label missing' detail); the pod is then deleted
        # for the remaining attempts. The exhausted-wait 502 must reflect the LAST-seen state ('no pod'),
        # not the stale 'label missing' from attempt 1.
        core = self._run_with_core(
            monkeypatch,
            attempts=3,
            list_side_effect=[
                SimpleNamespace(items=[_pod({})]),  # unlabelled pod -> 'label missing'
                SimpleNamespace(items=[]),  # pod gone
                SimpleNamespace(items=[]),  # still gone
            ],
        )
        with pytest.raises(HTTPException) as ei:
            nodes.classify_service(_state())
        assert ei.value.status_code == 502
        assert "no pod owned by workload" in ei.value.detail
        assert "label missing" not in ei.value.detail
        assert core.list_namespaced_pod.call_count == 3
