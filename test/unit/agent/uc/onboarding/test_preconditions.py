"""Unit tests for the UC1 enforcement precondition checks (D30, ``check_preconditions``).

The checks read Kubernetes through the ``kube._core_v1`` seam, faked here (see ``kube_fakes``). The
Orchestrator-level contract (the checks run first, before Provision and the PRB, with no rollback)
is in ``test_orchestrator.py``; this file covers what each check reads and when it fails.
"""

from unittest.mock import patch

import pytest
from fastapi import HTTPException
from kubernetes.client.exceptions import ApiException

from aiac.agent.uc.onboarding.preconditions import EnforcementPreconditionError, check_preconditions
from aiac.agent.uc.onboarding.provision import kube
from aiac.idp.configuration.models import Service, ServiceType
from test.unit.agent.uc.onboarding import kube_fakes as kf


@pytest.fixture(autouse=True)
def _one_look(monkeypatch):
    # One look, no sleep; the re-poll tests set more attempts themselves.
    monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "1")
    monkeypatch.setenv("ONBOARD_LABEL_WAIT_BACKOFF", "0")
    monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")


def _service(name=kf.SERVICE_NAME):
    return Service(id="svc-uuid", serviceId="spiffe://example.org/ns/team1/sa/svc-1", name=name, enabled=True)


def _check(core):
    with patch.object(kube, "_core_v1", return_value=core):
        return check_preconditions(_service())


def _failures(core) -> list[str]:
    with pytest.raises(EnforcementPreconditionError) as ei:
        _check(core)
    return ei.value.failures


class TestPassingService:
    @pytest.mark.parametrize(("label", "expected"), [("agent", ServiceType.AGENT), ("tool", ServiceType.TOOL)])
    def test_returns_the_type_from_the_pod_label(self, label, expected):
        assert _check(kf.core_v1(pods=[kf.pod(type_label=label)])) is expected

    def test_the_sidecar_may_have_its_own_http_get_probe(self):
        # #6 reads the app containers only: the sidecar's own probes go to the sidecar, not the proxy.
        assert _check(kf.core_v1(pods=[kf.pod(containers=[kf.app_container(), kf.sidecar_container()])]))

    def test_an_app_container_with_no_probe_passes(self):
        assert _check(kf.core_v1(pods=[kf.pod(containers=[kf.container("app"), kf.sidecar_container()])]))


class TestCheck1Sidecar:
    def test_a_pod_with_no_sidecar_fails(self):
        failures = _failures(kf.core_v1(pods=[kf.pod(containers=[kf.app_container()])]))
        assert len(failures) == 1
        assert failures[0].startswith("#1")
        assert kf.SIDECAR in failures[0]

    def test_every_live_pod_of_the_workload_is_checked(self):
        # Two replicas: one has no sidecar. Each live pod must enforce the CR.
        pods = [kf.pod(name="svc-1-a"), kf.pod(name="svc-1-b", containers=[kf.app_container()])]
        failures = _failures(kf.core_v1(pods=pods))
        assert [f[:2] for f in failures] == ["#1"]
        assert "svc-1-b" in failures[0] and "svc-1-a" not in failures[0]

    def test_a_terminating_pod_is_not_checked(self):
        # The old pod of a rollout (no sidecar) is terminating: only the new pod counts.
        pods = [kf.pod(name="old", containers=[kf.app_container()], terminating=True), kf.pod(name="new")]
        assert _check(kf.core_v1(pods=pods)) is ServiceType.AGENT

    def test_a_pod_of_another_workload_is_not_checked(self):
        other = kf.pod(name="other-x", owner_name="other-abc", containers=[kf.app_container()])
        assert _check(kf.core_v1(pods=[other, kf.pod()])) is ServiceType.AGENT


class TestCheck2Pipeline:
    def test_an_agent_needs_opa_in_the_inbound_pipeline(self):
        core = kf.core_v1(configmap=kf.pipeline_configmap(inbound=("jwt-validation", "mcp-parser")))
        failures = _failures(core)
        assert len(failures) == 1
        assert failures[0].startswith("#2") and "'opa'" in failures[0]

    def test_an_agent_does_not_need_mcp_parser(self):
        core = kf.core_v1(configmap=kf.pipeline_configmap(inbound=("jwt-validation", "opa")))
        assert _check(core) is ServiceType.AGENT

    def test_a_tool_also_needs_mcp_parser(self):
        core = kf.core_v1(
            pods=[kf.pod(type_label="tool")],
            configmap=kf.pipeline_configmap(inbound=("jwt-validation", "opa")),
        )
        failures = _failures(core)
        assert len(failures) == 1
        assert failures[0].startswith("#2") and "'mcp-parser'" in failures[0]

    def test_opa_in_the_outbound_pipeline_only_does_not_count(self):
        core = kf.core_v1(configmap=kf.pipeline_configmap(inbound=("jwt-validation",), outbound=("opa",)))
        assert _failures(core)[0].startswith("#2")

    def test_a_missing_configmap_fails(self):
        core = kf.core_v1()
        core.read_namespaced_config_map.side_effect = kf.not_found()
        failures = _failures(core)
        assert failures[0].startswith("#2") and "not found" in failures[0]
        core.read_namespaced_config_map.assert_called_once_with(kf.PIPELINE_CONFIGMAP, kf.NAMESPACE)

    @pytest.mark.parametrize("config_yaml", [None, "", "pipeline: [", "pipeline:\n  outbound: {}\n", "- a list"])
    def test_an_unreadable_pipeline_fails(self, config_yaml):
        configmap = kf.pipeline_configmap()
        configmap.data = {} if config_yaml is None else {"config.yaml": config_yaml}
        failures = _failures(kf.core_v1(configmap=configmap))
        assert [f[:2] for f in failures] == ["#2"]

    @pytest.mark.parametrize("status", [403, 500])
    def test_a_kubernetes_api_failure_is_a_502_not_a_failed_check(self, status):
        core = kf.core_v1()
        core.read_namespaced_config_map.side_effect = ApiException(status=status, reason="boom")
        with pytest.raises(HTTPException) as ei:
            _check(core)
        assert ei.value.status_code == 502


class TestCheck6Probes:
    @pytest.mark.parametrize("kind", ["readiness", "liveness", "startup"])
    def test_an_http_get_probe_on_an_app_container_fails(self, kind):
        app = kf.app_container(**{kind: kf.http_get_probe()})
        failures = _failures(kf.core_v1(pods=[kf.pod(containers=[app, kf.sidecar_container()])]))
        assert len(failures) == 1
        assert failures[0].startswith("#6") and kind in failures[0] and "'app'" in failures[0]

    def test_a_second_app_container_is_checked_too(self):
        containers = [
            kf.app_container(),
            kf.app_container("worker", startup=kf.http_get_probe()),
            kf.sidecar_container(),
        ]
        failures = _failures(kf.core_v1(pods=[kf.pod(containers=containers)]))
        assert [f[:2] for f in failures] == ["#6"]
        assert "'worker'" in failures[0] and "'app'" not in failures[0]


class TestThePodRace:
    """A pod or a label that is not there yet is a deploy->onboard race, not a failed check
    (the same bounded re-poll as ``classify_service``)."""

    def test_a_pod_that_comes_later_passes(self, monkeypatch):
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "3")
        core = kf.core_v1()
        core.list_namespaced_pod.side_effect = [
            kf.pod_list(),
            kf.pod_list(kf.pod(type_label=None)),
            kf.pod_list(kf.pod()),
        ]
        assert _check(core) is ServiceType.AGENT
        assert core.list_namespaced_pod.call_count == 3

    def test_no_pod_after_the_wait_is_a_502_not_a_failed_check(self, monkeypatch):
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "2")
        core = kf.core_v1(pods=[])
        with pytest.raises(HTTPException) as ei:
            _check(core)
        assert ei.value.status_code == 502
        assert kf.WORKLOAD in ei.value.detail
        core.read_namespaced_config_map.assert_not_called()

    def test_no_label_after_the_wait_is_a_502(self):
        with pytest.raises(HTTPException) as ei:
            _check(kf.core_v1(pods=[kf.pod(type_label=None)]))
        assert ei.value.status_code == 502
        assert "rossoctl.io/type" in ei.value.detail

    def test_an_invalid_label_is_a_502_at_once(self, monkeypatch):
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "5")
        core = kf.core_v1(pods=[kf.pod(type_label="sidecar")])
        with pytest.raises(HTTPException) as ei:
            _check(core)
        assert ei.value.status_code == 502
        assert core.list_namespaced_pod.call_count == 1

    def test_an_old_pod_with_no_sidecar_during_a_rollout_is_waited_for(self, monkeypatch):
        # The operator can roll the workload onto the injected template after the client
        # registration: the old pod (no sidecar) is still live at the first look.
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "2")
        old = kf.pod(name="old", containers=[kf.app_container()])
        core = kf.core_v1()
        core.list_namespaced_pod.side_effect = [kf.pod_list(old, kf.pod(name="new")), kf.pod_list(kf.pod(name="new"))]
        assert _check(core) is ServiceType.AGENT

    def test_a_pod_check_that_still_fails_after_the_wait_is_a_failed_check(self, monkeypatch):
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "2")
        core = kf.core_v1(pods=[kf.pod(containers=[kf.app_container()])])
        assert [f[:2] for f in _failures(core)] == ["#1"]
        assert core.list_namespaced_pod.call_count == 2

    def test_a_pod_list_failure_is_a_502(self):
        core = kf.core_v1()
        core.list_namespaced_pod.side_effect = ApiException(status=500, reason="boom")
        with pytest.raises(HTTPException) as ei:
            _check(core)
        assert ei.value.status_code == 502

    def test_a_client_name_with_no_slash_is_a_502(self):
        with patch.object(kube, "_core_v1", return_value=kf.core_v1()) as core_v1:
            with pytest.raises(HTTPException) as ei:
                check_preconditions(_service(name="no-slash"))
        assert ei.value.status_code == 502
        core_v1.assert_not_called()
