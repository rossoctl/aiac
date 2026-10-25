"""Unit tests for the UC1 enforcement precondition checks (D30, ``check_preconditions``).

The checks read Kubernetes through the ``kube._apps_v1`` and ``kube._core_v1`` seams, faked here (see
``kube_fakes``). The
Orchestrator-level contract (the checks run first, before Provision and the PRB, with no rollback)
is in ``test_orchestrator.py``; this file covers what each check reads and when it fails.
"""

from unittest.mock import patch

import pytest
from fastapi import HTTPException
from kubernetes.client.exceptions import ApiException

from aiac.agent.uc.onboarding.preconditions import EnforcementPreconditionError, check_preconditions
from aiac.agent.uc.onboarding.provision import kube
from aiac.agent.uc.onboarding.provision.nodes import WorkloadNotReadyError
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


def _check(core, apps=None):
    """Run the checks on ``core`` (pods, ConfigMap) and ``apps`` (the Deployment; default: a complete
    rollout)."""
    with (
        patch.object(kube, "_core_v1", return_value=core),
        patch.object(kube, "_apps_v1", return_value=apps if apps is not None else kf.apps_v1()),
    ):
        return check_preconditions(_service())


def _failures(core, apps=None) -> list[str]:
    with pytest.raises(EnforcementPreconditionError) as ei:
        _check(core, apps)
    return ei.value.failures


def _raw_pipeline(inbound_entries: str):
    """A pipeline ConfigMap whose inbound plugin list is the YAML flow text ``inbound_entries`` (so a
    test can write YAML 1.1 values such as an unquoted ``off``), with an empty outbound list."""
    configmap = kf.pipeline_configmap()
    configmap.data = {
        "config.yaml": f"pipeline:\n  inbound:\n    plugins: [{inbound_entries}]\n  outbound:\n    plugins: []\n"
    }
    return configmap


# (pod type label, a passing inbound plugin list) for each service type.
_ON_ERROR_CASES = [
    ("agent", ("jwt-validation", "opa")),
    ("tool", ("jwt-validation", "mcp-parser", "opa")),
]


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

    @pytest.mark.parametrize(
        ("label", "inbound", "kind"),
        [
            ("agent", ("opa",), "an agent"),
            ("tool", ("mcp-parser", "opa"), "a tool"),
        ],
    )
    def test_every_service_needs_jwt_validation_in_the_inbound_pipeline(self, label, inbound, kind):
        # jwt-validation is the only plugin that validates the token and sets input.identity: without it
        # every rules-based package denies (D27).
        core = kf.core_v1(
            pods=[kf.pod(type_label=label)],
            configmap=kf.pipeline_configmap(inbound=inbound),
        )
        failures = _failures(core)
        assert len(failures) == 1
        assert failures[0].startswith("#2") and "'jwt-validation'" in failures[0]
        assert f"needed for {kind}" in failures[0]

    def test_the_outbound_pipeline_is_not_checked(self):
        # Every outbound is a pass-through (D24): the callee decides.
        core = kf.core_v1(configmap=kf.pipeline_configmap(outbound=("token-exchange",)))
        assert _check(core) is ServiceType.AGENT

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

    # The on_error of an entry (cortex ErrorPolicy): `off` takes the plugin out of the running
    # pipeline, and `observe` turns its Reject into a pass-through. Unquoted `off` is YAML 1.1 false.
    @pytest.mark.parametrize("on_error", ["'off'", "off", "observe"])
    @pytest.mark.parametrize(("label", "inbound"), _ON_ERROR_CASES)
    def test_a_required_plugin_that_does_not_enforce_fails(self, on_error, label, inbound):
        entries = ", ".join(
            f"{{name: {n}, on_error: {on_error}}}" if n == "jwt-validation" else f"{{name: {n}}}" for n in inbound
        )
        core = kf.core_v1(pods=[kf.pod(type_label=label)], configmap=_raw_pipeline(entries))
        failures = _failures(core)
        assert len(failures) == 1
        assert failures[0].startswith("#2")
        assert "'jwt-validation' has on_error=" in failures[0] and "so it does not enforce" in failures[0]
        assert "has no" not in failures[0]

    def test_opa_that_does_not_enforce_fails_too(self):
        core = kf.core_v1(configmap=_raw_pipeline("{name: jwt-validation}, {name: opa, on_error: observe}"))
        failures = _failures(core)
        assert len(failures) == 1
        assert "'opa' has on_error='observe', so it does not enforce" in failures[0]

    @pytest.mark.parametrize("entry", ["{name: jwt-validation, on_error: enforce}", "jwt-validation"], ids=str)
    def test_an_enforcing_entry_and_the_bare_name_form_pass(self, entry):
        # cortex accepts a bare plugin name as an entry with the default policy (enforce).
        core = kf.core_v1(configmap=_raw_pipeline(f"{entry}, {{name: opa}}"))
        assert _check(core) is ServiceType.AGENT

    @pytest.mark.parametrize("status", [403, 500])
    def test_a_kubernetes_api_failure_is_a_502_not_a_failed_check(self, status):
        core = kf.core_v1()
        core.read_namespaced_config_map.side_effect = ApiException(status=status, reason="boom")
        with pytest.raises(HTTPException) as ei:
            _check(core)
        assert type(ei.value) is HTTPException  # a real failure, not the nak'd not-ready class
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

    def test_no_pod_after_the_wait_is_not_ready_not_a_failed_check(self, monkeypatch):
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "2")
        core = kf.core_v1(pods=[])
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(core)
        assert ei.value.status_code == 502
        assert kf.WORKLOAD in ei.value.detail
        assert ei.value.template is None
        core.read_namespaced_config_map.assert_not_called()

    def test_no_label_after_the_wait_is_not_ready(self):
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(kf.core_v1(pods=[kf.pod(type_label=None)]))
        assert ei.value.status_code == 502
        assert "rossoctl.io/type" in ei.value.detail

    def test_an_invalid_label_is_a_502_at_once(self, monkeypatch):
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "5")
        core = kf.core_v1(pods=[kf.pod(type_label="sidecar")])
        with pytest.raises(HTTPException) as ei:
            _check(core)
        assert type(ei.value) is HTTPException  # a misconfiguration: not nak'd, unlike WorkloadNotReadyError
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
        assert type(ei.value) is HTTPException
        assert ei.value.status_code == 502

    def test_a_client_name_with_no_slash_is_a_502(self):
        with (
            patch.object(kube, "_core_v1", return_value=kf.core_v1()) as core_v1,
            patch.object(kube, "_apps_v1", return_value=kf.apps_v1()) as apps_v1,
        ):
            with pytest.raises(HTTPException) as ei:
                check_preconditions(_service(name="no-slash"))
        assert ei.value.status_code == 502
        core_v1.assert_not_called()
        apps_v1.assert_not_called()


class TestTheRollout:
    """The operator rolls the Deployment more than once after a deploy, and the onboarding event comes
    before the last rollout: the pods are checked only when the rollout is complete."""

    def test_the_checks_run_on_the_final_pods_after_the_rollout(self, monkeypatch):
        # Look 1: the rollout is in progress (the old pod with no sidecar is still live), so the pods
        # are not read. Look 2: the rollout is complete, and only the final pod is left.
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "3")
        apps = kf.apps_v1()
        apps.read_namespaced_deployment.side_effect = [kf.rolling_out(), kf.deployment()]
        core = kf.core_v1(pods=[kf.pod(name="new")])
        assert _check(core, apps) is ServiceType.AGENT
        assert apps.read_namespaced_deployment.call_count == 2
        assert core.list_namespaced_pod.call_count == 1

    @pytest.mark.parametrize(
        "dep",
        [
            kf.rolling_out(),  # an old pod is left (replicas > updatedReplicas)
            kf.deployment(updated_replicas=None, available_replicas=None),  # no new pod yet
            kf.deployment(available_replicas=None),  # the new pod is not available yet
            kf.deployment(generation=3, observed_generation=2),  # the controller has not seen the change
            kf.deployment(
                observed_generation=None, status_replicas=None, updated_replicas=None, available_replicas=None
            ),
        ],
        ids=["old-pod-left", "not-updated", "not-available", "generation-not-observed", "no-status"],
    )
    def test_a_rollout_that_is_not_complete_is_not_ready(self, dep):
        core = kf.core_v1()
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(core, kf.apps_v1(dep))
        assert ei.value.status_code == 502
        assert "rollout" in ei.value.detail and kf.WORKLOAD in ei.value.detail
        assert "updatedReplicas" in ei.value.detail and "observedGeneration" in ei.value.detail
        core.list_namespaced_pod.assert_not_called()
        core.read_namespaced_config_map.assert_not_called()

    @pytest.mark.parametrize(
        "dep, want",
        [
            (
                kf.rolling_out(
                    conditions=[kf.condition("Progressing", "False", "ProgressDeadlineExceeded", "timed out")]
                ),
                "Progressing=False (ProgressDeadlineExceeded): timed out",
            ),
            (kf.rolling_out(paused=True), "paused"),
        ],
        ids=["progress-deadline-exceeded", "paused"],
    )
    def test_a_rollout_that_waits_for_a_person_is_not_ready_and_says_why(self, dep, want):
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(kf.core_v1(), kf.apps_v1(dep))
        assert want in ei.value.detail

    def test_a_deployment_scaled_to_zero_is_not_ready_and_says_why(self):
        dep = kf.deployment(replicas=0, status_replicas=None, updated_replicas=None, available_replicas=None)
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(kf.core_v1(pods=[]), kf.apps_v1(dep))
        assert "spec.replicas 0" in ei.value.detail

    def test_an_old_pod_with_no_sidecar_at_the_end_of_the_wait_is_not_a_failed_check(self, monkeypatch):
        # W2: the budget ends during the rollout, with a labelled new pod and a live old pod that has no
        # sidecar. That pod is about to be replaced: not ready (nak'd), not a permanent #1.
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "2")
        old = kf.pod(
            name="svc-1-78cf9dffd5-a", owner_name="svc-1-78cf9dffd5", type_label=None, containers=[kf.app_container()]
        )
        new = kf.pod(name="svc-1-7565d64dcc-b", owner_name="svc-1-7565d64dcc")
        with pytest.raises(WorkloadNotReadyError):
            _check(kf.core_v1(pods=[new, old]), kf.apps_v1(kf.rolling_out()))

    @pytest.mark.parametrize("kind", ["readiness", "startup"])
    def test_a_rollout_that_is_not_complete_with_an_http_get_probe_is_a_failed_check(self, kind):
        # An httpGet probe goes through the sidecar, which denies it, so the pod never becomes Ready and
        # the rollout never completes. The webhook does not change probes: #6 runs on the pod template.
        app = kf.app_container(**{kind: kf.http_get_probe()})
        dep = kf.rolling_out(containers=[app, kf.sidecar_container()])
        failures = _failures(kf.core_v1(), kf.apps_v1(dep))
        assert len(failures) == 1
        assert failures[0].startswith("#6") and kind in failures[0] and "pod template" in failures[0]

    def test_a_complete_rollout_with_no_sidecar_is_a_failed_check(self):
        failures = _failures(kf.core_v1(pods=[kf.pod(containers=[kf.app_container()])]), kf.apps_v1())
        assert [f[:2] for f in failures] == ["#1"]

    def test_a_complete_rollout_with_no_pod_is_not_ready(self):
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(kf.core_v1(pods=[]), kf.apps_v1())
        assert "no pod owned by workload" in ei.value.detail
        assert ei.value.template is None

    def test_no_deployment_uses_the_pod_list(self):
        # A StatefulSet or a Sandbox has no Deployment of the workload's name: the pod list decides.
        apps = kf.apps_v1()
        apps.read_namespaced_deployment.side_effect = kf.not_found()
        assert _check(kf.core_v1(), apps) is ServiceType.AGENT

    def test_no_deployment_and_no_pod_is_not_ready(self):
        apps = kf.apps_v1()
        apps.read_namespaced_deployment.side_effect = kf.not_found()
        with pytest.raises(WorkloadNotReadyError) as ei:
            _check(kf.core_v1(pods=[]), apps)
        assert "no pod owned by workload" in ei.value.detail

    @pytest.mark.parametrize("status", [403, 500])
    def test_a_deployment_read_failure_is_a_502_at_once(self, monkeypatch, status):
        # A 403 is a missing RBAC rule (k8s/agent-deployment.yaml), not a race: not nak'd.
        monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "5")
        apps = kf.apps_v1()
        apps.read_namespaced_deployment.side_effect = ApiException(status=status, reason="boom")
        core = kf.core_v1()
        with pytest.raises(HTTPException) as ei:
            _check(core, apps)
        assert type(ei.value) is HTTPException
        assert ei.value.status_code == 502
        assert "Deployment GET failed" in ei.value.detail
        assert apps.read_namespaced_deployment.call_count == 1
        core.list_namespaced_pod.assert_not_called()


class TestScope:
    """#1, #2 and #6 run for every service, agent or tool (D30)."""

    @pytest.mark.parametrize("label", ["agent", "tool"])
    @pytest.mark.parametrize("check", ["#1", "#6"])
    def test_every_service_gets_the_pod_checks(self, check, label):
        containers = (
            [kf.app_container()]
            if check == "#1"
            else [kf.app_container(liveness=kf.http_get_probe()), kf.sidecar_container()]
        )
        pods = [kf.pod(type_label=label, containers=containers)]
        assert [f[:2] for f in _failures(kf.core_v1(pods=pods))] == [check]
