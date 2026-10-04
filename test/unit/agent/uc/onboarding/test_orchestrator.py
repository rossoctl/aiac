"""Unit tests for the Service Onboarding Orchestrator (UC1, issues 4.5 + 171).

The Orchestrator is a plain function that sequences exactly two stages:
Service Provision (a compiled StateGraph) -> Service Policy Builder. Both are mocked
here via the module-level `build_provision_graph` / `ServicePolicyBuilder` seams, and the
idp-library `Configuration` is mocked via the `_config` seam -- no live graph, IdP,
Kubernetes, or LLM. The Orchestrator applies nothing (no PCE call); it returns
`(list[PolicyRule], override=False)` to the Controller, which makes the
single `compute_and_apply` call afterwards.

Issue 171 adds a compensating rollback (UC1-only): on any of the four typed build
failures the Orchestrator tears down exactly what Provision *created this run* (the
created-manifest) and disables the client (failed-service marker). The client type is
kept (handoff 11 B2). Then it calls the PCE's ``quarantine`` (the policy teardown) and
re-raises. The caller re-enables the client after a successful apply (idempotent).

Handoff 12 (D30, checkpoint B1) adds the enforcement precondition checks, which run first (before
Provision and the PRB), and the bootstrap CR of a tool, which the PCE writes after the checks and
before Provision. The checks read Kubernetes through the ``kube._core_v1`` seam, which is faked here
for every test (by default a service that passes every check); the PCE ``bootstrap`` is patched at
its import site.
"""

import ast
import inspect
import threading
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from aiac.agent.policy_rules_builder.conflict_detection import PolicyConflictError
from aiac.agent.policy_rules_builder.diagnostic_models import ConflictReport
from aiac.agent.policy_rules_builder.graph import (
    LLMAccessError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
)
from aiac.agent.uc.onboarding import orchestrator
from aiac.agent.uc.onboarding.preconditions import EnforcementPreconditionError
from aiac.agent.uc.onboarding.provision import kube
from aiac.idp.configuration.models import Role, Scope, Service, ServiceType
from test.unit.agent.uc.onboarding import kube_fakes as kf

# The onboarding trigger carries the Keycloak UUID; the PCE takes the clientId. The two differ, so a
# test fails if the UUID leaks to the PCE.
SERVICE_ID = "svc-1"
CLIENT_ID = "spiffe://example.org/ns/team1/sa/svc-1"


@pytest.fixture(autouse=True)
def quarantine():
    """The PCE ``quarantine`` seam — patched for every test, so the failure path never reaches a
    live PCE. Tests that check it request this fixture by name."""
    with patch.object(orchestrator, "quarantine") as mock:
        yield mock


@pytest.fixture(autouse=True)
def bootstrap():
    """The PCE ``bootstrap`` seam (the first CR of a tool, checkpoint B1) — patched for every test.
    Tests that check it request this fixture by name."""
    with patch.object(orchestrator, "bootstrap") as mock:
        yield mock


@pytest.fixture(autouse=True)
def k8s(monkeypatch):
    """The Kubernetes seam of the precondition checks (D30): by default one agent pod and a pipeline
    that pass every check. Tests that change the cluster request this fixture by name. The
    deploy->onboard re-poll is one look with no sleep, unless a test sets it. The enforcement side
    is unset (target side), unless a test sets it."""
    monkeypatch.setenv("ONBOARD_LABEL_WAIT_ATTEMPTS", "1")
    monkeypatch.setenv("ONBOARD_LABEL_WAIT_BACKOFF", "0")
    monkeypatch.delenv("AIAC_ENFORCEMENT_SIDE", raising=False)
    core = kf.core_v1()
    with patch.object(kube, "_core_v1", return_value=core):
        yield core


def _graph(*, created_roles=(), created_scopes=(), service_type=ServiceType.AGENT):
    """A mocked Service Provision graph whose invoke() returns the final state dict,
    including the created-manifest (`created_roles` / `created_scopes`)."""
    graph = MagicMock()
    graph.invoke.return_value = {
        "service_type": service_type,
        "created_roles": list(created_roles),
        "created_scopes": list(created_scopes),
    }
    return graph


def _service(*, enabled=True):
    """The onboarded service as the IdP returns it: UUID ``SERVICE_ID``, clientId ``CLIENT_ID``, and
    ``client.name`` = ``<namespace>/<workload>`` (the checks find the pod from it)."""
    return Service(id=SERVICE_ID, serviceId=CLIENT_ID, name=kf.SERVICE_NAME, enabled=enabled)


def _config_returning(service):
    """A mocked Configuration whose get_service() yields `service`."""
    config = MagicMock()
    config.get_service.return_value = service
    return config


def _rollback_errors():
    """The four typed build failures that trigger the UC1 compensating rollback.

    Instances (not classes): PolicyConflictError needs a ConflictReport, so all four are
    built here and passed as `build` side effects. `from_survey([], [], 0)` is the minimal
    valid report (see test_error_logging.py)."""
    return [
        PolicyConflictError(ConflictReport.from_survey([], [], evaluated_count=0)),
        PolicyRulesBuilderError("auditor rejected after retries"),
        LLMAccessError("LLM endpoint unreachable"),
        UnparseableLLMResponseError("schema validation failed"),
    ]


class TestBothStagesSucceed:
    def test_provision_result_fed_to_builder_and_rules_returned_with_override_false(self):
        # The Orchestrator treats the rule list as opaque -- the builder (mocked) owns
        # PolicyRule construction, so a sentinel list is enough to prove pass-through.
        rules = [object()]
        graph = _graph(service_type=ServiceType.AGENT)

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.return_value = rules
            result = orchestrator.onboard_service(SERVICE_ID)

        # service_type produced by Provision is fed into the Service Policy Builder
        spb.build.assert_called_once_with(SERVICE_ID, ServiceType.AGENT)
        # Orchestrator returns the builder's rules, the append flag, and the service's clientId (the
        # PCE focus service). There is no default effect to forward: the deployed Rego always denies
        # an unmentioned pair.
        assert result == (rules, False, CLIENT_ID)

    def test_onboard_service_takes_no_default_effect(self):
        import inspect

        assert "default_effect" not in inspect.signature(orchestrator.onboard_service).parameters

    def test_provision_graph_invoked_with_service_id_in_trigger(self):
        # The service_id must reach Provision as the trigger's entity_id (Keycloak
        # client_id) -- otherwise Provision classifies the wrong service. The other
        # tests never inspect the graph's argument, so this guards that wiring.
        graph = _graph(service_type=ServiceType.AGENT)

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.return_value = [object()]
            orchestrator.onboard_service(SERVICE_ID)

        (state,), _ = graph.invoke.call_args
        assert state.trigger.entity_id == SERVICE_ID


class TestProvisionFails:
    def test_builder_not_called_and_provision_error_propagates(self):
        graph = MagicMock()
        graph.invoke.side_effect = HTTPException(502, "IdP config unavailable")

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            with pytest.raises(HTTPException) as exc:
                orchestrator.onboard_service(SERVICE_ID)

        assert exc.value.status_code == 502
        spb.build.assert_not_called()


class TestServiceReadFails:
    def test_nothing_is_provisioned_or_quarantined_when_the_service_read_fails(self, quarantine):
        # The clientId is resolved before Provision, so a failed IdP read happens before anything
        # exists that needs compensation: no Provision, no build, no rollback, no quarantine.
        # A raw IdP error (the Configuration library raises RuntimeError) becomes the same
        # HTTPException(502) that Provision raises, not a generic 500.
        config = MagicMock()
        config.get_service.side_effect = RuntimeError("IdP config unavailable")
        graph = _graph()

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            with pytest.raises(HTTPException) as exc:
                orchestrator.onboard_service(SERVICE_ID)

        assert exc.value.status_code == 502
        graph.invoke.assert_not_called()
        spb.build.assert_not_called()
        config.set_service_enabled.assert_not_called()
        quarantine.assert_not_called()
        assert SERVICE_ID not in orchestrator._service_locks


class TestSuccessDoesNotReEnableClient:
    def test_success_does_not_touch_enabled_and_does_not_tear_down(self):
        # On a successful onboarding the Orchestrator no longer re-enables the client itself —
        # the caller does that via reenable_service(), but only AFTER compute_and_apply succeeds
        # (so a PCE failure leaves the client disabled). onboard_service tears nothing down and
        # never sets enabled here.
        service = _service()
        config = _config_returning(service)
        graph = _graph(
            created_roles=[Role(id="r1", name="weather.forecast", composite=False)],
            created_scopes=[Scope(id="s1", name="weather.history")],
        )

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.return_value = [object()]
            orchestrator.onboard_service(SERVICE_ID)

        config.set_service_enabled.assert_not_called()
        config.delete_service_role.assert_not_called()
        config.delete_service_scope.assert_not_called()


class TestReenableService:
    def test_reenable_sets_enabled_true_and_touches_nothing_else(self):
        # reenable_service is the UC1-only, idempotent post-apply hook the caller runs after a
        # successful compute_and_apply. It resolves the service and sets enabled=true — nothing else.
        service = _service()
        config = _config_returning(service)

        with patch.object(orchestrator, "_config", return_value=config):
            orchestrator.reenable_service(SERVICE_ID)

        config.get_service.assert_called_once_with(SERVICE_ID)
        config.set_service_enabled.assert_called_once_with(service, True)
        config.delete_service_role.assert_not_called()
        config.delete_service_scope.assert_not_called()


class TestRollbackOnBuildFailure:
    @pytest.mark.parametrize("service_type", [ServiceType.AGENT, ServiceType.TOOL])
    @pytest.mark.parametrize("error", _rollback_errors(), ids=lambda e: type(e).__name__)
    def test_rollback_then_quarantine_then_reraise(self, error, service_type, quarantine):
        role = Role(id="r1", name="weather.forecast", composite=False)
        scope = Scope(id="s1", name="weather.history")
        service = _service()
        config = _config_returning(service)
        graph = _graph(created_roles=[role], created_scopes=[scope], service_type=service_type)
        order = MagicMock()
        order.attach_mock(config, "config")
        order.attach_mock(quarantine, "quarantine")

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = error
            with pytest.raises(type(error)) as ei:
                orchestrator.onboard_service(SERVICE_ID)

        # The ORIGINAL error instance is re-raised, not swallowed or re-wrapped.
        assert ei.value is error
        # Teardown of exactly what this run created (unmap-then-delete is done inside the
        # Configuration primitives), then disable (failed-service marker), then the PCE quarantine
        # keyed by the clientId. The Service is read from the IdP once, by its UUID.
        config.get_service.assert_called_once_with(SERVICE_ID)
        config.delete_service_role.assert_called_once_with(service, role)
        config.delete_service_scope.assert_called_once_with(service, scope)
        config.set_service_enabled.assert_called_once_with(service, False)
        # The created roles go to the quarantine: the rollback deleted them from the IdP, so the
        # quarantine cannot find them in the catalog, but their grants can be on other SPMs.
        quarantine.assert_called_once_with(CLIENT_ID, [role])
        calls = [c[0] for c in order.method_calls if c[0] != "config.get_service"]
        assert calls == [
            "config.delete_service_role",
            "config.delete_service_scope",
            "config.set_service_enabled",
            "quarantine",
        ]

    def test_disable_is_the_last_rollback_action(self):
        # The failed-service marker (enabled=false) must land AFTER the teardown, so a
        # crash mid-teardown never leaves a disabled-but-still-provisioned client. It lands
        # BEFORE the quarantine (asserted above), so no run after the teardown sees the service
        # as enabled.
        role = Role(id="r1", name="weather.forecast", composite=False)
        scope = Scope(id="s1", name="weather.history")
        service = _service()
        config = _config_returning(service)
        graph = _graph(created_roles=[role], created_scopes=[scope])

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = LLMAccessError("boom")
            with pytest.raises(LLMAccessError):
                orchestrator.onboard_service(SERVICE_ID)

        names = [c[0] for c in config.method_calls]
        assert names.index("set_service_enabled") > names.index("delete_service_role")
        assert names.index("set_service_enabled") > names.index("delete_service_scope")

    def test_quarantine_failure_propagates_after_the_rollback(self, quarantine):
        # A failed quarantine (e.g. the PDP is down) surfaces loudly — it is not swallowed. The
        # rollback already ran, so the client is disabled. The quarantine error replaces even a
        # permanent build error, so the consumer retries (and quarantines again) instead of
        # term()ing a fail-open service; the build error stays on __context__.
        service = _service()
        config = _config_returning(service)
        quarantine.side_effect = RuntimeError("PDP unreachable")
        build_error = PolicyRulesBuilderError("auditor rejected after retries")

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = build_error
            with pytest.raises(RuntimeError, match="PDP unreachable") as ei:
                orchestrator.onboard_service(SERVICE_ID)

        config.set_service_enabled.assert_called_once_with(service, False)
        assert ei.value.__context__ is build_error

    def test_rollback_failure_still_quarantines(self, quarantine):
        # A failed rollback (e.g. Keycloak is down) must not skip the quarantine: else a failed
        # first onboarding stays fail-open. The rollback error propagates (a retryable error), and
        # the build error stays on its __context__.
        config = _config_returning(_service())
        config.delete_service_role.side_effect = RuntimeError("Keycloak unreachable")
        build_error = PolicyRulesBuilderError("auditor rejected after retries")
        created_role = Role(id="r1", name="weather.forecast", composite=False)
        graph = _graph(created_roles=[created_role])

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = build_error
            with pytest.raises(RuntimeError, match="Keycloak unreachable") as ei:
                orchestrator.onboard_service(SERVICE_ID)

        quarantine.assert_called_once_with(CLIENT_ID, [created_role])
        assert ei.value.__context__ is build_error


class TestRollbackLogInjectionSanitized:
    def test_crlf_in_service_id_and_names_cannot_forge_log_lines(self, caplog):
        # service_id reaches the Orchestrator from the request / NATS trigger (user-controlled).
        # A crafted id or entity name carrying CR/LF must not inject or forge extra log lines
        # (CodeQL py/log-injection): each rollback record stays a single physical line.
        evil_id = "svc-1\r\nINFO forged: attacker-controlled entry"
        role = Role(id="r1", name="role\r\ninjected", composite=False)
        scope = Scope(id="s1", name="scope\ninjected")
        service = Service(id=evil_id, serviceId=CLIENT_ID, name=kf.SERVICE_NAME, enabled=True)
        config = _config_returning(service)
        graph = _graph(created_roles=[role], created_scopes=[scope])

        with (
            caplog.at_level("INFO", logger=orchestrator.logger.name),
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = LLMAccessError("boom")
            with pytest.raises(LLMAccessError):
                orchestrator.onboard_service(evil_id)

        for record in caplog.records:
            assert "\n" not in record.getMessage()
            assert "\r" not in record.getMessage()


class TestRollbackDeletesOnlyCreated:
    def test_reused_by_name_entities_are_never_torn_down(self):
        # Provision's created-manifest lists ONLY what it created this run. A role/scope it
        # reused by name (created by another service / a prior run) is absent from the
        # manifest, so rollback -- which iterates the manifest -- never deletes it.
        created_role = Role(id="r-new", name="weather.new", composite=False)
        reused_role = Role(id="r-shared", name="shared.role", composite=False)
        created_scope = Scope(id="s-new", name="weather.new")
        reused_scope = Scope(id="s-shared", name="shared.scope")
        service = _service()
        config = _config_returning(service)
        graph = _graph(created_roles=[created_role], created_scopes=[created_scope])

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = LLMAccessError("boom")
            with pytest.raises(LLMAccessError):
                orchestrator.onboard_service(SERVICE_ID)

        config.delete_service_role.assert_called_once_with(service, created_role)
        config.delete_service_scope.assert_called_once_with(service, created_scope)
        deleted_roles = [c.args[1] for c in config.delete_service_role.call_args_list]
        deleted_scopes = [c.args[1] for c in config.delete_service_scope.call_args_list]
        assert reused_role not in deleted_roles
        assert reused_scope not in deleted_scopes


class TestRollbackScopedToFourErrors:
    def test_non_rollback_builder_error_propagates_without_teardown(self, quarantine):
        # A builder error that is NOT one of the four typed failures (e.g. an HTTPException
        # from IdP focus resolution) propagates untouched -- no teardown, no disable.
        service = _service()
        config = _config_returning(service)
        graph = _graph(
            created_roles=[Role(id="r1", name="weather.forecast", composite=False)],
            created_scopes=[Scope(id="s1", name="weather.history")],
            service_type=ServiceType.TOOL,
        )

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            spb.build.side_effect = HTTPException(502, "IdP Configuration Service unavailable")
            with pytest.raises(HTTPException) as exc:
                orchestrator.onboard_service(SERVICE_ID)

        assert exc.value.status_code == 502
        graph.invoke.assert_called_once()
        config.delete_service_role.assert_not_called()
        config.delete_service_scope.assert_not_called()
        config.set_service_enabled.assert_not_called()
        quarantine.assert_not_called()


class TestRetryableReRunRollsBackIdempotently:
    def test_second_attempt_rolls_back_only_its_own_created_objects(self):
        # A retryable LLMAccessError re-provisions on NATS redelivery and rolls back again.
        # The first attempt already deleted its objects; the second re-creates fresh ones
        # (its own created-manifest) and tears down ONLY those -- no crash on already-gone
        # objects (the Configuration deletes are idempotent; the mock never raises).
        service = _service()
        config = _config_returning(service)

        def _attempt(role, scope):
            graph = _graph(created_roles=[role], created_scopes=[scope])
            with (
                patch.object(orchestrator, "build_provision_graph", return_value=graph),
                patch.object(orchestrator, "ServicePolicyBuilder") as spb,
                patch.object(orchestrator, "_config", return_value=config),
            ):
                spb.build.side_effect = LLMAccessError("transient")
                with pytest.raises(LLMAccessError):
                    orchestrator.onboard_service(SERVICE_ID)

        _attempt(
            Role(id="r-run1", name="weather.forecast", composite=False),
            Scope(id="s-run1", name="weather.history"),
        )
        config.reset_mock()
        config.get_service.return_value = service

        r2 = Role(id="r-run2", name="weather.forecast", composite=False)
        s2 = Scope(id="s-run2", name="weather.history")
        _attempt(r2, s2)

        # Second rollback targets ONLY its own re-created objects.
        config.delete_service_role.assert_called_once_with(service, r2)
        config.delete_service_scope.assert_called_once_with(service, s2)
        config.set_service_enabled.assert_called_once_with(service, False)


class TestLockRegistryEviction:
    """Issue 202: the per-service lock registry must not grow unbounded. Once the last run
    using a service_id's lock finishes -- on the success path and on EVERY failure path --
    the entry is evicted, while same-service runs stay strictly serialized across the
    eviction boundary. Emptiness is observed on the module-level `_service_locks` registry
    (the ticket's contract is precisely that this map does not accumulate idle entries)."""

    def test_success_path_evicts_the_entry(self):
        graph = _graph(service_type=ServiceType.AGENT)
        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.return_value = [object()]
            orchestrator.onboard_service(SERVICE_ID)

        assert SERVICE_ID not in orchestrator._service_locks

    @pytest.mark.parametrize("error", _rollback_errors(), ids=lambda e: type(e).__name__)
    def test_rollback_path_evicts_the_entry(self, error):
        # Every typed build failure runs the compensating rollback and re-raises; the entry
        # is evicted the same way as on success.
        role = Role(id="r1", name="weather.forecast", composite=False)
        scope = Scope(id="s1", name="weather.history")
        graph = _graph(created_roles=[role], created_scopes=[scope])
        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.side_effect = error
            with pytest.raises(type(error)):
                orchestrator.onboard_service(SERVICE_ID)

        assert SERVICE_ID not in orchestrator._service_locks

    def test_passthrough_fault_evicts_the_entry(self):
        # A non-rollback fault (e.g. an HTTPException from focus resolution) propagates
        # untouched, but the lock entry is still evicted on the way out.
        graph = _graph(service_type=ServiceType.TOOL)
        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.side_effect = HTTPException(502, "IdP config unavailable")
            with pytest.raises(HTTPException):
                orchestrator.onboard_service(SERVICE_ID)

        assert SERVICE_ID not in orchestrator._service_locks

    def test_provision_stage_fault_evicts_the_entry(self):
        # A fault raised in the provision stage (before the try/except) must also evict:
        # the entry is claimed at lock-acquire, so its release path runs on this exit too.
        graph = MagicMock()
        graph.invoke.side_effect = HTTPException(502, "IdP config unavailable")
        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder"),
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            with pytest.raises(HTTPException):
                orchestrator.onboard_service(SERVICE_ID)

        assert SERVICE_ID not in orchestrator._service_locks

    def test_same_service_runs_stay_serialized_across_eviction(self):
        # Overlapping same-service runs are driven through eviction boundaries: staggered
        # arrivals let early runs finish (and evict) while later ones are still queued on or
        # arriving at the lock. A naive delete would let a late arrival mint a fresh lock and
        # overtake a queued waiter -- so `max` would climb above 1. Reference-counted eviction
        # keeps the shared lock in the map while any run holds or waits, so max stays 1, and
        # the registry is empty once the last run leaves.
        concurrency = {"cur": 0, "max": 0}
        counter_lock = threading.Lock()

        def _build(_service_id, _service_type):
            with counter_lock:
                concurrency["cur"] += 1
                concurrency["max"] = max(concurrency["max"], concurrency["cur"])
            threading.Event().wait(0.05)
            with counter_lock:
                concurrency["cur"] -= 1
            return [object()]

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.side_effect = _build

            def _run():
                orchestrator.onboard_service(SERVICE_ID)

            threads = [threading.Thread(target=_run) for _ in range(6)]
            for t in threads:
                t.start()
                threading.Event().wait(0.02)  # stagger so runs cross eviction boundaries
            for t in threads:
                t.join(timeout=10)
                assert not t.is_alive(), "onboard_service thread hung (deadlock?)"

        assert concurrency["max"] == 1, "same-service runs overlapped across an eviction"
        assert SERVICE_ID not in orchestrator._service_locks


class TestPerServiceSerialization:
    """Issue 180: the full provision → build → rollback lifecycle is serialized per
    service_id so overlapping same-service runs (POST + NATS) cannot corrupt the
    created-manifest or roll back a shared entity, while different service_ids stay
    concurrent. All waits are bounded so a regression fails fast rather than hangs."""

    def test_same_service_id_calls_serialize(self):
        # Two threads onboard the SAME service_id. The mocked builder records how many
        # threads are inside `build` at once; the lock must keep that at 1.
        concurrency = {"cur": 0, "max": 0}
        counter_lock = threading.Lock()

        def _build(_service_id, _service_type):
            with counter_lock:
                concurrency["cur"] += 1
                concurrency["max"] = max(concurrency["max"], concurrency["cur"])
            # Hold the section briefly so a missing lock would overlap deterministically.
            threading.Event().wait(0.05)
            with counter_lock:
                concurrency["cur"] -= 1
            return [object()]

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.side_effect = _build

            def _run():
                orchestrator.onboard_service(SERVICE_ID)

            threads = [threading.Thread(target=_run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
                assert not t.is_alive(), "onboard_service thread hung (deadlock?)"

        assert concurrency["max"] == 1

    def test_different_service_ids_run_concurrently(self):
        # Two threads onboard DIFFERENT service_ids. `build` waits on a Barrier(2): both
        # must arrive for it to release, which can only happen if the two runs overlap.
        # A bounded timeout means a regression (serialized) trips BrokenBarrierError fast
        # instead of hanging the suite.
        barrier = threading.Barrier(2, timeout=5)
        errors = []

        def _build(_service_id, _service_type):
            try:
                barrier.wait()
            except threading.BrokenBarrierError as e:  # pragma: no cover - regression path
                errors.append(e)
            return [object()]

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.side_effect = _build

            def _run(service_id):
                orchestrator.onboard_service(service_id)

            threads = [
                threading.Thread(target=_run, args=("svc-a",)),
                threading.Thread(target=_run, args=("svc-b",)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
                assert not t.is_alive(), "onboard_service thread hung"

        assert errors == [], "different service_ids did not run concurrently"


class TestPceOwnsThePdp:
    def test_orchestrator_does_not_import_the_pdp_library(self):
        # The PCE owns the PDP: the orchestrator reaches it only through the PCE (quarantine).
        tree = ast.parse(inspect.getsource(orchestrator))
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        }
        assert not any(name and name.startswith("aiac.pdp") for name in imported)
        assert "aiac.policy.computation" in imported


# --------------------------------------------------------------------------- #
# Precondition checks (D30) and the bootstrap CR of a tool (checkpoint B1)     #
# --------------------------------------------------------------------------- #
def _failed_pod_check(check: str):
    """A cluster in which exactly one precondition check fails."""
    if check == "#1":
        return {"pods": [kf.pod(containers=[kf.app_container()])]}  # no sidecar
    if check == "#2":
        return {"configmap": kf.pipeline_configmap(inbound=("jwt-validation", "mcp-parser"))}  # no opa
    return {"pods": [kf.pod(containers=[kf.app_container(readiness=kf.http_get_probe()), kf.sidecar_container()])]}


class TestPreconditionChecksRunFirst:
    @pytest.mark.parametrize("check", ["#1", "#2", "#6"])
    def test_a_failed_check_raises_before_provision_and_the_prb_with_no_rollback(
        self, check, k8s, quarantine, bootstrap
    ):
        # Checkpoint O2: the checks run first, so nothing changed yet. A failed check is not a
        # rollback error: no Provision, no PRB, no rollback, no client disable, no quarantine.
        cluster = _failed_pod_check(check)
        if "pods" in cluster:
            k8s.list_namespaced_pod.return_value = kf.pod_list(*cluster["pods"])
        if "configmap" in cluster:
            k8s.read_namespaced_config_map.return_value = cluster["configmap"]
        config = _config_returning(_service())
        graph = _graph()

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            with pytest.raises(EnforcementPreconditionError) as ei:
                orchestrator.onboard_service(SERVICE_ID)

        assert len(ei.value.failures) == 1
        assert ei.value.failures[0].startswith(check)
        graph.invoke.assert_not_called()
        spb.build.assert_not_called()
        config.set_service_enabled.assert_not_called()
        config.delete_service_role.assert_not_called()
        config.delete_service_scope.assert_not_called()
        quarantine.assert_not_called()
        bootstrap.assert_not_called()
        assert SERVICE_ID not in orchestrator._service_locks

    def test_every_failed_check_is_named(self, k8s):
        # The Orchestrator runs every check, then raises one error that names each failed check.
        k8s.list_namespaced_pod.return_value = kf.pod_list(
            kf.pod(containers=[kf.app_container(liveness=kf.http_get_probe())])
        )
        k8s.read_namespaced_config_map.return_value = kf.pipeline_configmap(inbound=("jwt-validation",))

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder"),
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            with pytest.raises(EnforcementPreconditionError) as ei:
                orchestrator.onboard_service(SERVICE_ID)

        assert [f[:2] for f in ei.value.failures] == ["#1", "#2", "#6"]

    def test_the_checks_read_the_pods_and_the_pipeline_of_the_service_namespace(self, k8s):
        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.return_value = []
            orchestrator.onboard_service(SERVICE_ID)

        k8s.list_namespaced_pod.assert_called_with(kf.NAMESPACE)
        k8s.read_namespaced_config_map.assert_called_once_with(kf.PIPELINE_CONFIGMAP, kf.NAMESPACE)


class TestBootstrapOfATool:
    def test_a_passing_tool_gets_its_bootstrap_cr_before_provision(self, k8s, bootstrap):
        # Checkpoint B1: checks -> bootstrap (tool only) -> Provision -> PRB. The type comes from the
        # pod label: the catalog type is not set before Provision.
        k8s.list_namespaced_pod.return_value = kf.pod_list(kf.pod(type_label="tool"))
        graph = _graph(service_type=ServiceType.TOOL)
        order = MagicMock()
        order.attach_mock(bootstrap, "bootstrap")
        order.attach_mock(graph.invoke, "provision")

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            order.attach_mock(spb.build, "prb")
            spb.build.return_value = []
            orchestrator.onboard_service(SERVICE_ID)

        bootstrap.assert_called_once_with(CLIENT_ID, ServiceType.TOOL)
        assert [c[0] for c in order.mock_calls] == ["bootstrap", "provision", "prb"]

    def test_a_passing_agent_gets_no_bootstrap(self, bootstrap):
        with (
            patch.object(orchestrator, "build_provision_graph", return_value=_graph()),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.return_value = []
            orchestrator.onboard_service(SERVICE_ID)

        bootstrap.assert_not_called()

    def test_a_disabled_tool_gets_no_bootstrap(self, k8s, bootstrap):
        # A disabled (quarantined) tool fails at the discovery-token mint anyway (C5); a bootstrap CR
        # would then stay stale until the next resync.
        k8s.list_namespaced_pod.return_value = kf.pod_list(kf.pod(type_label="tool"))
        graph = _graph(service_type=ServiceType.TOOL)

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service(enabled=False))),
        ):
            spb.build.return_value = []
            orchestrator.onboard_service(SERVICE_ID)

        bootstrap.assert_not_called()
        graph.invoke.assert_called_once()

    def test_under_agent_side_a_tool_gets_no_check_but_still_its_bootstrap(self, k8s, bootstrap, monkeypatch):
        # D30 scope: under agent side a tool gets a pass-through CR, which needs no check. So a tool
        # pod with no sidecar and no opa passes; its type still comes from the pod label, and the
        # bootstrap (the pass-through CR under agent side) runs before Provision.
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", "agent-side")
        k8s.list_namespaced_pod.return_value = kf.pod_list(kf.pod(type_label="tool", containers=[kf.app_container()]))
        k8s.read_namespaced_config_map.return_value = kf.pipeline_configmap(inbound=(), outbound=())
        graph = _graph(service_type=ServiceType.TOOL)
        order = MagicMock()
        order.attach_mock(bootstrap, "bootstrap")
        order.attach_mock(graph.invoke, "provision")

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=_config_returning(_service())),
        ):
            spb.build.return_value = []
            orchestrator.onboard_service(SERVICE_ID)

        bootstrap.assert_called_once_with(CLIENT_ID, ServiceType.TOOL)
        assert [c[0] for c in order.mock_calls] == ["bootstrap", "provision"]

    def test_under_agent_side_an_agent_with_no_outbound_opa_fails_before_provision(self, k8s, quarantine, monkeypatch):
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", "agent-side")
        k8s.read_namespaced_config_map.return_value = kf.pipeline_configmap(outbound=("token-exchange",))
        config = _config_returning(_service())
        graph = _graph()

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            with pytest.raises(EnforcementPreconditionError) as ei:
                orchestrator.onboard_service(SERVICE_ID)

        assert [f[:2] for f in ei.value.failures] == ["#2"]
        graph.invoke.assert_not_called()
        spb.build.assert_not_called()
        config.set_service_enabled.assert_not_called()
        quarantine.assert_not_called()

    def test_a_failed_bootstrap_propagates_before_provision_with_no_rollback(self, k8s, bootstrap, quarantine):
        # The bootstrap stores no SPM and Provision has not run, so nothing needs compensation: the
        # error propagates (retryable on the NATS path), with no rollback and no quarantine.
        k8s.list_namespaced_pod.return_value = kf.pod_list(kf.pod(type_label="tool"))
        bootstrap.side_effect = RuntimeError("PDP unreachable")
        config = _config_returning(_service())
        graph = _graph(service_type=ServiceType.TOOL)

        with (
            patch.object(orchestrator, "build_provision_graph", return_value=graph),
            patch.object(orchestrator, "ServicePolicyBuilder") as spb,
            patch.object(orchestrator, "_config", return_value=config),
        ):
            with pytest.raises(RuntimeError, match="PDP unreachable"):
                orchestrator.onboard_service(SERVICE_ID)

        graph.invoke.assert_not_called()
        spb.build.assert_not_called()
        config.set_service_enabled.assert_not_called()
        quarantine.assert_not_called()
