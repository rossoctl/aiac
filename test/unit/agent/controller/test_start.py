"""Unit tests for the Controller start sequence (the FastAPI lifespan, before the NATS consumer).

The sequence: start check #4 (D30: the global combiner denies a pod that has no client CR), then the
PCE ``resync()`` (D28), then the NATS consumer. A failure in check #4 or in the resync stops the
Controller: the lifespan raises, so uvicorn never serves. Driven through the real app with a
``TestClient`` context (which runs the lifespan). The k8s read of the combiner CR is faked at the
``kube._custom_objects`` seam, the PCE ``resync`` at its import site, and the NATS consumer is a fake.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from kubernetes.client.exceptions import ApiException

from aiac.agent.controller import start
from aiac.agent.controller.routes import app
from aiac.agent.uc.onboarding.provision import kube

_INBOUND_LINE = "client_ok if not data.authbridge.client.inbound.request"
_OUTBOUND_LINE = "client_ok if not data.authbridge.client.outbound.request"


def _package(direction: str, phase: str, *, fail_open: bool) -> str:
    """One package of the global combiner, as the operator chart renders it (``fail_open``: with the
    stock ``client_ok if not <client package>`` line, which allows a pod that has no client CR)."""
    pkg = f"data.authbridge.client.{direction}.{phase}"
    lines = [
        f"package authbridge.{direction}.{phase}",
        "import rego.v1",
        "default allow := false",
        f"allow if data.authbridge.ns.{direction}.{phase}.override",
        "allow if {",
        "    ns_ok",
        "    client_ok",
        "}",
        f"ns_ok if data.authbridge.ns.{direction}.{phase}.allow",
        f"ns_ok if not data.authbridge.ns.{direction}.{phase}",
        f"client_ok if {pkg}.allow",
    ]
    if fail_open:
        lines.append(f"client_ok if not {pkg}")
    return "\n".join(lines) + "\n"


def _combiner(*, inbound_fail_open=False, outbound_fail_open=False, drop=()):
    """The ``default`` AuthorizationPolicy CR. By default the changed (AIAC) combiner: no
    ``client_ok if not`` line in the two request packages. The response packages keep the default."""
    policies = [
        {"path": "inbound/request.rego", "content": _package("inbound", "request", fail_open=inbound_fail_open)},
        {"path": "inbound/response.rego", "content": _package("inbound", "response", fail_open=True)},
        {"path": "outbound/request.rego", "content": _package("outbound", "request", fail_open=outbound_fail_open)},
        {"path": "outbound/response.rego", "content": _package("outbound", "response", fail_open=True)},
    ]
    return {
        "apiVersion": "agent.rossoctl.dev/v1alpha1",
        "kind": "AuthorizationPolicy",
        "metadata": {"name": "default", "namespace": "rossoctl-system"},
        "spec": {"scope": "global", "policies": [p for p in policies if p["path"] not in drop]},
    }


class _FakeConsumer:
    def __init__(self, events):
        self._events = events

    async def start_with_retry(self):
        self._events.append("consumer")

    async def stop(self):
        pass


@pytest.fixture
def cluster(monkeypatch):
    """The fake CustomObjectsApi (``get_namespaced_custom_object`` returns the changed combiner), the
    PCE ``resync`` and the NATS consumer, recording the start order in ``cluster.events``."""
    monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")
    monkeypatch.delenv("AIAC_BUNDLE_SERVICE_NAMESPACE", raising=False)
    events: list[str] = []
    objects = MagicMock()
    objects.get_namespaced_custom_object.side_effect = lambda **_: events.append("check #4") or objects.combiner
    objects.combiner = _combiner()
    with (
        patch.object(kube, "_custom_objects", return_value=objects),
        patch.object(start, "resync", side_effect=lambda: events.append("resync")) as resync,
        patch("aiac.agent.eventbus.consumer.AiacEventConsumer", side_effect=lambda: _FakeConsumer(events)),
    ):
        objects.resync = resync
        objects.events = events
        yield objects


def _serve():
    """Start the app (the lifespan runs), answer one /health, stop."""
    with TestClient(app) as client:
        return client.get("/health").status_code


class TestStartSequencePasses:
    def test_check_4_then_resync_then_the_consumer_then_serve(self, cluster):
        assert _serve() == 200
        assert cluster.events == ["check #4", "resync", "consumer"]

    def test_check_4_reads_the_default_cr_in_the_bundle_service_namespace(self, cluster):
        _serve()
        cluster.get_namespaced_custom_object.assert_called_once_with(
            group="agent.rossoctl.dev",
            version="v1alpha1",
            namespace="rossoctl-system",
            plural="authorizationpolicies",
            name="default",
        )

    def test_the_bundle_service_namespace_comes_from_the_env(self, cluster, monkeypatch):
        monkeypatch.setenv("AIAC_BUNDLE_SERVICE_NAMESPACE", "authbridge-system")
        _serve()
        assert cluster.get_namespaced_custom_object.call_args.kwargs["namespace"] == "authbridge-system"

    def test_a_commented_out_line_is_no_failure(self, cluster):
        # Rego ignores a comment, so a commented-out default line does not allow a pod with no CR.
        content = _package("inbound", "request", fail_open=False) + f"# {_INBOUND_LINE}\n"
        cluster.combiner["spec"]["policies"][0]["content"] = content
        assert _serve() == 200


class TestCheck4StopsTheController:
    @pytest.mark.parametrize(
        ("combiner", "named"),
        [
            (_combiner(inbound_fail_open=True), "inbound/request.rego"),
            (_combiner(outbound_fail_open=True), "outbound/request.rego"),
            (_combiner(drop=("inbound/request.rego",)), "inbound/request.rego"),
            (_combiner(drop=("outbound/request.rego",)), "outbound/request.rego"),
        ],
        ids=["inbound-line", "outbound-line", "no-inbound-package", "no-outbound-package"],
    )
    def test_a_combiner_that_allows_a_pod_with_no_client_cr_stops_the_start(self, cluster, combiner, named, caplog):
        cluster.combiner = combiner
        with pytest.raises(start.StartCheckError, match="#4") as ei:
            _serve()
        assert named in str(ei.value)
        cluster.resync.assert_not_called()
        assert "consumer" not in cluster.events
        assert any("#4" in r.getMessage() and r.levelname == "ERROR" for r in caplog.records)

    def test_both_lines_are_named(self, cluster):
        cluster.combiner = _combiner(inbound_fail_open=True, outbound_fail_open=True)
        with pytest.raises(start.StartCheckError) as ei:
            _serve()
        assert "inbound/request.rego" in str(ei.value) and "outbound/request.rego" in str(ei.value)

    def test_a_missing_cr_stops_the_start(self, cluster):
        cluster.get_namespaced_custom_object.side_effect = ApiException(status=404, reason="Not Found")
        with pytest.raises(start.StartCheckError, match="missing"):
            _serve()
        cluster.resync.assert_not_called()

    @pytest.mark.parametrize("status", [403, 500])
    def test_a_cr_that_cannot_be_read_stops_the_start(self, cluster, status):
        cluster.get_namespaced_custom_object.side_effect = ApiException(status=status, reason="boom")
        with pytest.raises(start.StartCheckError):
            _serve()
        cluster.resync.assert_not_called()


class TestResyncStopsTheController:
    def test_a_failed_resync_stops_the_start(self, cluster, caplog):
        cluster.resync.side_effect = RuntimeError("PDP unreachable")
        with pytest.raises(RuntimeError, match="PDP unreachable"):
            _serve()
        assert "consumer" not in cluster.events
        assert any("resync" in r.getMessage() and r.levelname == "ERROR" for r in caplog.records)
