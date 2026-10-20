"""Unit tests for aiac.pdp.service.policy.opa.main — the writer HTTP API (D18c).

Targets the always-on Custom Resource writer. The module builds a
``CustomObjectsApi`` at import (kube-config load is guarded, so import needs no
cluster); every test patches that module-level ``_api`` with a ``MagicMock`` so
no real Kubernetes API is contacted. The additive ``POLICY_WRITER_DUMP_REGO``
local-dump toggle is covered here too (it never gates or replaces the CR write).

The body of ``POST`` / ``PUT /policy`` is the policy model; each ``services[]``
SPM is one CR. A body without ``services`` is 422. The per-service delete takes
the id with the ``{service_id:path}`` converter: the library percent-encodes the
slashes of a clientId (``%2F``), and the server decodes them back before routing.

The end-to-end test runs ``opa eval`` on the CR content that the writer applied
(skips without ``opa`` on PATH); its verdicts are hand-written from the spec.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from kubernetes.client import ApiException

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.pdp.policy.library.api import _service_id_segment
from aiac.pdp.service.policy.opa import main
from aiac.pdp.service.policy.opa.main import app
from aiac.policy.model.models import PolicyModel, PolicyRule, ServicePolicyModel

TOOL = "spiffe://localtest.me/ns/team1/sa/github-tool"
AGENT = "spiffe://localtest.me/ns/team1/sa/github-agent"
LABEL = {"app.kubernetes.io/managed-by": "aiac-pdp-policy-writer"}
PASS_THROUGH_OUTBOUND = "package authbridge.client.outbound.request\nimport rego.v1\n\nallow := true\n"


@pytest.fixture
def api(monkeypatch):
    """Patch the module-level Kubernetes client and default the dump toggle off."""
    mock = MagicMock()
    monkeypatch.setattr(main, "_api", mock)
    monkeypatch.delenv("POLICY_WRITER_DUMP_REGO", raising=False)
    monkeypatch.delenv("REGO_OUTPUT_DIR", raising=False)
    monkeypatch.delenv("PLATFORM_SOURCE_CLIENTS", raising=False)
    return mock


def _spm(service_id: str, service_type: ServiceType = ServiceType.TOOL) -> ServicePolicyModel:
    owner = service_id.rsplit("/", 1)[-1]
    scope = Scope(id=f"{owner}-s1", name=f"{owner}.source-read", serviceId=service_id)
    user_role = Role(id="developer", name="developer", composite=False, kind=RoleKind.USER, actorIds=["dev-user"])
    return ServicePolicyModel(
        service_id=service_id,
        service_type=service_type,
        owned_roles=[],
        owned_scopes=[scope],
        inbound_allow_rules=[PolicyRule(role=user_role, scope=scope)],
    )


def _body(*spms: ServicePolicyModel) -> dict:
    """The JSON body of ``POST`` / ``PUT /policy``: the policy model of ``spms``."""
    return PolicyModel(services=list(spms)).model_dump(mode="json")


def _applied(api) -> list[dict]:
    """The CR bodies, in the order the writer server-side-applied them."""
    return [c.kwargs["body"] for c in api.patch_namespaced_custom_object.call_args_list]


def _policies(cr: dict) -> dict[str, str]:
    return {p["path"]: p["content"] for p in cr["spec"]["policies"]}


# ---------------------------------------------------------------------------
# POST /policy -> one server-side apply per SPM
# ---------------------------------------------------------------------------


class TestPost:
    def test_tool_cr_is_server_side_applied(self, api):
        resp = TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_called_once()
        kwargs = api.patch_namespaced_custom_object.call_args.kwargs
        assert kwargs["group"] == "agent.rossoctl.dev"
        assert kwargs["version"] == "v1alpha1"
        assert kwargs["plural"] == "authorizationpolicies"
        assert (kwargs["namespace"], kwargs["name"]) == ("team1", "github-tool")
        assert kwargs["field_manager"] == "aiac-pdp-policy-writer"
        assert kwargs["force"] is True
        assert kwargs["_content_type"] == "application/apply-patch+yaml"

    def test_tool_cr_shape_and_both_request_packages(self, api):
        TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        (cr,) = _applied(api)
        assert cr["apiVersion"] == "agent.rossoctl.dev/v1alpha1"
        assert cr["kind"] == "AuthorizationPolicy"
        assert cr["metadata"] == {"name": "github-tool", "namespace": "team1", "labels": LABEL}
        assert cr["spec"]["scope"] == "client"
        assert cr["spec"]["clientID"] == "github-tool"
        assert [p["path"] for p in cr["spec"]["policies"]] == ["inbound/request.rego", "outbound/request.rego"]
        policies = _policies(cr)
        inbound = policies["inbound/request.rego"]
        assert inbound.startswith("package authbridge.client.inbound.request\nimport rego.v1\n")
        # The tool inbound (D26), with the self-discovery rule of the tool's own client.
        assert 'owned_tools := ["source-read"]' in inbound
        assert f'self_client_id := "{TOOL}"' in inbound
        assert policies["outbound/request.rego"] == PASS_THROUGH_OUTBOUND

    def test_agent_cr_has_the_agent_inbound_and_the_pass_through_outbound(self, api, monkeypatch):
        monkeypatch.setenv("PLATFORM_SOURCE_CLIENTS", "rossoctl,argocd")
        resp = TestClient(app).post("/policy", json=_body(_spm(AGENT, ServiceType.AGENT)))
        assert resp.status_code == 204
        (cr,) = _applied(api)
        assert cr["metadata"] == {"name": "github-agent", "namespace": "team1", "labels": LABEL}
        assert cr["spec"]["clientID"] == "github-agent"
        policies = _policies(cr)
        inbound = policies["inbound/request.rego"]
        # The agent inbound (D26a): the full scope names and the platform-client bypass.
        assert 'agent_scopes := ["github-agent.source-read"]' in inbound
        assert 'source_allow_ok if { input.identity.client_id == "argocd" }' in inbound
        assert "owned_tools" not in inbound
        assert policies["outbound/request.rego"] == PASS_THROUGH_OUTBOUND

    def test_batch_writes_one_cr_per_service_in_order(self, api):
        body = _body(_spm(TOOL), _spm(AGENT, ServiceType.AGENT), _spm("team2/weather-tool"))
        resp = TestClient(app).post("/policy", json=body)
        assert resp.status_code == 204
        refs = [(cr["metadata"]["namespace"], cr["metadata"]["name"]) for cr in _applied(api)]
        assert refs == [("team1", "github-tool"), ("team1", "github-agent"), ("team2", "weather-tool")]

    def test_a_bad_id_is_skipped_and_logged_and_the_other_entries_are_written(self, api, caplog):
        # "github-agent" has no derivable namespace: it cannot have a CR (D20 denies it).
        body = _body(_spm("github-agent"), _spm(TOOL))
        resp = TestClient(app).post("/policy", json=body)
        assert resp.status_code == 204
        assert [cr["metadata"]["name"] for cr in _applied(api)] == ["github-tool"]
        assert "github-agent" in caplog.text

    def test_api_exception_is_502(self, api):
        api.patch_namespaced_custom_object.side_effect = ApiException(status=500)
        resp = TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_empty_model_writes_nothing(self, api):
        resp = TestClient(app).post("/policy", json=_body())
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_not_called()


def _opa_allows(rego: str, tier: str, input_doc: dict) -> bool:
    """``data.authbridge.client.<tier>.request.allow`` of ``rego`` for ``input_doc`` (opa eval)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego)
        out = subprocess.run(
            [shutil.which("opa"), "eval", "-f", "json", "-d", str(path), "--stdin-input"]
            + [f"data.authbridge.client.{tier}.request.allow"],
            input=json.dumps(input_doc),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    return json.loads(out)["result"][0]["expressions"][0]["value"]


def _tool_call(subject: str, tool: str, client_id: str = AGENT) -> dict:
    return {
        "identity": {"subject": subject, "client_id": client_id},
        "mcp": {"method": "tools/call", "params": {"name": tool}},
    }


def _end_to_end_body() -> dict:
    """dev-user (role developer) may call github-agent (its one agent scope). dev-user and
    github-agent (role github-caller) may call the tool ``source-read`` of github-tool. github-tool
    also owns ``issues-read``, with no grant. No other grant."""
    developer = Role(id="developer", name="developer", composite=False, kind=RoleKind.USER, actorIds=["dev-user"])
    caller = Role(id="github-caller", name="github-caller", composite=False, kind=RoleKind.AGENT, actorIds=[AGENT])
    agent_scope = Scope(id="github-agent-ops", name="github-agent.source_operations", serviceId=AGENT)
    source_read = Scope(id="github-tool-s1", name="github-tool.source-read", serviceId=TOOL)
    issues_read = Scope(id="github-tool-s2", name="github-tool.issues-read", serviceId=TOOL)
    agent = ServicePolicyModel(
        service_id=AGENT,
        service_type=ServiceType.AGENT,
        owned_roles=[caller],
        owned_scopes=[agent_scope],
        inbound_allow_rules=[PolicyRule(role=developer, scope=agent_scope)],
    )
    tool = ServicePolicyModel(
        service_id=TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[source_read, issues_read],
        inbound_allow_rules=[PolicyRule(role=developer, scope=source_read), PolicyRule(role=caller, scope=source_read)],
    )
    return _body(agent, tool)


# The verdicts that the spec gives for the CRs of ``_end_to_end_body``.
_VERDICTS = [
    # the tool inbound: the per-tool check, both gates mandatory (D26)
    ("github-tool", "inbound", _tool_call("dev-user", "source-read"), True),
    ("github-tool", "inbound", _tool_call("dev-user", "issues-read"), False),
    ("github-tool", "inbound", _tool_call("test-user", "source-read"), False),
    (
        "github-tool",
        "inbound",
        _tool_call("dev-user", "source-read", "spiffe://localtest.me/ns/team1/sa/other-agent"),
        False,
    ),
    # the tool inbound: no platform-client bypass, and no "no calling agent" open
    ("github-tool", "inbound", _tool_call("dev-user", "source-read", "rossoctl"), False),
    (
        "github-tool",
        "inbound",
        {"identity": {"subject": "dev-user"}, "mcp": {"method": "tools/call", "params": {"name": "source-read"}}},
        False,
    ),
    # the tool inbound: the MCP session rule and the self-discovery rule of the tool's own client
    (
        "github-tool",
        "inbound",
        {"identity": {"subject": "dev-user", "client_id": AGENT}, "mcp": {"method": "tools/list"}},
        True,
    ),
    (
        "github-tool",
        "inbound",
        {"identity": {"subject": "test-user", "client_id": AGENT}, "mcp": {"method": "initialize"}},
        False,
    ),
    ("github-tool", "inbound", {"identity": {"client_id": TOOL}, "mcp": {"method": "tools/list"}}, True),
    # the tool inbound: a request that is not an MCP message, and a request with no identity, are denied
    (
        "github-tool",
        "inbound",
        {"identity": {"subject": "dev-user", "client_id": AGENT}, "a2a": {"method": "message/send"}},
        False,
    ),
    ("github-tool", "inbound", {}, False),
    # the agent inbound (agent-level): a granted user, the platform client; no role or no identity is denied
    ("github-agent", "inbound", {"identity": {"subject": "dev-user"}, "a2a": {"method": "message/send"}}, True),
    ("github-agent", "inbound", {"identity": {"subject": "dev-user", "client_id": "rossoctl"}}, True),
    ("github-agent", "inbound", {"identity": {"subject": "test-user"}, "a2a": {"method": "message/send"}}, False),
    ("github-agent", "inbound", {}, False),
    # the outbound of each CR: a pass-through that allows every request (D24)
    ("github-agent", "outbound", {}, True),
    ("github-agent", "outbound", _tool_call("test-user", "issues-write", TOOL), True),
    ("github-tool", "outbound", {}, True),
    ("github-tool", "outbound", {"identity": {"subject": "test-user"}, "a2a": {"method": "message/send"}}, True),
]


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("cr_name, tier, input_doc, allowed", _VERDICTS)
def test_the_applied_crs_end_to_end(api, cr_name, tier, input_doc, allowed):
    # The Rego under test is the CR content that the writer applied, not a generator output.
    resp = TestClient(app).post("/policy", json=_end_to_end_body())
    assert resp.status_code == 204
    contents = {cr["metadata"]["name"]: _policies(cr) for cr in _applied(api)}
    assert _opa_allows(contents[cr_name][f"{tier}/request.rego"], tier, input_doc) is allowed


# ---------------------------------------------------------------------------
# PUT /policy -> upsert every entry, then delete every other labelled CR
# ---------------------------------------------------------------------------


def _listing(*refs: tuple[str, str]) -> dict:
    return {"items": [{"metadata": {"namespace": ns, "name": name, "labels": LABEL}} for ns, name in refs]}


def _deleted(api) -> list[tuple[str, str]]:
    return [(c.kwargs["namespace"], c.kwargs["name"]) for c in api.delete_namespaced_custom_object.call_args_list]


def _upserted(api) -> list[tuple[str, str]]:
    return [(c.kwargs["namespace"], c.kwargs["name"]) for c in api.patch_namespaced_custom_object.call_args_list]


class TestPut:
    def test_deletes_the_stale_labelled_crs_and_keeps_the_entries(self, api):
        api.list_cluster_custom_object.return_value = _listing(
            ("team1", "github-tool"), ("team1", "old-agent"), ("team1", "github-agent"), ("team2", "gone-tool")
        )
        body = _body(_spm(TOOL), _spm(AGENT, ServiceType.AGENT))
        resp = TestClient(app).put("/policy", json=body)
        assert resp.status_code == 204
        assert [cr["metadata"]["name"] for cr in _applied(api)] == ["github-tool", "github-agent"]
        # The cluster-wide list selects only the CRs this writer owns.
        kwargs = api.list_cluster_custom_object.call_args.kwargs
        assert kwargs["label_selector"] == "app.kubernetes.io/managed-by=aiac-pdp-policy-writer"
        assert sorted(_deleted(api)) == [("team1", "old-agent"), ("team2", "gone-tool")]
        delete_kwargs = api.delete_namespaced_custom_object.call_args.kwargs
        assert (delete_kwargs["group"], delete_kwargs["version"], delete_kwargs["plural"]) == (
            "agent.rossoctl.dev",
            "v1alpha1",
            "authorizationpolicies",
        )

    def test_deletes_run_only_after_every_upsert(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        TestClient(app).put("/policy", json=_body(_spm(TOOL), _spm(AGENT, ServiceType.AGENT)))
        calls = [name for name, _, _ in api.method_calls]
        assert calls == [
            "patch_namespaced_custom_object",
            "patch_namespaced_custom_object",
            "list_cluster_custom_object",
            "delete_namespaced_custom_object",
        ]

    def test_a_failed_upsert_deletes_nothing(self, api):
        api.patch_namespaced_custom_object.side_effect = [None, ApiException(status=500)]
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        resp = TestClient(app).put("/policy", json=_body(_spm(TOOL), _spm(AGENT, ServiceType.AGENT)))
        assert resp.status_code == 502
        api.list_cluster_custom_object.assert_not_called()
        api.delete_namespaced_custom_object.assert_not_called()

    def test_a_bad_id_is_skipped_and_the_rest_is_replaced(self, api, caplog):
        # A bad id cannot have a CR. One bad stored SPM must not stop the resync at every start.
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team1", "old-agent"))
        resp = TestClient(app).put("/policy", json=_body(_spm("github-agent"), _spm(TOOL)))
        assert resp.status_code == 204
        assert _upserted(api) == [("team1", "github-tool")]
        assert _deleted(api) == [("team1", "old-agent")]
        assert "github-agent" in caplog.text

    def test_an_empty_model_deletes_every_labelled_cr(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team1", "github-agent"))
        resp = TestClient(app).put("/policy", json=_body())
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_not_called()
        assert sorted(_deleted(api)) == [("team1", "github-agent"), ("team1", "github-tool")]

    def test_a_concurrent_delete_404_is_success(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        api.delete_namespaced_custom_object.side_effect = ApiException(status=404)
        resp = TestClient(app).put("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 204

    def test_a_failed_delete_is_502(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        api.delete_namespaced_custom_object.side_effect = ApiException(status=500)
        resp = TestClient(app).put("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 502
        assert "error" in resp.json()


# ---------------------------------------------------------------------------
# DELETE /policy/services/{service_id:path} -> delete the CR of one service
# ---------------------------------------------------------------------------


class TestDeleteService:
    @pytest.mark.parametrize("service_id", [TOOL, "team1/github-tool"], ids=["spiffe", "ns-name"])
    def test_the_library_url_reaches_the_route_and_deletes_the_cr(self, api, service_id):
        # The exact URL that the library's delete_service_cr builds (the id URL-encoded as one segment).
        resp = TestClient(app).delete(f"/policy/services/{_service_id_segment(service_id)}")
        assert resp.status_code == 204
        kwargs = api.delete_namespaced_custom_object.call_args.kwargs
        assert (kwargs["group"], kwargs["version"], kwargs["plural"]) == (
            "agent.rossoctl.dev",
            "v1alpha1",
            "authorizationpolicies",
        )
        assert (kwargs["namespace"], kwargs["name"]) == ("team1", "github-tool")
        api.list_cluster_custom_object.assert_not_called()

    def test_a_missing_cr_is_success(self, api):
        api.delete_namespaced_custom_object.side_effect = ApiException(status=404)
        resp = TestClient(app).delete(f"/policy/services/{_service_id_segment(TOOL)}")
        assert resp.status_code == 204

    def test_another_api_exception_is_502(self, api):
        api.delete_namespaced_custom_object.side_effect = ApiException(status=500)
        resp = TestClient(app).delete(f"/policy/services/{_service_id_segment(TOOL)}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_a_bad_id_has_no_cr_to_delete(self, api, caplog):
        # The quarantine and the decommission of such a service must be able to finish.
        resp = TestClient(app).delete("/policy/services/github-tool")
        assert resp.status_code == 204
        assert "github-tool" in caplog.text
        api.delete_namespaced_custom_object.assert_not_called()


# ---------------------------------------------------------------------------
# A body without services is a 422 (nothing is written, nothing is deleted)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["post", "put"])
def test_a_body_without_services_is_422_and_writes_nothing(api, method):
    resp = getattr(TestClient(app), method)("/policy", json={})
    assert resp.status_code == 422
    api.patch_namespaced_custom_object.assert_not_called()
    api.list_cluster_custom_object.assert_not_called()
    api.delete_namespaced_custom_object.assert_not_called()


# ---------------------------------------------------------------------------
# GET /health -> 200 when the API is reachable, 503 otherwise
# ---------------------------------------------------------------------------


class TestHealth:
    def test_200_when_list_succeeds(self, api):
        api.list_cluster_custom_object.return_value = {"items": []}
        resp = TestClient(app).get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        assert api.list_cluster_custom_object.call_args.kwargs["limit"] == 1

    def test_503_when_list_raises(self, api):
        api.list_cluster_custom_object.side_effect = ApiException(status=500)
        resp = TestClient(app).get("/health")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "unavailable"
        assert "error" in body


# ---------------------------------------------------------------------------
# DELETE /policy -> list-by-label then delete each
# ---------------------------------------------------------------------------


class TestDeleteAll:
    def test_lists_by_managed_by_label_then_deletes_each(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team2", "weather-agent"))
        resp = TestClient(app).delete("/policy")
        assert resp.status_code == 204
        selector = api.list_cluster_custom_object.call_args.kwargs["label_selector"]
        assert selector == "app.kubernetes.io/managed-by=aiac-pdp-policy-writer"
        assert sorted(_deleted(api)) == [("team1", "github-tool"), ("team2", "weather-agent")]

    def test_empty_listing_returns_204(self, api):
        api.list_cluster_custom_object.return_value = {"items": []}
        resp = TestClient(app).delete("/policy")
        assert resp.status_code == 204
        api.delete_namespaced_custom_object.assert_not_called()

    def test_list_failure_is_502(self, api):
        api.list_cluster_custom_object.side_effect = ApiException(status=403)
        resp = TestClient(app).delete("/policy")
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# POLICY_WRITER_DUMP_REGO additive local dump (never gates the CR write)
# ---------------------------------------------------------------------------


class TestDumpToggle:
    @pytest.fixture
    def dump(self, api, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICY_WRITER_DUMP_REGO", "1")
        monkeypatch.setenv("REGO_OUTPUT_DIR", str(tmp_path))
        return tmp_path

    def test_dump_on_writes_both_packages_and_still_patches(self, api, dump):
        resp = TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_called_once()
        tree = dump / "team1" / "github-tool"
        assert "package authbridge.client.inbound.request" in (tree / "inbound" / "request.rego").read_text()
        assert (tree / "outbound" / "request.rego").read_text() == PASS_THROUGH_OUTBOUND

    def test_dump_off_writes_no_files_but_still_patches(self, api, tmp_path, monkeypatch):
        # Toggle unset (deleted by the api fixture); REGO_OUTPUT_DIR set but unused.
        monkeypatch.setenv("REGO_OUTPUT_DIR", str(tmp_path))
        resp = TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_called_once()
        assert list(tmp_path.rglob("*.rego")) == []

    def test_dump_os_error_maps_to_502(self, api, tmp_path, monkeypatch):
        # REGO_OUTPUT_DIR under a regular file -> mkdir raises OSError.
        blocker = tmp_path / "afile"
        blocker.write_text("x")
        monkeypatch.setenv("POLICY_WRITER_DUMP_REGO", "1")
        monkeypatch.setenv("REGO_OUTPUT_DIR", str(blocker / "out"))
        resp = TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 502
        assert "error" in resp.json()
        # The SSA write happened before the additive dump failed.
        api.patch_namespaced_custom_object.assert_called_once()

    def test_dump_on_service_delete_removes_its_tree(self, api, dump):
        TestClient(app).post("/policy", json=_body(_spm(TOOL)))
        tree = dump / "team1" / "github-tool"
        assert tree.exists()
        resp = TestClient(app).delete(f"/policy/services/{_service_id_segment(TOOL)}")
        assert resp.status_code == 204
        assert not tree.exists()

    def test_dump_on_put_removes_the_stale_tree_and_keeps_the_entries(self, api, dump):
        TestClient(app).post("/policy", json=_body(_spm(TOOL), _spm(AGENT, ServiceType.AGENT)))
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team1", "github-agent"))
        resp = TestClient(app).put("/policy", json=_body(_spm(TOOL)))
        assert resp.status_code == 204
        assert (dump / "team1" / "github-tool").exists()
        assert not (dump / "team1" / "github-agent").exists()
