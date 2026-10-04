"""Unit tests for aiac.pdp.service.policy.opa.main — the writer HTTP API (D18c).

Targets the always-on Custom Resource writer. The module builds a
``CustomObjectsApi`` at import (kube-config load is guarded, so import needs no
cluster); every test patches that module-level ``_api`` with a ``MagicMock`` so
no real Kubernetes API is contacted. The additive ``POLICY_WRITER_DUMP_REGO``
local-dump toggle is covered here too (it never gates or replaces the CR write).

The body of ``POST`` / ``PUT /policy`` is a tagged policy model; each entry is one
CR (target side: each ``services[]`` SPM). The per-service delete takes the id with
the ``{service_id:path}`` converter: the library percent-encodes the slashes of a
clientId (``%2F``), and the server decodes them back before routing.
"""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from kubernetes.client import ApiException

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.pdp.policy.library.api import _service_id_segment
from aiac.pdp.service.policy.opa import main
from aiac.pdp.service.policy.opa.main import app
from aiac.policy.model.models import PolicyRule, ServicePolicyModel, TargetSidePolicyModel

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


def _target_side(*spms: ServicePolicyModel) -> dict:
    return TargetSidePolicyModel(services=list(spms)).model_dump(mode="json")


def _applied(api) -> list[dict]:
    """The CR bodies, in the order the writer server-side-applied them."""
    return [c.kwargs["body"] for c in api.patch_namespaced_custom_object.call_args_list]


def _policies(cr: dict) -> dict[str, str]:
    return {p["path"]: p["content"] for p in cr["spec"]["policies"]}


# ---------------------------------------------------------------------------
# POST /policy (target side) -> one server-side apply per SPM
# ---------------------------------------------------------------------------


class TestPostTargetSide:
    def test_tool_cr_is_server_side_applied(self, api):
        resp = TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
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
        TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
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
        resp = TestClient(app).post("/policy", json=_target_side(_spm(AGENT, ServiceType.AGENT)))
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
        body = _target_side(_spm(TOOL), _spm(AGENT, ServiceType.AGENT), _spm("team2/weather-tool"))
        resp = TestClient(app).post("/policy", json=body)
        assert resp.status_code == 204
        refs = [(cr["metadata"]["namespace"], cr["metadata"]["name"]) for cr in _applied(api)]
        assert refs == [("team1", "github-tool"), ("team1", "github-agent"), ("team2", "weather-tool")]

    def test_bad_id_is_400_naming_it_and_the_entries_before_stay_written(self, api):
        # "github-tool" has no derivable namespace.
        resp = TestClient(app).post("/policy", json=_target_side(_spm(TOOL), _spm("github-tool")))
        assert resp.status_code == 400
        assert "github-tool" in resp.json()["error"]
        assert [cr["metadata"]["name"] for cr in _applied(api)] == ["github-tool"]  # no rollback

    def test_api_exception_is_502(self, api):
        api.patch_namespaced_custom_object.side_effect = ApiException(status=500)
        resp = TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_empty_model_writes_nothing(self, api):
        resp = TestClient(app).post("/policy", json=_target_side())
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_not_called()


# ---------------------------------------------------------------------------
# PUT /policy -> upsert every entry, then delete every other labelled CR
# ---------------------------------------------------------------------------


def _listing(*refs: tuple[str, str]) -> dict:
    return {"items": [{"metadata": {"namespace": ns, "name": name, "labels": LABEL}} for ns, name in refs]}


def _deleted(api) -> list[tuple[str, str]]:
    return [(c.kwargs["namespace"], c.kwargs["name"]) for c in api.delete_namespaced_custom_object.call_args_list]


class TestPut:
    def test_deletes_the_stale_labelled_crs_and_keeps_the_entries(self, api):
        api.list_cluster_custom_object.return_value = _listing(
            ("team1", "github-tool"), ("team1", "old-agent"), ("team1", "github-agent"), ("team2", "gone-tool")
        )
        body = _target_side(_spm(TOOL), _spm(AGENT, ServiceType.AGENT))
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
        TestClient(app).put("/policy", json=_target_side(_spm(TOOL), _spm(AGENT, ServiceType.AGENT)))
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
        resp = TestClient(app).put("/policy", json=_target_side(_spm(TOOL), _spm(AGENT, ServiceType.AGENT)))
        assert resp.status_code == 502
        api.list_cluster_custom_object.assert_not_called()
        api.delete_namespaced_custom_object.assert_not_called()

    def test_a_bad_id_is_400_and_deletes_nothing(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        resp = TestClient(app).put("/policy", json=_target_side(_spm(TOOL), _spm("github-agent")))
        assert resp.status_code == 400
        assert "github-agent" in resp.json()["error"]
        api.delete_namespaced_custom_object.assert_not_called()

    def test_an_empty_model_deletes_every_labelled_cr(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team1", "github-agent"))
        resp = TestClient(app).put("/policy", json=_target_side())
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_not_called()
        assert sorted(_deleted(api)) == [("team1", "github-agent"), ("team1", "github-tool")]

    def test_a_concurrent_delete_404_is_success(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        api.delete_namespaced_custom_object.side_effect = ApiException(status=404)
        resp = TestClient(app).put("/policy", json=_target_side(_spm(TOOL)))
        assert resp.status_code == 204

    def test_a_failed_delete_is_502(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-agent"))
        api.delete_namespaced_custom_object.side_effect = ApiException(status=500)
        resp = TestClient(app).put("/policy", json=_target_side(_spm(TOOL)))
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

    def test_a_bad_id_is_400(self, api):
        resp = TestClient(app).delete("/policy/services/github-tool")
        assert resp.status_code == 400
        assert "github-tool" in resp.json()["error"]
        api.delete_namespaced_custom_object.assert_not_called()


@pytest.mark.parametrize("method", ["post", "delete"])
def test_the_per_agent_routes_are_retired(api, method):
    resp = getattr(TestClient(app), method)(f"/policy/agents/{_service_id_segment(AGENT)}")
    assert resp.status_code in (404, 405)
    api.patch_namespaced_custom_object.assert_not_called()
    api.delete_namespaced_custom_object.assert_not_called()


# ---------------------------------------------------------------------------
# The policy-model tag: a wrong or missing tag is a 422 (nothing is written)
# ---------------------------------------------------------------------------


_SERVICES = [_spm(TOOL).model_dump(mode="json")]


@pytest.mark.parametrize("method", ["post", "put"])
@pytest.mark.parametrize(
    "body",
    [
        {"services": _SERVICES},  # no tag
        {"enforcement_side": "both-sides", "services": _SERVICES},  # an unknown tag
        {"enforcement_side": "agent-side", "services": _SERVICES},  # the tag of another side
        {"agents": []},  # the retired per-agent shape (no tag)
    ],
    ids=["missing-tag", "unknown-tag", "other-side-tag", "retired-shape"],
)
def test_a_wrong_or_missing_tag_is_422(api, method, body):
    resp = getattr(TestClient(app), method)("/policy", json=body)
    assert resp.status_code == 422
    api.patch_namespaced_custom_object.assert_not_called()
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
        resp = TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_called_once()
        tree = dump / "team1" / "github-tool"
        assert "package authbridge.client.inbound.request" in (tree / "inbound" / "request.rego").read_text()
        assert (tree / "outbound" / "request.rego").read_text() == PASS_THROUGH_OUTBOUND

    def test_dump_off_writes_no_files_but_still_patches(self, api, tmp_path, monkeypatch):
        # Toggle unset (deleted by the api fixture); REGO_OUTPUT_DIR set but unused.
        monkeypatch.setenv("REGO_OUTPUT_DIR", str(tmp_path))
        resp = TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_called_once()
        assert list(tmp_path.rglob("*.rego")) == []

    def test_dump_os_error_maps_to_502(self, api, tmp_path, monkeypatch):
        # REGO_OUTPUT_DIR under a regular file -> mkdir raises OSError.
        blocker = tmp_path / "afile"
        blocker.write_text("x")
        monkeypatch.setenv("POLICY_WRITER_DUMP_REGO", "1")
        monkeypatch.setenv("REGO_OUTPUT_DIR", str(blocker / "out"))
        resp = TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
        assert resp.status_code == 502
        assert "error" in resp.json()
        # The SSA write happened before the additive dump failed.
        api.patch_namespaced_custom_object.assert_called_once()

    def test_dump_on_service_delete_removes_its_tree(self, api, dump):
        TestClient(app).post("/policy", json=_target_side(_spm(TOOL)))
        tree = dump / "team1" / "github-tool"
        assert tree.exists()
        resp = TestClient(app).delete(f"/policy/services/{_service_id_segment(TOOL)}")
        assert resp.status_code == 204
        assert not tree.exists()

    def test_dump_on_put_removes_the_stale_tree_and_keeps_the_entries(self, api, dump):
        TestClient(app).post("/policy", json=_target_side(_spm(TOOL), _spm(AGENT, ServiceType.AGENT)))
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team1", "github-agent"))
        resp = TestClient(app).put("/policy", json=_target_side(_spm(TOOL)))
        assert resp.status_code == 204
        assert (dump / "team1" / "github-tool").exists()
        assert not (dump / "team1" / "github-agent").exists()
