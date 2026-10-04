"""Unit tests for aiac.pdp.service.policy.opa.main — the writer HTTP API (D18c).

Targets the always-on Custom Resource writer. The module builds a
``CustomObjectsApi`` at import (kube-config load is guarded, so import needs no
cluster); every test patches that module-level ``_api`` with a ``MagicMock`` so
no real Kubernetes API is contacted. The additive ``POLICY_WRITER_DUMP_REGO``
local-dump toggle is covered here too (it never gates or replaces the CR write).

The body of ``POST`` / ``PUT /policy`` is a tagged policy model; each entry is one
CR (target side: each ``services[]`` SPM; agent side: each ``agents[]`` APM and each
``pass_through[]`` tool id). A wrong or missing tag, a body that mixes the sides, and
an agent that is also a pass-through are 422. The per-service delete takes the id
with the ``{service_id:path}`` converter: the library percent-encodes the slashes of
a clientId (``%2F``), and the server decodes them back before routing.

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
from aiac.policy.model.models import (
    AgentPolicyModel,
    AgentSidePolicyModel,
    PolicyRule,
    ServicePolicyModel,
    TargetSidePolicyModel,
)

TOOL = "spiffe://localtest.me/ns/team1/sa/github-tool"
AGENT = "spiffe://localtest.me/ns/team1/sa/github-agent"
LABEL = {"app.kubernetes.io/managed-by": "aiac-pdp-policy-writer"}
PASS_THROUGH_INBOUND = "package authbridge.client.inbound.request\nimport rego.v1\n\nallow := true\n"
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


def _apm(agent_id: str) -> AgentPolicyModel:
    """dev-user (role developer) may call the agent (its one agent scope) and, through it, the tool
    ``source-read`` of github-tool. No other grant."""
    owner = agent_id.rsplit("/", 1)[-1]
    agent_scope = Scope(id=f"{owner}-ops", name=f"{owner}.source_operations", serviceId=agent_id)
    tool_scope = Scope(id="github-tool-s1", name="github-tool.source-read", serviceId=TOOL)
    developer = Role(id="developer", name="developer", composite=False, kind=RoleKind.USER, actorIds=["dev-user"])
    return AgentPolicyModel(
        agent_id=agent_id,
        agent_roles=[],
        agent_scopes=[agent_scope],
        subject_roles={"dev-user": [developer]},
        source_roles={},
        target_allow_scopes={TOOL: [tool_scope]},
        inbound_subject_allow_rules=[PolicyRule(role=developer, scope=agent_scope)],
        outbound_subject_allow_rules=[PolicyRule(role=developer, scope=tool_scope)],
    )


def _agent_side(*apms: AgentPolicyModel, pass_through: tuple[str, ...] = ()) -> dict:
    return AgentSidePolicyModel(agents=list(apms), pass_through=list(pass_through)).model_dump(mode="json")


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
# POST /policy (agent side) -> one agent CR per APM, one pass-through CR per tool
# ---------------------------------------------------------------------------


class TestPostAgentSide:
    def test_agent_cr_has_the_agent_inbound_and_the_agent_outbound(self, api, monkeypatch):
        monkeypatch.setenv("PLATFORM_SOURCE_CLIENTS", "rossoctl,argocd")
        resp = TestClient(app).post("/policy", json=_agent_side(_apm(AGENT)))
        assert resp.status_code == 204
        (cr,) = _applied(api)
        assert cr["metadata"] == {"name": "github-agent", "namespace": "team1", "labels": LABEL}
        assert cr["spec"]["scope"] == "client"
        assert cr["spec"]["clientID"] == "github-agent"
        assert [p["path"] for p in cr["spec"]["policies"]] == ["inbound/request.rego", "outbound/request.rego"]
        policies = _policies(cr)
        inbound = policies["inbound/request.rego"]
        # The agent inbound (agent-level): the full scope names and the platform-client bypass.
        assert inbound.startswith("package authbridge.client.inbound.request\nimport rego.v1\n")
        assert 'agent_scopes := ["github-agent.source_operations"]' in inbound
        assert 'source_allow_ok if { input.identity.client_id == "argocd" }' in inbound
        outbound = policies["outbound/request.rego"]
        # The agent outbound: the per-tool checks (the full target id, the bare tool name) and the
        # MCP session rule.
        assert outbound.startswith("package authbridge.client.outbound.request\nimport rego.v1\n")
        assert f'    "{TOOL}": ["source-read"],' in outbound
        assert 'session_methods := {"initialize", "notifications/initialized", "ping", "tools/list"}' in outbound
        assert "default allow := false" in outbound

    def test_each_pass_through_id_gets_a_pass_through_cr(self, api):
        resp = TestClient(app).post("/policy", json=_agent_side(pass_through=(TOOL, "team2/weather-tool")))
        assert resp.status_code == 204
        crs = _applied(api)
        assert [cr["metadata"] for cr in crs] == [
            {"name": "github-tool", "namespace": "team1", "labels": LABEL},
            {"name": "weather-tool", "namespace": "team2", "labels": LABEL},
        ]
        for cr in crs:
            assert cr["spec"]["scope"] == "client"
            assert cr["spec"]["clientID"] == cr["metadata"]["name"]
            assert _policies(cr) == {
                "inbound/request.rego": PASS_THROUGH_INBOUND,
                "outbound/request.rego": PASS_THROUGH_OUTBOUND,
            }

    def test_batch_writes_the_agent_crs_then_the_pass_through_crs_in_order(self, api):
        body = _agent_side(_apm(AGENT), _apm("team2/weather-agent"), pass_through=(TOOL, "team2/weather-tool"))
        resp = TestClient(app).post("/policy", json=body)
        assert resp.status_code == 204
        refs = [(cr["metadata"]["namespace"], cr["metadata"]["name"]) for cr in _applied(api)]
        assert refs == [
            ("team1", "github-agent"),
            ("team2", "weather-agent"),
            ("team1", "github-tool"),
            ("team2", "weather-tool"),
        ]

    @pytest.mark.parametrize(
        "body",
        [
            _agent_side(_apm(AGENT), _apm("github-agent")),
            _agent_side(_apm(AGENT), pass_through=("github-agent",)),
        ],
        ids=["agent-id", "pass-through-id"],
    )
    def test_bad_id_is_400_naming_it_and_the_entries_before_stay_written(self, api, body):
        # "github-agent" has no derivable namespace.
        resp = TestClient(app).post("/policy", json=body)
        assert resp.status_code == 400
        assert "github-agent" in resp.json()["error"]
        assert [cr["metadata"]["name"] for cr in _applied(api)] == ["github-agent"]  # no rollback

    def test_empty_model_writes_nothing(self, api):
        resp = TestClient(app).post("/policy", json=_agent_side())
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


def _tool_call(subject: str, tool: str, target: str = TOOL) -> dict:
    return {
        "identity": {"subject": subject, "service_id": target},
        "mcp": {"method": "tools/call", "params": {"name": tool}},
    }


# The verdicts that the spec gives for the CRs of the agent-side body {agents: [github-agent],
# pass_through: [github-tool]}, where dev-user (developer) may call github-agent and, through it,
# github-tool's source-read; nothing else is granted.
_AGENT_SIDE_VERDICTS = [
    # the agent outbound: the per-tool checks
    ("github-agent", "outbound", _tool_call("dev-user", "source-read"), True),
    ("github-agent", "outbound", _tool_call("dev-user", "issues-read"), False),
    ("github-agent", "outbound", _tool_call("test-user", "source-read"), False),
    (
        "github-agent",
        "outbound",
        _tool_call("dev-user", "source-read", "spiffe://localtest.me/ns/team1/sa/other-tool"),
        False,
    ),
    # the agent outbound: the MCP session rule
    (
        "github-agent",
        "outbound",
        {"identity": {"subject": "dev-user", "service_id": TOOL}, "mcp": {"method": "tools/list"}},
        True,
    ),
    (
        "github-agent",
        "outbound",
        {"identity": {"subject": "test-user", "service_id": TOOL}, "mcp": {"method": "initialize"}},
        False,
    ),
    # the agent outbound: the known limit (b435aa1) — A2A and LLM calls are denied
    (
        "github-agent",
        "outbound",
        {"identity": {"subject": "dev-user", "service_id": TOOL}, "a2a": {"method": "message/send"}},
        False,
    ),
    ("github-agent", "outbound", {"identity": {"subject": "dev-user", "service_id": TOOL}}, False),
    # the agent inbound (agent-level): a granted user, the platform client; no role or no identity is denied
    ("github-agent", "inbound", {"identity": {"subject": "dev-user"}, "a2a": {"method": "message/send"}}, True),
    ("github-agent", "inbound", {"identity": {"subject": "dev-user", "client_id": "rossoctl"}}, True),
    ("github-agent", "inbound", {"identity": {"subject": "test-user"}, "a2a": {"method": "message/send"}}, False),
    ("github-agent", "inbound", {}, False),
    # the pass-through CR of the tool: both tiers allow every request (D24)
    ("github-tool", "inbound", {}, True),
    (
        "github-tool",
        "inbound",
        {
            "identity": {"subject": "test-user", "client_id": AGENT},
            "mcp": {"method": "tools/call", "params": {"name": "issues-write"}},
        },
        True,
    ),
    ("github-tool", "outbound", {}, True),
    ("github-tool", "outbound", {"identity": {"subject": "test-user"}, "a2a": {"method": "message/send"}}, True),
]


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("cr_name, tier, input_doc, allowed", _AGENT_SIDE_VERDICTS)
def test_agent_side_crs_end_to_end(api, cr_name, tier, input_doc, allowed):
    # The Rego under test is the CR content that the writer applied, not a generator output.
    resp = TestClient(app).post("/policy", json=_agent_side(_apm(AGENT), pass_through=(TOOL,)))
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

    def test_agent_side_keeps_the_agent_and_pass_through_crs_and_deletes_the_rest(self, api):
        # A side change: github-tool still has its target-side CR. The PUT writes it again as a
        # pass-through CR (spec.policies is atomic, so one write replaces both packages) and never
        # deletes it; only the CRs that are in no entry go.
        api.list_cluster_custom_object.return_value = _listing(
            ("team1", "github-agent"), ("team1", "github-tool"), ("team1", "old-tool"), ("team2", "gone-agent")
        )
        resp = TestClient(app).put("/policy", json=_agent_side(_apm(AGENT), pass_through=(TOOL,)))
        assert resp.status_code == 204
        agent_cr, tool_cr = _applied(api)
        assert (agent_cr["metadata"]["name"], tool_cr["metadata"]["name"]) == ("github-agent", "github-tool")
        assert _policies(agent_cr)["outbound/request.rego"] != PASS_THROUGH_OUTBOUND
        assert _policies(tool_cr) == {
            "inbound/request.rego": PASS_THROUGH_INBOUND,
            "outbound/request.rego": PASS_THROUGH_OUTBOUND,
        }
        assert sorted(_deleted(api)) == [("team1", "old-tool"), ("team2", "gone-agent")]

    def test_agent_side_bad_id_is_400_and_deletes_nothing(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "old-tool"))
        resp = TestClient(app).put("/policy", json=_agent_side(_apm(AGENT), pass_through=("github-tool",)))
        assert resp.status_code == 400
        assert "github-tool" in resp.json()["error"]
        api.delete_namespaced_custom_object.assert_not_called()

    def test_an_empty_agent_side_model_deletes_every_labelled_cr(self, api):
        api.list_cluster_custom_object.return_value = _listing(("team1", "github-tool"), ("team1", "github-agent"))
        resp = TestClient(app).put("/policy", json=_agent_side())
        assert resp.status_code == 204
        api.patch_namespaced_custom_object.assert_not_called()
        assert sorted(_deleted(api)) == [("team1", "github-agent"), ("team1", "github-tool")]


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
# The policy-model tag: a wrong or missing tag, or a body that mixes the sides, is a 422
# (nothing is written, nothing is deleted)
# ---------------------------------------------------------------------------


_SERVICES = [_spm(TOOL).model_dump(mode="json")]
_AGENTS = [_apm(AGENT).model_dump(mode="json")]


def _assert_nothing_changed(api) -> None:
    api.patch_namespaced_custom_object.assert_not_called()
    api.list_cluster_custom_object.assert_not_called()
    api.delete_namespaced_custom_object.assert_not_called()


# The plain discriminated union (no Body wrapper) rejects these bodies: the tag is mandatory.
@pytest.mark.parametrize("method", ["post", "put"])
@pytest.mark.parametrize(
    "body",
    [
        {"services": _SERVICES},  # no tag
        {"agents": _AGENTS, "pass_through": [TOOL]},  # no tag
        {"enforcement_side": "both-sides", "services": _SERVICES},  # an unknown tag
        {"enforcement_side": "agent-side", "services": _SERVICES},  # the tag of another side
        {"enforcement_side": "target-side", "agents": _AGENTS},  # the tag of another side
        {"agents": []},  # the retired per-agent shape (no tag)
    ],
    ids=[
        "missing-tag-target",
        "missing-tag-agent",
        "unknown-tag",
        "agent-tag-on-services",
        "target-tag-on-agents",
        "retired-shape",
    ],
)
def test_a_wrong_or_missing_tag_is_422(api, method, body):
    resp = getattr(TestClient(app), method)("/policy", json=body)
    assert resp.status_code == 422
    _assert_nothing_changed(api)


@pytest.mark.parametrize("method", ["post", "put"])
@pytest.mark.parametrize(
    "body",
    [
        {"enforcement_side": "agent-side", "agents": _AGENTS, "pass_through": [TOOL], "services": _SERVICES},
        {"enforcement_side": "agent-side", "agents": [], "services": []},
        {"enforcement_side": "target-side", "services": _SERVICES, "agents": _AGENTS},
        {"enforcement_side": "target-side", "services": _SERVICES, "pass_through": [TOOL]},
    ],
    ids=[
        "agent-side-with-services",
        "agent-side-with-empty-services",
        "target-side-with-agents",
        "target-side-with-pass-through",
    ],
)
def test_a_body_that_mixes_the_sides_is_422(api, method, body):
    # The models ignore unknown fields, so without this check the entries of the other side would be
    # dropped without a word, and a PUT would then delete their CRs.
    resp = getattr(TestClient(app), method)("/policy", json=body)
    assert resp.status_code == 422
    _assert_nothing_changed(api)


@pytest.mark.parametrize("method", ["post", "put"])
def test_an_agent_that_is_also_a_pass_through_is_422(api, method):
    # Fail closed: a pass-through CR must never replace the agent CR of the same service.
    body = {"enforcement_side": "agent-side", "agents": _AGENTS, "pass_through": [TOOL, AGENT]}
    resp = getattr(TestClient(app), method)("/policy", json=body)
    assert resp.status_code == 422
    assert AGENT in resp.text
    _assert_nothing_changed(api)


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
