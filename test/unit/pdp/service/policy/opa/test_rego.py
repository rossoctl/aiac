"""Unit tests for aiac.pdp.service.policy.opa.rego (fixed packages, ALLOW/DENY).

Targets the CR renderer of a stored SPM (``render_target_side``): fixed package names
(``authbridge.client.{inbound,outbound}.request`` + ``import rego.v1``), the
nested ``input.identity`` / ``input.mcp`` shape, and de-prefixing (provisioned
``<owner>.<tool>`` scope names collapse to the bare ``input.mcp.params.name`` the
live plugin sends).

- **Tool inbound** (D26): the user gate and the calling-agent gate, the session
  messages, the self-discovery rule of checkpoint B1.
- **Agent inbound** (D26a, agent-level): the ``rossoctl`` platform bypass on the
  source gate, the deny-overrides ALLOW/DENY split, the effect-agnostic identity
  maps, and the DENY default for a pair that no rule mentions.
- No request without identity (D27), and the pass-through outbound (D24).

Scope maps are split symmetrically (``subject_role_allow_scopes`` / ``_deny_scopes``,
``source_role_allow_scopes`` / ``_deny_scopes``); the identity maps
(``subject_roles`` / ``source_roles``) keep their names.

The behavioural tests evaluate the rendered Rego with ``opa eval`` and skip
without ``opa`` on PATH. Expected verdicts are hand-written oracles, never read
back from the Rego under test.
"""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.pdp.service.policy.opa.rego import (
    ClientPolicies,
    generate_pass_through_rego,
    identity_ref,
    render_target_side,
)
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel

# Full SPIFFE id of the github-tool workload.
GH_TOOL = "spiffe://localtest.me/ns/team1/sa/github-tool"
# Full SPIFFE id of the github-agent workload.
GH_AGENT = "spiffe://localtest.me/ns/team1/sa/github-agent"


def _role(name: str = "reader") -> Role:
    return Role(id=f"role-{name}", name=name, composite=False)


def _scope(name: str = "read", service_id: str = "") -> Scope:
    return Scope(id=f"scope-{name}", name=name, serviceId=service_id)


def _rule(role: Role, scope: Scope, effect: RuleEffect = RuleEffect.ALLOW) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=effect)


# --- identity_ref ---


def test_identity_ref_spiffe():
    assert identity_ref("spiffe://localtest.me/ns/team1/sa/github-agent") == (
        "team1",
        "github-agent",
    )


def test_identity_ref_trust_domain_irrelevant():
    assert identity_ref("spiffe://other.example/ns/team1/sa/github-agent") == (
        "team1",
        "github-agent",
    )


def test_identity_ref_plain_ns_name():
    assert identity_ref("team1/github-agent") == ("team1", "github-agent")


def test_identity_ref_no_namespace_raises():
    with pytest.raises(ValueError):
        identity_ref("github-agent")


def test_identity_ref_invalid_label_raises():
    with pytest.raises(ValueError):
        identity_ref("Team1/GitHub-Agent")  # uppercase -> not a DNS-1123 label


def _assert_opa_allow(rego: str, query: str, input_doc: dict, expected: bool) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego)
        cmd = [
            shutil.which("opa"),
            "eval",
            "-f",
            "json",
            "-d",
            str(path),
            "--stdin-input",
            query,
        ]
        out = subprocess.run(
            cmd,
            input=json.dumps(input_doc),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        result = json.loads(out)["result"][0]["expressions"][0]["value"]
    assert result is expected, f"input={input_doc!r}"


_OUTBOUND = "data.authbridge.client.outbound.request.allow"
_INBOUND = "data.authbridge.client.inbound.request.allow"
_SESSION_METHODS = ("initialize", "notifications/initialized", "ping", "tools/list")


# =========================================================================== #
# The CR of a stored SPM (D18c, D24, D26, D26a, D27; checkpoint B1)           #
# =========================================================================== #
#
# The render input of a CR is the stored SPM of the callee. The writer does no
# join: every edge that the callee checks is already on its own SPM.


# --- the pass-through package (D24) -----------------------------------------

_PASS_THROUGH_OUTBOUND = "package authbridge.client.outbound.request\nimport rego.v1\n\nallow := true\n"


def test_pass_through_package_is_the_outbound_header_and_allow_true():
    assert generate_pass_through_rego() == _PASS_THROUGH_OUTBOUND


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "input_doc",
    [
        {},
        {"identity": {"subject": "dev-user", "service_id": GH_TOOL}, "mcp": {"method": "tools/call"}},
        {"identity": {"subject": "dev-user"}, "a2a": {"method": "message/send"}},
    ],
    ids=["no-identity", "mcp", "a2a"],
)
def test_pass_through_outbound_allows_every_request(input_doc):
    _assert_opa_allow(_PASS_THROUGH_OUTBOUND, _OUTBOUND, input_doc, True)


# --- the tool inbound package (D26, checkpoint B1) ---------------------------
#
# The tool's stored SPM, with the two gates keyed by the bare tool name:
#
#   user roles   developer (dev-user)    allow source-read, issues-read
#                tester (test-user)      allow issues-read, issues-write
#                sr-reader (mixed-user)  allow source-read
#                auditor (mixed-user)    DENY  source-read
#   agent roles  github-agent.ops        (github-agent) allow source-read, issues-read
#                other-agent.ops         (other-agent)  allow source-read, issues-read, issues-write
#                other-agent.restricted  (other-agent)  DENY  issues-read

OTHER_AGENT = "spiffe://localtest.me/ns/team1/sa/other-agent"


def _user_role(name: str, *users: str) -> Role:
    return Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.USER, actorIds=list(users))


def _agent_role(name: str, *agents: str) -> Role:
    return Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.AGENT, actorIds=list(agents))


def _tool_spm() -> ServicePolicyModel:
    source_read = _scope("github-tool.source-read", GH_TOOL)
    issues_read = _scope("github-tool.issues-read", GH_TOOL)
    issues_write = _scope("github-tool.issues-write", GH_TOOL)
    developer = _user_role("developer", "dev-user")
    tester = _user_role("tester", "test-user")
    sr_reader = _user_role("sr-reader", "mixed-user")
    auditor = _user_role("auditor", "mixed-user")
    gh_ops = _agent_role("github-agent.ops", GH_AGENT)
    other_ops = _agent_role("other-agent.ops", OTHER_AGENT)
    other_restricted = _agent_role("other-agent.restricted", OTHER_AGENT)
    return ServicePolicyModel(
        service_id=GH_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[source_read, issues_read, issues_write],
        inbound_allow_rules=[
            _rule(developer, source_read),
            _rule(developer, issues_read),
            _rule(tester, issues_read),
            _rule(tester, issues_write),
            _rule(sr_reader, source_read),
            _rule(gh_ops, source_read),
            _rule(gh_ops, issues_read),
            _rule(other_ops, source_read),
            _rule(other_ops, issues_read),
            _rule(other_ops, issues_write),
        ],
        inbound_deny_rules=[
            _rule(auditor, source_read, RuleEffect.DENY),
            _rule(other_restricted, issues_read, RuleEffect.DENY),
        ],
    )


def _tool_inbound() -> str:
    return render_target_side(_tool_spm()).inbound


def _call(tool: str) -> dict:
    return {"method": "tools/call", "params": {"name": tool}}


def _inbound_input(subject: str | None, client_id: str | None, mcp: dict) -> dict:
    identity = {}
    if subject is not None:
        identity["subject"] = subject
    if client_id is not None:
        identity["client_id"] = client_id
    return {"identity": identity, "mcp": mcp}


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "subject, client_id, tool, allowed",
    [
        ("dev-user", GH_AGENT, "source-read", True),  # both gates allow
        ("test-user", OTHER_AGENT, "issues-write", True),  # both gates allow
        ("dev-user", GH_AGENT, "issues-write", False),  # neither gate allows
        ("test-user", GH_AGENT, "issues-write", False),  # the user is granted, the calling agent is not
        ("dev-user", OTHER_AGENT, "issues-write", False),  # the calling agent is granted, the user is not
        ("mixed-user", GH_AGENT, "source-read", False),  # a user deny vetoes the user allow
        ("dev-user", OTHER_AGENT, "issues-read", False),  # a calling-agent deny vetoes its allow
        ("dev-user", None, "source-read", False),  # no calling agent (no bypass)
        ("dev-user", "rossoctl", "source-read", False),  # no platform-client bypass on a tool inbound
        ("dev-user", GH_AGENT, "delete-repo", False),  # not a tool of this service
    ],
    ids=[
        "granted",
        "granted-other-agent",
        "ungranted",
        "agent-gate-closed",
        "user-gate-closed",
        "user-deny-veto",
        "agent-deny-veto",
        "no-calling-agent",
        "platform-client",
        "unknown-tool",
    ],
)
def test_tool_inbound_tools_call_needs_both_gates_and_no_deny(subject, client_id, tool, allowed):
    _assert_opa_allow(_tool_inbound(), _INBOUND, _inbound_input(subject, client_id, _call(tool)), allowed)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("method", _SESSION_METHODS)
@pytest.mark.parametrize(
    "subject, client_id, allowed",
    [
        ("dev-user", GH_AGENT, True),  # source-read and issues-read pass both gates
        ("test-user", OTHER_AGENT, True),  # issues-write passes both gates
        ("mixed-user", GH_AGENT, False),  # the only allow (source-read) is vetoed by a user deny
        ("test-user", "spiffe://localtest.me/ns/team1/sa/unknown-agent", False),  # the agent holds no role
        ("guest", GH_AGENT, False),  # the user holds no role
        ("dev-user", None, False),  # no calling agent
        ("dev-user", "rossoctl", False),  # no platform-client bypass
    ],
    ids=["granted", "granted-other-agent", "vetoed", "unknown-agent", "no-roles", "no-calling-agent", "platform"],
)
def test_tool_inbound_session_methods_pass_only_for_a_granted_caller(method, subject, client_id, allowed):
    _assert_opa_allow(_tool_inbound(), _INBOUND, _inbound_input(subject, client_id, {"method": method}), allowed)


# The self-discovery rule (checkpoint B1): the UC-1 discovery token is minted as the tool's own
# client, so its client_id is the tool's clientId (the SPM service_id). It opens the session
# methods only, never tools/call.


def test_tool_inbound_renders_the_tool_client_id_as_self_client_id():
    assert f'self_client_id := "{GH_TOOL}"' in _tool_inbound()


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("method", _SESSION_METHODS)
@pytest.mark.parametrize("subject", [None, "guest"], ids=["no-subject", "no-roles"])
def test_tool_inbound_self_discovery_passes_the_session_methods(method, subject):
    _assert_opa_allow(_tool_inbound(), _INBOUND, _inbound_input(subject, GH_TOOL, {"method": method}), True)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("subject", [None, "dev-user"], ids=["no-subject", "granted-user"])
@pytest.mark.parametrize("mcp", [_call("source-read"), {"method": "resources/list"}], ids=["tools-call", "other"])
def test_tool_inbound_self_discovery_never_passes_other_methods(subject, mcp):
    _assert_opa_allow(_tool_inbound(), _INBOUND, _inbound_input(subject, GH_TOOL, mcp), False)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_tool_inbound_self_discovery_is_only_for_the_tool_itself():
    # Another tool's own client gets no session on this tool.
    other_tool = "spiffe://localtest.me/ns/team1/sa/other-tool"
    _assert_opa_allow(_tool_inbound(), _INBOUND, _inbound_input(None, other_tool, {"method": "tools/list"}), False)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "mcp",
    [
        {"method": "resources/list"},
        {"method": "prompts/list"},
        {"method": "resources/read", "params": {"uri": "file:///etc/passwd"}},
        # A granted tool name under a method that is not tools/call.
        {"method": "prompts/get", "params": {"name": "source-read"}},
        {"params": {"name": "source-read"}},  # no method at all
    ],
    ids=["resources-list", "prompts-list", "resources-read", "prompts-get-granted-name", "no-method"],
)
def test_tool_inbound_denies_every_other_mcp_method(mcp):
    _assert_opa_allow(_tool_inbound(), _INBOUND, _inbound_input("dev-user", GH_AGENT, mcp), False)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "input_doc",
    [
        {},
        {"mcp": _call("source-read")},
        {"mcp": {"method": "tools/list"}},
        {"identity": {}, "mcp": {"method": "initialize"}},
    ],
    ids=["nothing", "tools-call", "tools-list", "empty-identity"],
)
def test_tool_inbound_denies_a_request_without_identity(input_doc):
    # D27: jwt-validation lets its bypass paths through with no identity; OPA must deny them.
    _assert_opa_allow(_tool_inbound(), _INBOUND, input_doc, False)


def test_tool_inbound_known_good_lines():
    rego = _tool_inbound()
    assert rego.startswith("package authbridge.client.inbound.request\nimport rego.v1\n")
    # The bare MCP names of the tool's own scopes (de-prefixed).
    assert 'owned_tools := ["source-read", "issues-read", "issues-write"]' in rego
    assert 'subject_role_allow_scopes := {\n    "developer": ["source-read", "issues-read"],' in rego
    assert 'source_role_deny_scopes := {\n    "other-agent.restricted": ["issues-read"],\n}' in rego
    assert 'session_methods := {"initialize", "notifications/initialized", "ping", "tools/list"}' in rego
    assert rego.count("default allow := false") == 1
    assert 'allow if { input.mcp.method == "tools/call"; tool_ok(input.mcp.params.name) }' in rego
    assert "allow if { input.mcp.method in session_methods; some tool in owned_tools; tool_ok(tool) }" in rego
    assert "allow if { input.mcp.method in session_methods; input.identity.client_id == self_client_id }" in rego
    # The callee is the key: no target map, and no platform-client bypass.
    assert "input.identity.service_id" not in rego
    assert "rossoctl" not in rego


def test_tool_inbound_deprefix_fallbacks_survive_unchanged():
    """A scope with no owner (empty serviceId) and one whose name lacks the
    ``<owner>.`` prefix both survive unchanged — no crash, no partial strip."""
    spm = ServicePolicyModel(
        service_id=GH_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[
            _scope("github-tool.source-read", GH_TOOL),  # -> source-read
            _scope("already-bare", GH_TOOL),  # owner is github-tool, no prefix
            _scope("orphan", ""),  # no serviceId -> survives as "orphan"
        ],
    )
    assert 'owned_tools := ["source-read", "already-bare", "orphan"]' in render_target_side(spm).inbound


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_tool_inbound_escapes_its_keys_and_values():
    """The maps escape each key and value (no broken Rego)."""
    odd_user = _user_role('dev "x"\n', "alice")
    odd_agent = _agent_role('ops "y"\n', GH_AGENT)
    tool = _scope('github-tool.say-"hi"', GH_TOOL)
    spm = ServicePolicyModel(
        service_id=GH_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[tool],
        inbound_allow_rules=[_rule(odd_user, tool), _rule(odd_agent, tool)],
    )
    input_doc = _inbound_input("alice", GH_AGENT, _call('say-"hi"'))
    _assert_opa_allow(render_target_side(spm).inbound, _INBOUND, input_doc, True)


# --- the agent inbound package (D26a) ----------------------------------------
#
# The agent's stored SPM: two agent scopes; developer may use both, tester only issue_operations;
# the orchestrator agent may call the agent through source_operations.

ORCHESTRATOR = "spiffe://localtest.me/ns/team1/sa/orchestrator"


def _agent_spm() -> ServicePolicyModel:
    source_ops = _scope("github-agent.source_operations", GH_AGENT)
    issue_ops = _scope("github-agent.issue_operations", GH_AGENT)
    developer = _user_role("developer", "dev-user")
    tester = _user_role("tester", "test-user")
    orchestrator = _agent_role("orchestrator.ops", ORCHESTRATOR)
    return ServicePolicyModel(
        service_id=GH_AGENT,
        service_type=ServiceType.AGENT,
        owned_roles=[_agent_role("github-agent.ops", GH_AGENT)],
        owned_scopes=[source_ops, issue_ops],
        inbound_allow_rules=[
            _rule(developer, source_ops),
            _rule(developer, issue_ops),
            _rule(tester, issue_ops),
            _rule(orchestrator, source_ops),
        ],
    )


def _agent_inbound(platform_clients: tuple[str, ...] = ("rossoctl",)) -> str:
    return render_target_side(_agent_spm(), platform_clients=platform_clients).inbound


def test_agent_inbound_keeps_the_full_scope_names():
    rego = _agent_inbound()
    assert rego.startswith("package authbridge.client.inbound.request\nimport rego.v1\n")
    assert 'agent_scopes := ["github-agent.source_operations", "github-agent.issue_operations"]' in rego
    assert '"tester": ["github-agent.issue_operations"]' in rego
    assert "allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }" in rego
    # Not the tool package.
    assert "owned_tools" not in rego
    assert "tool_ok" not in rego


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "identity, allowed",
    [
        ({"subject": "dev-user"}, True),  # end-user traffic, no calling client
        ({"subject": "test-user"}, True),  # agent-level: an allow on any scope of the agent is enough
        ({"subject": "dev-user", "client_id": "rossoctl"}, True),  # the platform-client bypass
        ({"subject": "dev-user", "client_id": ORCHESTRATOR}, True),  # a calling agent that holds a role
        ({"subject": "dev-user", "client_id": OTHER_AGENT}, False),  # a calling agent with no role
        ({"subject": "guest"}, False),  # a user with no role
        ({"client_id": "rossoctl"}, False),  # D27: no subject
        ({"client_id": ORCHESTRATOR}, False),  # D27: no subject
        ({}, False),  # D27: no identity
    ],
    ids=[
        "user",
        "agent-level",
        "platform-client",
        "calling-agent",
        "unknown-agent",
        "no-roles",
        "platform-no-subject",
        "agent-no-subject",
        "no-identity",
    ],
)
def test_agent_inbound_is_agent_level_and_needs_identity(identity, allowed):
    # The A2A input has no skill ID, so the method does not change the decision.
    input_doc = {"identity": identity, "a2a": {"method": "message/send"}}
    _assert_opa_allow(_agent_inbound(), _INBOUND, input_doc, allowed)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_agent_inbound_platform_clients_come_from_the_caller():
    rego = _agent_inbound(platform_clients=("argocd",))
    _assert_opa_allow(rego, _INBOUND, {"identity": {"subject": "dev-user", "client_id": "argocd"}}, True)
    _assert_opa_allow(rego, _INBOUND, {"identity": {"subject": "dev-user", "client_id": "rossoctl"}}, False)


# --- the agent inbound: the package shape (D26a) -----------------------------
#
# A user role (``RoleKind.USER``) feeds the user gate and an agent role (``RoleKind.AGENT``) feeds
# the source gate (``project_inbound``). The agent scopes stay FULL (prefixed): the gates compare
# them internally, never against the bare invoked tool name.


def _agent_spm_with(
    owned_scopes: list[Scope] | None = None,
    allow: list[PolicyRule] | None = None,
    deny: list[PolicyRule] | None = None,
) -> ServicePolicyModel:
    """The SPM of github-agent with the given scopes and inbound edges."""
    return ServicePolicyModel(
        service_id=GH_AGENT,
        service_type=ServiceType.AGENT,
        owned_roles=[],
        owned_scopes=owned_scopes or [],
        inbound_allow_rules=allow or [],
        inbound_deny_rules=deny or [],
    )


def _inbound_of(spm: ServicePolicyModel, **kwargs) -> str:
    return render_target_side(spm, **kwargs).inbound


def test_agent_inbound_embeds_agent_scopes_list_full_names():
    # The agent scopes stay FULL (prefixed), also when they carry the owner's serviceId.
    scopes = [
        _scope("github-agent.source_operations", GH_AGENT),
        _scope("github-agent.issues_operations", GH_AGENT),
    ]
    rego = _inbound_of(_agent_spm_with(owned_scopes=scopes))
    assert 'agent_scopes := ["github-agent.source_operations", "github-agent.issues_operations"]' in rego


def test_agent_inbound_embeds_subject_roles_map():
    access = _scope("github-agent.access", GH_AGENT)
    developer = _user_role("developer", "dev-user")
    tester = _user_role("tester", "dev-user")
    rego = _inbound_of(_agent_spm_with([access], allow=[_rule(developer, access), _rule(tester, access)]))
    assert "subject_roles := {" in rego
    assert '"dev-user": ["developer", "tester"]' in rego


def test_agent_inbound_embeds_source_roles_map():
    access = _scope("github-agent.access", GH_AGENT)
    rego = _inbound_of(_agent_spm_with([access], allow=[_rule(_agent_role("reader", "github-tool"), access)]))
    assert "source_roles := {" in rego
    assert '"github-tool": ["reader"]' in rego


def test_agent_inbound_subject_role_allow_scopes_grouped_full_names():
    rego = _agent_inbound()
    assert "subject_role_allow_scopes := {" in rego
    assert '"developer": ["github-agent.source_operations", "github-agent.issue_operations"]' in rego
    assert '"tester": ["github-agent.issue_operations"]' in rego


def test_agent_inbound_split_scope_maps_from_split_edge_lists():
    """subject/source allow/deny scope maps each come from their own edge list (by kind and effect)."""
    access = _scope("access")
    spm = _agent_spm_with(
        [access],
        allow=[_rule(_user_role("developer", "dev-user"), access), _rule(_agent_role("src-ok", OTHER_AGENT), access)],
        deny=[
            _rule(_user_role("banned", "bad-user"), access, RuleEffect.DENY),
            _rule(_agent_role("src-bad", OTHER_AGENT), access, RuleEffect.DENY),
        ],
    )
    rego = _inbound_of(spm)
    assert 'subject_role_allow_scopes := {\n    "developer": ["access"],' in rego
    assert 'subject_role_deny_scopes := {\n    "banned": ["access"],' in rego
    assert 'source_role_allow_scopes := {\n    "src-ok": ["access"],' in rego
    assert 'source_role_deny_scopes := {\n    "src-bad": ["access"],' in rego


def test_agent_inbound_subject_gates_use_identity_fields():
    rego = _agent_inbound()
    assert "some role in object.get(subject_roles, input.identity.subject, [])" in rego
    assert "some scope in object.get(subject_role_allow_scopes, role, [])" in rego
    assert "some scope in object.get(subject_role_deny_scopes, role, [])" in rego
    assert "scope in agent_scopes" in rego


def test_agent_inbound_platform_bypass_default_rossoctl():
    rego = _inbound_of(_agent_spm())  # the default platform clients
    assert "source_allow_ok if { not input.identity.client_id }" in rego
    assert 'source_allow_ok if { input.identity.client_id == "rossoctl" }' in rego
    assert "some role in object.get(source_roles, input.identity.client_id, [])" in rego
    assert "some scope in object.get(source_role_allow_scopes, role, [])" in rego


def test_agent_inbound_platform_bypass_multiple_clients():
    rego = _agent_inbound(platform_clients=("rossoctl", "argocd"))
    assert 'source_allow_ok if { input.identity.client_id == "rossoctl" }' in rego
    assert 'source_allow_ok if { input.identity.client_id == "argocd" }' in rego


def test_agent_inbound_source_deny_gate_present():
    rego = _agent_inbound()
    assert "source_deny_ok if {" in rego
    assert "some scope in object.get(source_role_deny_scopes, role, [])" in rego


def test_agent_inbound_uses_only_nested_identity_input():
    rego = _agent_inbound()
    # Only the nested identity fields appear (no flat legacy input keys).
    assert "input.identity.subject" in rego
    assert "input.identity.client_id" in rego
    assert "input.subject" not in rego
    assert "input.source" not in rego


def test_agent_inbound_has_no_legacy_single_effect_identifiers():
    rego = _agent_inbound()
    # The pre-split single-effect names are gone (no alias / no back-compat).
    assert "\nrole_scopes :=" not in rego
    assert "subject_ok if" not in rego
    assert "source_ok if" not in rego


def test_agent_inbound_empty_spm_renders_valid_empty_literals():
    rego = _inbound_of(_agent_spm_with())
    assert "agent_scopes := []" in rego
    assert "subject_roles := {}" in rego
    assert "source_roles := {}" in rego
    assert "subject_role_allow_scopes := {}" in rego
    assert "subject_role_deny_scopes := {}" in rego
    assert "source_role_allow_scopes := {}" in rego
    assert "source_role_deny_scopes := {}" in rego
    assert "default allow := false" in rego
    assert "allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }" in rego


# --- the agent inbound: deny-overrides (D26a) --------------------------------


def _inbound_deny_spm() -> ServicePolicyModel:
    """A subject that holds an allow role and a deny role on the agent scope — deny-overrides must bar it."""
    access = _scope("github-agent.access", GH_AGENT)
    good = _user_role("good", "ok-user", "bad-user")
    banned = _user_role("banned", "bad-user")
    return _agent_spm_with([access], allow=[_rule(good, access)], deny=[_rule(banned, access, RuleEffect.DENY)])


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "subject, allowed",
    [
        ("ok-user", True),  # holds only the allow role
        ("bad-user", False),  # holds a deny role -> deny-overrides
    ],
)
def test_agent_inbound_deny_overrides_behavioural(subject: str, allowed: bool):
    _assert_opa_allow(_inbound_of(_inbound_deny_spm()), _INBOUND, {"identity": {"subject": subject}}, allowed)


def _inbound_source_deny_spm() -> ServicePolicyModel:
    """A fully-allowed subject paired with a source that both allows and denies the agent scope.
    The colliding source ALLOW+DENY must resolve deny-overrides via the ``source_deny_ok`` gate,
    barring the request even though the subject and the source's allow role both pass."""
    access = _scope("access")
    good = _user_role("good", "user1")
    src_ok = _agent_role("src-ok", "clean-src", "tainted-src")
    src_bad = _agent_role("src-bad", "tainted-src")
    return _agent_spm_with(
        [access],
        allow=[_rule(good, access), _rule(src_ok, access)],
        deny=[_rule(src_bad, access, RuleEffect.DENY)],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "source, allowed",
    [
        ("clean-src", True),  # source holds only the allow role -> passes
        ("tainted-src", False),  # source holds a colliding deny role -> source deny-overrides
    ],
)
def test_agent_inbound_source_deny_overrides_behavioural(source: str, allowed: bool):
    """Behavioural: a denied SOURCE wins over a colliding source ALLOW (and an allowed subject),
    exercising the ``source_allow_ok`` / ``source_deny_ok`` split on the source dimension."""
    input_doc = {"identity": {"subject": "user1", "client_id": source}}
    _assert_opa_allow(_inbound_of(_inbound_source_deny_spm()), _INBOUND, input_doc, allowed)


# --- the agent inbound: always DENY, no configurable default effect ----------
#
# A (role, scope) pair that NO rule mentions is always denied. The rules-based package emits
# exactly one decision shape: `default allow := false` plus one allow conjunction with inline
# `not …_deny_ok` guards. There is no permissive (`default allow := true`) branch.


def test_agent_inbound_decision_block_is_the_single_deny_default():
    rego = _agent_inbound()
    assert "default allow := false" in rego
    assert "allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }" in rego
    assert "default allow := true" not in rego
    assert "allow := false if" not in rego


def test_service_policy_model_has_no_default_effect():
    assert "default_effect" not in ServicePolicyModel.model_fields


@pytest.mark.parametrize("spm", [_agent_spm(), _tool_spm()], ids=["agent", "tool"])
def test_legacy_default_effect_allow_in_payload_is_ignored(spm):
    """A stored or posted SPM that still carries ``default_effect: Allow`` renders the DENY default
    on its inbound (the field is gone and ``extra="ignore"`` drops it)."""
    payload = spm.model_dump()
    payload["default_effect"] = RuleEffect.ALLOW.value
    policies = render_target_side(ServicePolicyModel.model_validate(payload))
    assert "default allow := false" in policies.inbound
    for rego in policies:
        assert "default allow := true" not in rego


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("subject", ["some-user", "nobody"], ids=["role-on-no-agent-scope", "no-roles"])
def test_agent_inbound_unmentioned_pair_is_denied(subject):
    """No rule gives a role of the subject a scope of this agent. some-user holds ``lonely``, whose
    only edge names a scope that the agent does not own; nobody holds no role."""
    access = _scope("github-agent.access", GH_AGENT)
    elsewhere = _scope("other-agent.access", OTHER_AGENT)
    lonely = _user_role("lonely", "some-user")
    rego = _inbound_of(_agent_spm_with([access], allow=[_rule(lonely, elsewhere)]))
    _assert_opa_allow(rego, _INBOUND, {"identity": {"subject": subject}}, False)


# An agent with no rules and no scopes. Under the DENY default its inbound denies every request —
# also end-user traffic that carries the ``rossoctl`` platform client. (A quarantine does not write
# such a CR: it deletes the CR, D20.)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "identity",
    [
        {"subject": "dev-user"},
        {"subject": "dev-user", "client_id": "rossoctl"},
        {"subject": "dev-user", "client_id": "spiffe://localtest.me/ns/team1/sa/other-agent"},
        {},
    ],
    ids=["end-user", "platform-client", "agent-client", "anonymous"],
)
def test_no_rules_agent_inbound_denies_every_request(identity):
    _assert_opa_allow(_inbound_of(_agent_spm_with()), _INBOUND, {"identity": identity}, False)


# --- the outbound of every service (D24) -------------------------------------


@pytest.mark.parametrize("spm", [_tool_spm(), _agent_spm()], ids=["tool", "agent"])
def test_every_outbound_is_the_pass_through(spm):
    assert render_target_side(spm).outbound == _PASS_THROUGH_OUTBOUND


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("spm", [_tool_spm(), _agent_spm()], ids=["tool", "agent"])
def test_the_outbound_allows_an_ungranted_call(spm):
    # No rule grants this call, but the outbound allows it: the callee decides.
    input_doc = {"identity": {"subject": "guest", "service_id": GH_TOOL}, "mcp": _call("delete-repo")}
    _assert_opa_allow(render_target_side(spm).outbound, _OUTBOUND, input_doc, True)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "subject, client_id, mcp, allowed",
    [
        (None, GH_TOOL, {"method": "tools/list"}, True),  # the self-discovery rule
        (None, GH_TOOL, _call("source-read"), False),  # never tools/call
        ("dev-user", GH_AGENT, {"method": "tools/list"}, False),  # no rules: no session for a caller
        ("dev-user", GH_AGENT, _call("source-read"), False),  # no rules: no tool for a caller
    ],
    ids=["self-tools-list", "self-tools-call", "caller-tools-list", "caller-tools-call"],
)
def test_zero_rule_tool_inbound_passes_only_self_discovery(subject, client_id, mcp, allowed):
    # The bootstrap CR of a first onboarding (checkpoint B1): a zero-rule SPM.
    spm = ServicePolicyModel(
        service_id=GH_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[_scope("github-tool.source-read", GH_TOOL)],
    )
    _assert_opa_allow(render_target_side(spm).inbound, _INBOUND, _inbound_input(subject, client_id, mcp), allowed)


# =========================================================================== #
# Empty maps: every map is read with object.get (OPA 1.21)                    #
# =========================================================================== #
#
# An empty map renders as ``{}``. OPA 1.21 types ``{}`` as an object with no keys, so a direct
# index ``m[key]`` into it is a type error that stops the whole bundle from activating (the
# sidecar then denies every request). The writer reads every map with ``object.get``.


def _empty_map_policies() -> dict[str, ClientPolicies]:
    """The CRs whose maps are all empty: a zero-rule agent and tool."""
    agent_spm = ServicePolicyModel(
        service_id=GH_AGENT,
        service_type=ServiceType.AGENT,
        owned_roles=[],
        owned_scopes=[_scope("github-agent.source_operations", GH_AGENT)],
    )
    tool_spm = ServicePolicyModel(
        service_id=GH_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[_scope("github-tool.source-read", GH_TOOL)],
    )
    # The bootstrap CR of a tool before discovery: it owns no tool yet (owned_tools := []).
    bootstrap_tool_spm = ServicePolicyModel(
        service_id=GH_TOOL, service_type=ServiceType.TOOL, owned_roles=[], owned_scopes=[]
    )
    return {
        "agent": render_target_side(agent_spm),
        "tool": render_target_side(tool_spm),
        "bootstrap-tool": render_target_side(bootstrap_tool_spm),
    }


def _declared_maps(rego: str) -> list[str]:
    return re.findall(r"^(\w+) := \{", rego, flags=re.MULTILINE)


@pytest.mark.parametrize(
    "policies",
    list(_empty_map_policies().values()),
    ids=list(_empty_map_policies()),
)
def test_no_rule_indexes_a_declared_map(policies):
    # A direct index works only while the map has a key; object.get works on an empty map too.
    for rego in policies:
        for name in _declared_maps(rego):
            assert not re.search(rf"\b{name}\[", rego), f"{name} is indexed directly:\n{rego}"


def test_no_rule_loops_over_an_empty_list():
    # OPA 1.21 also rejects a loop over an empty array literal (some x in []); membership is fine.
    rego = _empty_map_policies()["bootstrap-tool"].inbound
    assert "owned_tools := []" in rego
    assert "some tool in owned_tools" not in rego
    # The self-discovery rule stays: the bootstrap CR exists for the discovery call.
    assert "input.identity.client_id == self_client_id" in rego


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    ("subject", "client_id", "mcp", "allowed"),
    [
        (None, GH_TOOL, {"method": "tools/list"}, True),  # self-discovery
        (None, GH_TOOL, _call("source-read"), False),  # never tools/call
        ("dev-user", GH_AGENT, {"method": "tools/list"}, False),  # no tool: no session for a caller
    ],
    ids=["self-tools-list", "self-tools-call", "caller-tools-list"],
)
def test_bootstrap_tool_with_no_tools_passes_only_self_discovery(subject, client_id, mcp, allowed):
    rego = _empty_map_policies()["bootstrap-tool"].inbound
    _assert_opa_allow(rego, _INBOUND, _inbound_input(subject, client_id, mcp), allowed)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("name", list(_empty_map_policies()))
def test_empty_map_packages_pass_opa_check(name):
    # With OPA 1.21 or later on the PATH, a direct index into {} fails here (rego_type_error).
    with tempfile.TemporaryDirectory() as tmp:
        for i, rego in enumerate(_empty_map_policies()[name]):
            (Path(tmp) / f"p{i}.rego").write_text(rego)
        result = subprocess.run([shutil.which("opa"), "check", tmp], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
