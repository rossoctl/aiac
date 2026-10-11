"""Unit tests for aiac.pdp.service.policy.opa.rego (fixed packages, ALLOW/DENY).

Targets the generators of both sides: fixed package names
(``authbridge.client.{inbound,outbound}.request`` + ``import rego.v1``), the
nested ``input.identity`` / ``input.mcp`` shape, and de-prefixing (provisioned
``<owner>.<tool>`` scope names collapse to the bare ``input.mcp.params.name`` the
live plugin sends).

- **Agent side** (an APM, ``render_agent_side``; a managed tool,
  ``render_pass_through``): the agent inbound (the ``rossoctl`` platform bypass)
  and the agent outbound (per-tool checks and the MCP session rule, each per target —
  LIM-02; the known limit that A2A and LLM calls are denied), with the
  deny-overrides ALLOW/DENY split; the
  pass-through CR of a managed tool (D24), which allows every request on both tiers. Scope maps are split symmetrically
  (``subject_role_allow_scopes`` / ``_deny_scopes``, ``source_role_allow_scopes`` /
  ``_deny_scopes``, ``target_allow_scopes`` / ``target_deny_scopes``); the identity
  maps (``subject_roles`` / ``source_roles`` / ``agent_roles``) keep their names.
- **Target side** (a stored SPM, ``render_target_side``): the tool inbound (D26:
  the user gate and the calling-agent gate, the session messages, the
  self-discovery rule of checkpoint B1), the agent inbound (D26a, agent-level),
  no request without identity (D27), and the pass-through outbound (D24).

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
    generate_inbound_rego,
    generate_outbound_rego,
    generate_pass_through_rego,
    identity_ref,
    render_agent_side,
    render_pass_through,
    render_target_side,
)
from aiac.policy.model.models import AgentPolicyModel, PolicyRule, RuleEffect, ServicePolicyModel

# Full SPIFFE id of the github-tool workload that owns the outbound scopes.
GH_TOOL = "spiffe://localtest.me/ns/team1/sa/github-tool"
# The agent whose policy we render.
GH_AGENT = "spiffe://localtest.me/ns/team1/sa/github-agent"


def _role(name: str = "reader") -> Role:
    return Role(id=f"role-{name}", name=name, composite=False)


def _scope(name: str = "read", service_id: str = "") -> Scope:
    return Scope(id=f"scope-{name}", name=name, serviceId=service_id)


def _rule(role: Role, scope: Scope, effect: RuleEffect = RuleEffect.ALLOW) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=effect)


def _model(
    agent_id: str = "team1/weather-agent",
    agent_roles: list[Role] | None = None,
    agent_scopes: list[Scope] | None = None,
    subject_roles: dict[str, list[Role]] | None = None,
    source_roles: dict[str, list[Role]] | None = None,
    target_allow_scopes: dict[str, list[Scope]] | None = None,
    target_deny_scopes: dict[str, list[Scope]] | None = None,
    inbound_subject_allow_rules: list[PolicyRule] | None = None,
    inbound_subject_deny_rules: list[PolicyRule] | None = None,
    inbound_source_allow_rules: list[PolicyRule] | None = None,
    inbound_source_deny_rules: list[PolicyRule] | None = None,
    outbound_target_allow_rules: list[PolicyRule] | None = None,
    outbound_target_deny_rules: list[PolicyRule] | None = None,
    outbound_subject_allow_rules: list[PolicyRule] | None = None,
    outbound_subject_deny_rules: list[PolicyRule] | None = None,
) -> AgentPolicyModel:
    return AgentPolicyModel(
        agent_id=agent_id,
        agent_roles=agent_roles or [],
        agent_scopes=agent_scopes or [],
        subject_roles=subject_roles or {},
        source_roles=source_roles or {},
        target_allow_scopes=target_allow_scopes or {},
        target_deny_scopes=target_deny_scopes or {},
        inbound_subject_allow_rules=inbound_subject_allow_rules or [],
        inbound_subject_deny_rules=inbound_subject_deny_rules or [],
        inbound_source_allow_rules=inbound_source_allow_rules or [],
        inbound_source_deny_rules=inbound_source_deny_rules or [],
        outbound_target_allow_rules=outbound_target_allow_rules or [],
        outbound_target_deny_rules=outbound_target_deny_rules or [],
        outbound_subject_allow_rules=outbound_subject_allow_rules or [],
        outbound_subject_deny_rules=outbound_subject_deny_rules or [],
    )


def _github_agent() -> AgentPolicyModel:
    """The worked example (allow-only).

    Inbound agent scopes are prefixed by the *agent* (``github-agent.*``) and are
    **not** de-prefixed — inbound compares scopes internally, never against the
    invoked tool name. Outbound tool scopes are prefixed by the *tool*
    (``github-tool.*``) and carry ``serviceId`` so they de-prefix to the bare tool
    names the live plugin puts in ``input.mcp.params.name``.
    """
    developer = _role("developer")
    tester = _role("tester")
    source_helper = _role("source-helper")
    issues_helper = _role("issues-helper")
    # Inbound audience scopes — agent-owned, prefixed, NOT de-prefixed.
    source_access = _scope("github-agent.source_operations")
    issues_access = _scope("github-agent.issues_operations")
    # Outbound tool scopes — tool-owned, prefixed AND carrying serviceId.
    source_read = _scope("github-tool.source-read", GH_TOOL)
    source_write = _scope("github-tool.source-write", GH_TOOL)
    issues_read = _scope("github-tool.issues-read", GH_TOOL)
    issues_write = _scope("github-tool.issues-write", GH_TOOL)
    return _model(
        agent_id=GH_AGENT,
        agent_roles=[source_helper, issues_helper],
        agent_scopes=[source_access, issues_access],
        subject_roles={"dev-user": [developer], "test-user": [tester]},
        source_roles={"github-tool": [_role("reader")]},
        # target_allow_scopes keyed by the FULL tool service id.
        target_allow_scopes={GH_TOOL: [source_read, source_write, issues_read, issues_write]},
        inbound_subject_allow_rules=[
            _rule(developer, source_access),
            _rule(developer, issues_access),
            _rule(tester, issues_access),
        ],
        outbound_target_allow_rules=[
            _rule(source_helper, source_read),
            _rule(source_helper, source_write),
            _rule(issues_helper, issues_read),
            _rule(issues_helper, issues_write),
        ],
        outbound_subject_allow_rules=[
            _rule(developer, source_read),
            _rule(developer, source_write),
            _rule(developer, issues_read),
            _rule(tester, issues_read),
            _rule(tester, issues_write),
        ],
    )


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


# --- generate_inbound_rego ---


def test_inbound_has_fixed_package_header():
    rego = generate_inbound_rego(_model())
    assert "package authbridge.client.inbound.request" in rego
    assert "import rego.v1" in rego


def test_inbound_embeds_agent_scopes_list_full_names():
    # Inbound audience scopes stay FULL (prefixed) — they are compared internally
    # against the scope maps, never against the bare invoked tool name.
    model = _model(
        agent_scopes=[
            _scope("github-agent.source_operations"),
            _scope("github-agent.issues_operations"),
        ]
    )
    rego = generate_inbound_rego(model)
    assert 'agent_scopes := ["github-agent.source_operations", "github-agent.issues_operations"]' in rego


def test_inbound_embeds_subject_roles_map():
    model = _model(subject_roles={"dev-user": [_role("developer"), _role("tester")]})
    rego = generate_inbound_rego(model)
    assert "subject_roles := {" in rego
    assert '"dev-user": ["developer", "tester"]' in rego


def test_inbound_embeds_source_roles_map():
    model = _model(source_roles={"github-tool": [_role("reader")]})
    rego = generate_inbound_rego(model)
    assert "source_roles := {" in rego
    assert '"github-tool": ["reader"]' in rego


def test_inbound_subject_role_allow_scopes_grouped_full_names():
    rego = generate_inbound_rego(_github_agent())
    assert "subject_role_allow_scopes := {" in rego
    assert '"developer": ["github-agent.source_operations", "github-agent.issues_operations"]' in rego
    assert '"tester": ["github-agent.issues_operations"]' in rego


def test_inbound_split_scope_maps_from_split_rule_lists():
    """subject/source allow/deny scope maps each come from their own rule list."""
    dev = _role("developer")
    banned = _role("banned")
    src_ok = _role("src-ok")
    src_bad = _role("src-bad")
    access = _scope("access")
    model = _model(
        agent_scopes=[access],
        inbound_subject_allow_rules=[_rule(dev, access)],
        inbound_subject_deny_rules=[_rule(banned, access, RuleEffect.DENY)],
        inbound_source_allow_rules=[_rule(src_ok, access)],
        inbound_source_deny_rules=[_rule(src_bad, access, RuleEffect.DENY)],
    )
    rego = generate_inbound_rego(model)
    assert 'subject_role_allow_scopes := {\n    "developer": ["access"],' in rego
    assert 'subject_role_deny_scopes := {\n    "banned": ["access"],' in rego
    assert 'source_role_allow_scopes := {\n    "src-ok": ["access"],' in rego
    assert 'source_role_deny_scopes := {\n    "src-bad": ["access"],' in rego


def test_inbound_subject_gates_use_identity_fields():
    rego = generate_inbound_rego(_github_agent())
    assert "some role in object.get(subject_roles, input.identity.subject, [])" in rego
    assert "some scope in object.get(subject_role_allow_scopes, role, [])" in rego
    assert "some scope in object.get(subject_role_deny_scopes, role, [])" in rego
    assert "scope in agent_scopes" in rego


def test_inbound_platform_bypass_default_rossoctl():
    rego = generate_inbound_rego(_github_agent())
    assert "source_allow_ok if { not input.identity.client_id }" in rego
    assert 'source_allow_ok if { input.identity.client_id == "rossoctl" }' in rego
    assert "some role in object.get(source_roles, input.identity.client_id, [])" in rego
    assert "some scope in object.get(source_role_allow_scopes, role, [])" in rego


def test_inbound_platform_bypass_multiple_clients():
    rego = generate_inbound_rego(_github_agent(), platform_clients=("rossoctl", "argocd"))
    assert 'source_allow_ok if { input.identity.client_id == "rossoctl" }' in rego
    assert 'source_allow_ok if { input.identity.client_id == "argocd" }' in rego


def test_inbound_source_deny_gate_present():
    rego = generate_inbound_rego(_github_agent())
    assert "source_deny_ok if {" in rego
    assert "some scope in object.get(source_role_deny_scopes, role, [])" in rego


def test_inbound_has_default_deny_and_deny_overrides_allow():
    rego = generate_inbound_rego(_github_agent())
    assert "default allow := false" in rego
    assert "allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }" in rego


def test_inbound_uses_only_nested_identity_input():
    rego = generate_inbound_rego(_github_agent())
    # Only the nested identity fields appear (no flat legacy input keys).
    assert "input.identity.subject" in rego
    assert "input.identity.client_id" in rego
    assert "input.subject" not in rego
    assert "input.source" not in rego


def test_inbound_has_no_legacy_single_effect_identifiers():
    rego = generate_inbound_rego(_github_agent())
    # The pre-split single-effect names are gone (no alias / no back-compat).
    assert "\nrole_scopes :=" not in rego
    assert "subject_ok if" not in rego
    assert "source_ok if" not in rego


def test_inbound_empty_model_renders_valid_empty_literals():
    rego = generate_inbound_rego(_model())
    assert "agent_scopes := []" in rego
    assert "subject_roles := {}" in rego
    assert "source_roles := {}" in rego
    assert "subject_role_allow_scopes := {}" in rego
    assert "subject_role_deny_scopes := {}" in rego
    assert "source_role_allow_scopes := {}" in rego
    assert "source_role_deny_scopes := {}" in rego
    assert "default allow := false" in rego
    assert "allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }" in rego


# --- generate_outbound_rego ---


def test_outbound_has_fixed_package_header():
    rego = generate_outbound_rego(_model())
    assert "package authbridge.client.outbound.request" in rego
    assert "import rego.v1" in rego


def test_outbound_embeds_agent_roles_list():
    rego = generate_outbound_rego(_github_agent())
    assert 'agent_roles := ["source-helper", "issues-helper"]' in rego
    # agent_scopes is the inbound audience gate; the outbound package must not emit it.
    assert "agent_scopes :=" not in rego


def test_outbound_subject_role_allow_scopes_are_deprefixed():
    rego = generate_outbound_rego(_github_agent())
    assert "subject_role_allow_scopes := {" in rego
    # role -> the FULL target service id -> bare tool names, owner prefix stripped (LIM-02)
    assert f'"developer": {{\n        "{GH_TOOL}": ["source-read", "source-write", "issues-read"],\n    }},' in rego
    assert f'"tester": {{\n        "{GH_TOOL}": ["issues-read", "issues-write"],\n    }},' in rego


def test_outbound_agent_role_scopes_are_deprefixed():
    rego = generate_outbound_rego(_github_agent())
    assert "agent_role_scopes := {" in rego
    assert '"source-helper": ["source-read", "source-write"]' in rego
    assert '"issues-helper": ["issues-read", "issues-write"]' in rego


def test_outbound_target_allow_and_deny_scopes_full_key_bare_values():
    dev = _role("developer")
    read = _scope("github-tool.source-read", GH_TOOL)
    secret = _scope("github-tool.source-delete", GH_TOOL)
    model = _model(
        agent_id=GH_AGENT,
        subject_roles={"dev-user": [dev]},
        target_allow_scopes={GH_TOOL: [read]},
        target_deny_scopes={GH_TOOL: [secret]},
        outbound_subject_allow_rules=[_rule(dev, read)],
        outbound_subject_deny_rules=[_rule(dev, secret, RuleEffect.DENY)],
    )
    rego = generate_outbound_rego(model)
    # key stays the FULL service id; values de-prefix to bare tool names.
    assert 'target_allow_scopes := {\n    "spiffe://localtest.me/ns/team1/sa/github-tool": ["source-read"],' in rego
    assert 'target_deny_scopes := {\n    "spiffe://localtest.me/ns/team1/sa/github-tool": ["source-delete"],' in rego


def test_outbound_no_prefixed_scope_leaks():
    rego = generate_outbound_rego(_github_agent())
    # Nothing prefixed leaks into the outbound package's scope values.
    assert "github-tool.source-read" not in rego
    assert "github-tool.issues-write" not in rego


def test_outbound_gates_use_nested_identity_and_mcp_input():
    rego = generate_outbound_rego(_github_agent())
    assert "some role in object.get(subject_roles, input.identity.subject, [])" in rego
    assert "tool in object.get(subject_role_allow_scopes, [role, input.identity.service_id], [])\n" in rego
    assert "tool in object.get(subject_role_deny_scopes, [role, input.identity.service_id], [])\n" in rego
    assert "subject_allow_ok if { subject_allows(input.mcp.params.name) }" in rego
    assert "subject_deny_ok if { subject_denies(input.mcp.params.name) }" in rego
    assert "target_allow_ok if { target_allows(input.mcp.params.name) }" in rego
    assert "tool in object.get(target_allow_scopes, input.identity.service_id, [])" in rego
    assert "target_deny_ok if { target_denies(input.mcp.params.name) }" in rego
    assert "tool in object.get(target_deny_scopes, input.identity.service_id, [])" in rego
    assert "default allow := false" in rego
    assert (
        'allow if { input.mcp.method == "tools/call"; subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }'
        in rego
    )
    # The inbound-flavoured subject gate must NOT appear in the outbound package.
    assert "scope in agent_scopes" not in rego


def test_outbound_does_not_embed_inbound_source_scope_maps():
    rego = generate_outbound_rego(_github_agent())
    # The inbound source scope maps must not leak into the outbound package.
    assert "source_role_allow_scopes" not in rego
    assert "source_role_deny_scopes" not in rego


def test_outbound_deprefix_fallbacks_survive_unchanged():
    """A scope with no owner (empty serviceId) and one whose name lacks the
    ``<owner>.`` prefix both survive unchanged — no crash, no partial strip."""
    orphan = _scope("orphan", "")  # no serviceId -> survives as "orphan"
    already_bare = _scope("already-bare", GH_TOOL)  # owner is github-tool, no prefix
    prefixed = _scope("github-tool.source-read", GH_TOOL)  # -> source-read
    model = _model(
        agent_id="team1/github-agent",
        target_allow_scopes={GH_TOOL: [prefixed, already_bare, orphan]},
    )
    rego = generate_outbound_rego(model)
    assert '"spiffe://localtest.me/ns/team1/sa/github-tool": ["source-read", "already-bare", "orphan"]' in rego


def test_outbound_empty_model_renders_valid_empty_literals():
    rego = generate_outbound_rego(_model())
    assert "agent_roles := []" in rego
    assert "subject_roles := {}" in rego
    assert "subject_role_allow_scopes := {}" in rego
    assert "subject_role_deny_scopes := {}" in rego
    assert "agent_role_scopes := {}" in rego
    assert "target_allow_scopes := {}" in rego
    assert "target_deny_scopes := {}" in rego
    assert "default allow := false" in rego
    assert (
        'allow if { input.mcp.method == "tools/call"; subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }'
        in rego
    )


# --- per-scope AND intersection + deny-overrides semantics ---


def _outbound_and_model() -> AgentPolicyModel:
    """Pins per-scope-AND + deny-overrides with de-prefixing in play.

    The user (subject gate) reaches bare {A, C, D}; the agent reaches bare
    {B, C, D} on target T (capability gate); and D is denied for the user
    (subject deny). So only C is allowed — A (user-only), B (agent-only) fail the
    AND, and D is deny-overridden. All provisioned scope names are
    ``github-tool.*``-prefixed to also exercise de-prefixing.
    """
    user = _role("u-role")
    operator = _role("op-role")
    a = _scope("github-tool.scope-a", GH_TOOL)
    b = _scope("github-tool.scope-b", GH_TOOL)
    c = _scope("github-tool.scope-c", GH_TOOL)
    d = _scope("github-tool.scope-d", GH_TOOL)
    return _model(
        agent_id="team1/github-agent",
        agent_roles=[operator],
        subject_roles={"user1": [user]},
        # target_allow_scopes IS the capability gate: the agent reaches {B, C, D} on T.
        target_allow_scopes={GH_TOOL: [b, c, d]},
        # user (subject allow gate) reaches {A, C, D}.
        outbound_subject_allow_rules=[
            _rule(user, a),
            _rule(user, c),
            _rule(user, d),
        ],
        # user is barred from D (deny-overrides even though both allow gates grant it).
        outbound_subject_deny_rules=[_rule(user, d, RuleEffect.DENY)],
        # informational agent_role_scopes (not referenced by allow): operator reaches {B, C, D}.
        outbound_target_allow_rules=[
            _rule(operator, b),
            _rule(operator, c),
            _rule(operator, d),
        ],
    )


def test_outbound_per_scope_and_structural():
    """Structural: the gates read the same ``input.mcp.params.name`` from disjoint
    maps — subject allow grants {A, C, D}, capability allow grants {B, C, D} on T,
    subject deny bars {D} — so allow is their per-scope intersection minus deny."""
    rego = generate_outbound_rego(_outbound_and_model())
    assert f'"u-role": {{\n        "{GH_TOOL}": ["scope-a", "scope-c", "scope-d"],' in rego  # subject allow gate
    assert (
        '"spiffe://localtest.me/ns/team1/sa/github-tool": ["scope-b", "scope-c", "scope-d"]' in rego
    )  # capability allow gate
    assert "subject_allow_ok if { subject_allows(input.mcp.params.name) }" in rego
    assert "subject_deny_ok if { subject_denies(input.mcp.params.name) }" in rego
    assert "target_allow_ok if { target_allows(input.mcp.params.name) }" in rego
    assert (
        'allow if { input.mcp.method == "tools/call"; subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }'
        in rego
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "tool_name, allowed",
    [
        ("scope-c", True),  # in BOTH allow gates, not denied -> allowed
        ("scope-a", False),  # user-only (not in the agent's capability gate) -> denied
        ("scope-b", False),  # agent-only (not in the user's subject gate) -> denied
        ("scope-d", False),  # in both allow gates BUT subject-denied -> deny-overrides
    ],
)
def test_outbound_per_scope_and_denies_mismatch(tool_name: str, allowed: bool):
    """Behavioural: evaluate the generated ``allow`` with ``opa eval`` against the
    nested ``input.identity`` / ``input.mcp`` doc the live plugin sends. Only the
    scope in both allow gates and not denied (C) is allowed; user-only (A),
    agent-only (B), and the deny-overridden (D) are denied — pinning the per-scope
    intersection AND deny-overrides."""
    rego = generate_outbound_rego(_outbound_and_model())
    _assert_opa_allow(
        rego,
        "data.authbridge.client.outbound.request.allow",
        {
            "identity": {"subject": "user1", "service_id": GH_TOOL},
            "mcp": {"method": "tools/call", "params": {"name": tool_name}},
        },
        allowed,
    )


def _inbound_deny_model() -> AgentPolicyModel:
    """A subject that both allows and denies the audience scope — deny-overrides must bar it."""
    good = _role("good")
    banned = _role("banned")
    access = _scope("github-agent.access")
    return _model(
        agent_id=GH_AGENT,
        agent_scopes=[access],
        subject_roles={"ok-user": [good], "bad-user": [good, banned]},
        inbound_subject_allow_rules=[_rule(good, access)],
        inbound_subject_deny_rules=[_rule(banned, access, RuleEffect.DENY)],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "subject, allowed",
    [
        ("ok-user", True),  # holds only the allow role
        ("bad-user", False),  # holds a deny role -> deny-overrides
    ],
)
def test_inbound_deny_overrides_behavioural(subject: str, allowed: bool):
    rego = generate_inbound_rego(_inbound_deny_model())
    _assert_opa_allow(
        rego,
        "data.authbridge.client.inbound.request.allow",
        {"identity": {"subject": subject}},
        allowed,
    )


def _inbound_source_deny_model() -> AgentPolicyModel:
    """A fully-allowed subject paired with a source that both allows and denies the audience scope.
    The colliding source ALLOW+DENY must resolve deny-overrides via the ``source_deny_ok`` gate,
    barring the request even though the subject and the source's allow role both pass."""
    good = _role("good")
    src_ok = _role("src-ok")
    src_bad = _role("src-bad")
    access = _scope("access")
    return _model(
        agent_id="github-agent",
        agent_scopes=[access],
        subject_roles={"user1": [good]},
        source_roles={"clean-src": [src_ok], "tainted-src": [src_ok, src_bad]},
        inbound_subject_allow_rules=[_rule(good, access)],
        inbound_source_allow_rules=[_rule(src_ok, access)],
        inbound_source_deny_rules=[_rule(src_bad, access, RuleEffect.DENY)],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "source, allowed",
    [
        ("clean-src", True),  # source holds only the allow role -> passes
        ("tainted-src", False),  # source holds a colliding deny role -> source deny-overrides
    ],
)
def test_inbound_source_deny_overrides_behavioural(source: str, allowed: bool):
    """Behavioural: a denied SOURCE wins over a colliding source ALLOW (and an allowed subject),
    exercising the ``source_allow_ok`` / ``source_deny_ok`` split on the source dimension — a path
    the other behavioural deny tests (subject inbound / subject outbound) do not cover."""
    rego = generate_inbound_rego(_inbound_source_deny_model())
    _assert_opa_allow(
        rego,
        "data.authbridge.client.inbound.request.allow",
        {"identity": {"subject": "user1", "client_id": source}},
        allowed,
    )


# --- always DENY: no configurable default effect ---------------------------
#
# A (role, scope) pair that NO rule mentions is always denied. Both packages emit
# exactly one decision shape: `default allow := false` plus one allow
# conjunction with inline `not …_deny_ok` guards. There is no permissive
# (`default allow := true`) branch.


def test_inbound_decision_block_is_the_single_deny_default():
    rego = generate_inbound_rego(_github_agent())
    assert "default allow := false" in rego
    assert "allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }" in rego
    assert "default allow := true" not in rego
    assert "allow := false if" not in rego


def test_outbound_decision_block_is_the_single_deny_default():
    rego = generate_outbound_rego(_github_agent())
    assert rego.count("default allow := false") == 1
    assert "default allow := true" not in rego
    assert "allow := false if" not in rego
    # Two allow rules, both under the DENY default: the per-tool tools/call check and the session.
    assert rego.count("\nallow if {") == 2


def test_agent_policy_model_has_no_default_effect():
    assert "default_effect" not in AgentPolicyModel.model_fields


def test_legacy_default_effect_allow_in_payload_is_ignored():
    """A stored or posted APM that still carries ``default_effect: Allow`` renders
    the DENY default (the field is gone and ``extra="ignore"`` drops it)."""
    payload = _github_agent().model_dump()
    payload["default_effect"] = RuleEffect.ALLOW.value
    model = AgentPolicyModel.model_validate(payload)
    for rego in (generate_inbound_rego(model), generate_outbound_rego(model)):
        assert "default allow := false" in rego
        assert "default allow := true" not in rego


# --- behavioural: an unmentioned pair is denied ------------------------------


def _inbound_unmentioned_model() -> AgentPolicyModel:
    """A subject holding a role that NO allow/deny rule mentions."""
    lonely = _role("lonely")
    access = _scope("github-agent.access")
    return _model(
        agent_id=GH_AGENT,
        agent_scopes=[access],
        subject_roles={"some-user": [lonely]},
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_inbound_unmentioned_pair_is_denied():
    _assert_opa_allow(
        generate_inbound_rego(_inbound_unmentioned_model()),
        "data.authbridge.client.inbound.request.allow",
        {"identity": {"subject": "some-user"}},
        False,
    )


def _outbound_unmentioned_model() -> AgentPolicyModel:
    """A (subject role, tool) that NO outbound rule mentions and no target scope grants."""
    lonely = _role("lonely")
    return _model(
        agent_id=GH_AGENT,
        subject_roles={"some-user": [lonely]},
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_outbound_unmentioned_pair_is_denied():
    _assert_opa_allow(
        generate_outbound_rego(_outbound_unmentioned_model()),
        "data.authbridge.client.outbound.request.allow",
        {
            "identity": {"subject": "some-user", "service_id": GH_TOOL},
            "mcp": {"method": "tools/call", "params": {"name": "anything"}},
        },
        False,
    )


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


def _opa_verdict(rego: str, query: str, input_doc: dict) -> bool:
    """Evaluate ``query`` against ``rego`` for ``input_doc`` and return the bool.

    The value-returning sibling of ``_assert_opa_allow`` — used by the matrix
    tests below, which compare each verdict against an oracle table."""
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
    return json.loads(out)["result"][0]["expressions"][0]["value"]


# --- Policy B matrix under the DENY default ---------------------------------
#
# One hand-built Policy-B outbound APM (the hand-built analogue of what the PRB
# emits), opa-evaluated over the full {developer,tester,devops} x
# {source,issues}-{read,write} matrix. The capability gate (target_allow_scopes)
# provisions all four tool scopes wide-open, as a real github-tool deployment
# does, so the two-gate AND reduces to the subject side.
#
#   ALLOW  developer -> source-read, source-write ; tester -> issues-read, issues-write
#   DENY   developer -> issues-*  ; tester -> source-*  ; devops -> source-*
# devops -> issues-* is mentioned by NO rule, so it is denied (no permissive default).

_POLICY_B_ROLES = ("developer", "tester", "devops")
_POLICY_B_TOOLS = ("source-read", "source-write", "issues-read", "issues-write")

# Oracle verdicts (allow=True / deny=False), computed from the rule lists by
# hand — NEVER read back from the Rego under test.
_POLICY_B_MATRIX: dict[tuple[str, str], bool] = {
    ("developer", "source-read"): True,  # explicit ALLOW + capability gate open
    ("developer", "source-write"): True,  # explicit ALLOW
    ("developer", "issues-read"): False,  # explicit DENY
    ("developer", "issues-write"): False,  # explicit DENY
    ("tester", "source-read"): False,  # explicit DENY
    ("tester", "source-write"): False,  # explicit DENY
    ("tester", "issues-read"): True,  # explicit ALLOW
    ("tester", "issues-write"): True,  # explicit ALLOW
    ("devops", "source-read"): False,  # explicit DENY
    ("devops", "source-write"): False,  # explicit DENY
    ("devops", "issues-read"): False,  # UNMENTIONED -> deny
    ("devops", "issues-write"): False,  # UNMENTIONED -> deny
}


def _policy_b_outbound_model() -> AgentPolicyModel:
    """One hand-built Policy-B outbound APM (see the section header)."""
    developer = _role("developer")
    tester = _role("tester")
    devops = _role("devops")
    source_read = _scope("github-tool.source-read", GH_TOOL)
    source_write = _scope("github-tool.source-write", GH_TOOL)
    issues_read = _scope("github-tool.issues-read", GH_TOOL)
    issues_write = _scope("github-tool.issues-write", GH_TOOL)
    return _model(
        agent_id=GH_AGENT,
        subject_roles={
            "developer": [developer],
            "tester": [tester],
            "devops": [devops],
        },
        target_allow_scopes={GH_TOOL: [source_read, source_write, issues_read, issues_write]},
        outbound_subject_allow_rules=[
            _rule(developer, source_read),
            _rule(developer, source_write),
            _rule(tester, issues_read),
            _rule(tester, issues_write),
        ],
        outbound_subject_deny_rules=[
            _rule(developer, issues_read, RuleEffect.DENY),
            _rule(developer, issues_write, RuleEffect.DENY),
            _rule(tester, source_read, RuleEffect.DENY),
            _rule(tester, source_write, RuleEffect.DENY),
            _rule(devops, source_read, RuleEffect.DENY),
            _rule(devops, source_write, RuleEffect.DENY),
        ],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_policy_b_matrix_under_deny_default():
    rego = generate_outbound_rego(_policy_b_outbound_model())
    query = "data.authbridge.client.outbound.request.allow"
    for role in _POLICY_B_ROLES:
        for tool in _POLICY_B_TOOLS:
            input_doc = {
                "identity": {"subject": role, "service_id": GH_TOOL},
                "mcp": {"method": "tools/call", "params": {"name": tool}},
            }
            assert _opa_verdict(rego, query, input_doc) is _POLICY_B_MATRIX[(role, tool)], (role, tool)


# --- an APM with no rules -----------------------------------------------------
#
# An agent with no rules and no scopes (agent side). Under the DENY default its
# packages deny every inbound and every outbound request — also end-user traffic
# that carries the ``rossoctl`` platform client, and also the MCP session messages.
# (A quarantine no longer writes such a CR: it deletes the CR, D20.)

_OUTBOUND = "data.authbridge.client.outbound.request.allow"
_INBOUND = "data.authbridge.client.inbound.request.allow"
_SESSION_METHODS = ("initialize", "notifications/initialized", "ping", "tools/list")


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
def test_no_rules_apm_denies_every_inbound_request(identity):
    _assert_opa_allow(generate_inbound_rego(_model(agent_id=GH_AGENT)), _INBOUND, {"identity": identity}, False)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "mcp",
    [{"method": "tools/call", "params": {"name": "source-read"}}] + [{"method": m} for m in _SESSION_METHODS],
    ids=lambda mcp: mcp["method"],
)
def test_no_rules_apm_denies_every_outbound_request(mcp):
    _assert_opa_allow(
        generate_outbound_rego(_model(agent_id=GH_AGENT)),
        _OUTBOUND,
        {"identity": {"subject": "dev-user", "service_id": GH_TOOL}, "mcp": mcp},
        False,
    )


# --- B4: MCP session messages on the outbound -------------------------------
#
# ``initialize``, ``notifications/initialized``, ``ping`` and ``tools/list``
# carry no tool name. They are allowed to a target (``input.identity.service_id``)
# iff at least ONE tool of that target passes the full per-tool check for this
# request: the user gate allows it, the target gate allows it, and no deny vetoes
# it. ``tools/call`` stays a per-tool check on ``input.mcp.params.name`` (and
# requires the ``tools/call`` method). Every other MCP method is denied.

OTHER_TOOL = "spiffe://localtest.me/ns/team1/sa/other-tool"


def _session_model() -> AgentPolicyModel:
    """dev-user may use source-read on github-tool; ops-user holds a role that is allowed
    issues-read but also denied it (a vetoed allow); guest holds a role that no rule grants.
    The target gate admits source-read and issues-read on github-tool, and nothing on other-tool
    except a target-denied tool."""
    dev = _role("developer")
    ops = _role("ops")
    lonely = _role("lonely")
    source_read = _scope("github-tool.source-read", GH_TOOL)
    issues_read = _scope("github-tool.issues-read", GH_TOOL)
    blocked = _scope("other-tool.blocked", OTHER_TOOL)
    return _model(
        agent_id=GH_AGENT,
        subject_roles={"dev-user": [dev], "ops-user": [ops], "guest": [lonely]},
        target_allow_scopes={GH_TOOL: [source_read, issues_read], OTHER_TOOL: [blocked]},
        target_deny_scopes={OTHER_TOOL: [blocked]},
        outbound_subject_allow_rules=[_rule(dev, source_read), _rule(ops, issues_read), _rule(dev, blocked)],
        outbound_subject_deny_rules=[_rule(ops, issues_read, RuleEffect.DENY)],
    )


def _outbound_input(subject, mcp, target=GH_TOOL):
    return {"identity": {"subject": subject, "service_id": target}, "mcp": mcp}


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("method", _SESSION_METHODS)
def test_session_message_allowed_when_a_tool_of_the_target_passes(method):
    rego = generate_outbound_rego(_session_model())
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input("dev-user", {"method": method}), True)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("method", _SESSION_METHODS)
@pytest.mark.parametrize(
    "subject, target",
    [
        ("guest", GH_TOOL),  # no role of the user grants any tool of the target
        ("ops-user", GH_TOOL),  # the only allow is vetoed by a subject deny
        ("dev-user", OTHER_TOOL),  # the only allow is vetoed by a target deny
        ("dev-user", "spiffe://localtest.me/ns/team1/sa/unknown"),  # a target with no grant
        ("nobody", GH_TOOL),  # a user with no roles
    ],
    ids=["no-grant", "subject-veto", "target-veto", "unknown-target", "no-roles"],
)
def test_session_message_denied_when_no_tool_of_the_target_passes(method, subject, target):
    rego = generate_outbound_rego(_session_model())
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input(subject, {"method": method}, target), False)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "subject, tool, allowed",
    [
        ("dev-user", "source-read", True),  # granted
        ("dev-user", "issues-read", False),  # the session is open, but this tool is not granted
        ("ops-user", "issues-read", False),  # vetoed
    ],
)
def test_tools_call_stays_a_per_tool_check(subject, tool, allowed):
    rego = generate_outbound_rego(_session_model())
    mcp = {"method": "tools/call", "params": {"name": tool}}
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input(subject, mcp), allowed)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "mcp",
    [
        {"method": "resources/list"},
        {"method": "prompts/list"},
        {"method": "resources/read", "params": {"uri": "file:///etc/passwd"}},
        # A granted tool name under a method that is not tools/call: the per-tool branch
        # requires the tools/call method.
        {"method": "prompts/get", "params": {"name": "source-read"}},
        {"params": {"name": "source-read"}},  # no method at all
    ],
    ids=["resources-list", "prompts-list", "resources-read", "prompts-get-granted-name", "no-method"],
)
def test_every_other_mcp_method_is_denied(mcp):
    rego = generate_outbound_rego(_session_model())
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input("dev-user", mcp), False)


# --- LIM-02: the outbound subject maps are per target ------------------------
#
# Two tools expose a tool with the same bare name: ``tool-a.source-read`` and ``tool-b.source-read``
# are two different scopes (two ids) that both de-prefix to ``source-read``. The agent may call both
# (the target gate admits ``source-read`` on each tool). A user rule names one scope, so it decides
# only on the owner of that scope: a grant on tool-b gives nothing on tool-a, and a deny on tool-a
# blocks nothing on tool-b.
#
# A shared scope (D32) is one scope (one id) with a copy on each owner. Each copy has the user rules of
# its own SPM: each owner's onboarding is its own scope-focal PRB pass, so two copies can get different
# rules, and under target side each copy decides from its own SPM. So a user rule, a GRANT or a DENY,
# decides only on the copy that it names (``scope.serviceId``), as under target side. A copy with no
# grant gets no allow entry, also when the agent may call that copy: a grant given to every copy is
# fail-open (it admits the user on a copy whose SPM has no such grant). A copy with no deny gets no deny
# entry: a deny given to every copy over-denies (it blocks the user on a copy whose SPM has no deny).
#
# The PCE keeps one outbound subject rule for each copy (role, scope id, copy owner, effect). So when
# the SPMs of both copies deny a role, the APM has the deny of each copy, and each copy gets its deny
# entry: a deny of one copy only would admit the user on the other copy through a grant of another role
# there (fail-open).

TOOL_A = "spiffe://localtest.me/ns/team1/sa/tool-a"
TOOL_B = "spiffe://localtest.me/ns/team1/sa/tool-b"
GH_TOOL_TEAM2 = "spiffe://localtest.me/ns/team2/sa/github-tool"
MIRROR_TOOL = "spiffe://localtest.me/ns/team1/sa/mirror-tool"


def _two_tools_model(deny_on_tool_a: bool) -> AgentPolicyModel:
    """alice (role dev) is granted ``tool-b.source-read`` only; with ``deny_on_tool_a``, dev is also
    denied ``tool-a.source-read``. The agent may call ``source-read`` on both tools."""
    dev = _user_role("dev", "alice")
    on_a = _scope("tool-a.source-read", TOOL_A)
    on_b = _scope("tool-b.source-read", TOOL_B)
    return _model(
        agent_id=GH_AGENT,
        subject_roles={"alice": [dev]},
        target_allow_scopes={TOOL_A: [on_a], TOOL_B: [on_b]},
        outbound_subject_allow_rules=[_rule(dev, on_b)],
        outbound_subject_deny_rules=[_rule(dev, on_a, RuleEffect.DENY)] if deny_on_tool_a else [],
    )


_CALL_SOURCE_READ = {"method": "tools/call", "params": {"name": "source-read"}}


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("mcp", [_CALL_SOURCE_READ, {"method": "tools/list"}], ids=["tools-call", "tools-list"])
@pytest.mark.parametrize("target, allowed", [(TOOL_B, True), (TOOL_A, False)], ids=["granted-tool", "other-tool"])
def test_outbound_subject_grant_on_one_target_gives_nothing_on_another(mcp, target, allowed):
    """The grant on tool-b does not let alice call ``source-read`` on tool-a (LIM-02, fail-open)."""
    rego = generate_outbound_rego(_two_tools_model(deny_on_tool_a=False))
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input("alice", mcp, target), allowed)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("mcp", [_CALL_SOURCE_READ, {"method": "tools/list"}], ids=["tools-call", "tools-list"])
@pytest.mark.parametrize("target, allowed", [(TOOL_B, True), (TOOL_A, False)], ids=["granted-tool", "denied-tool"])
def test_outbound_subject_deny_on_one_target_blocks_nothing_on_another(mcp, target, allowed):
    """The deny on tool-a does not block alice's grant on tool-b (LIM-02, fail-closed)."""
    rego = generate_outbound_rego(_two_tools_model(deny_on_tool_a=True))
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input("alice", mcp, target), allowed)


def test_outbound_subject_maps_are_keyed_by_role_then_target():
    rego = generate_outbound_rego(_two_tools_model(deny_on_tool_a=True))
    assert f'subject_role_allow_scopes := {{\n    "dev": {{\n        "{TOOL_B}": ["source-read"],\n    }},\n}}' in rego
    assert f'subject_role_deny_scopes := {{\n    "dev": {{\n        "{TOOL_A}": ["source-read"],\n    }},\n}}' in rego
    assert "tool in object.get(subject_role_allow_scopes, [role, input.identity.service_id], [])" in rego
    assert "tool in object.get(subject_role_deny_scopes, [role, input.identity.service_id], [])" in rego


_COPIES = (GH_TOOL, GH_TOOL_TEAM2)


def _shared_scope_model(allow_on: tuple[str, ...], deny_on: tuple[str, ...]) -> AgentPolicyModel:
    """``github-tool.source-read`` is one shared scope with a copy on team1/github-tool and on
    team2/github-tool (D32), and the agent may call both copies. alice holds dev; olga holds reader and
    ops. On each copy in ``allow_on``, dev and reader are granted the scope; on each copy in ``deny_on``,
    ops is denied it. Each rule names its own copy, as the SPM of that copy's owner has it (one rule for
    each copy)."""
    dev = _user_role("dev", "alice")
    reader = _user_role("reader", "olga")
    ops = _user_role("ops", "olga")
    copies = {owner: _scope("github-tool.source-read", owner) for owner in _COPIES}
    return _model(
        agent_id=GH_AGENT,
        subject_roles={"alice": [dev], "olga": [reader, ops]},
        target_allow_scopes={owner: [copy] for owner, copy in copies.items()},
        outbound_subject_allow_rules=[_rule(role, copies[owner]) for owner in allow_on for role in (dev, reader)],
        outbound_subject_deny_rules=[_rule(ops, copies[owner], RuleEffect.DENY) for owner in deny_on],
    )


# The rules of each copy: (the copies with the dev and reader grants, the copies with the ops deny).
# Through UC-1, a placement where one copy grants a role and the other copy denies the same role is a
# PRB policy conflict; here dev/reader and ops are different roles, so each placement can occur.
_SHARED_PLACEMENTS = {
    "both-copies": (_COPIES, _COPIES),
    "grant-on-first-copy-only": ((GH_TOOL,), ()),
    "grant-on-other-copy-only": ((GH_TOOL_TEAM2,), ()),
    "deny-on-first-copy-only": (_COPIES, (GH_TOOL,)),
    "deny-on-other-copy-only": (_COPIES, (GH_TOOL_TEAM2,)),
}


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("placement", list(_SHARED_PLACEMENTS))
@pytest.mark.parametrize("target", _COPIES, ids=["first-copy", "other-copy"])
@pytest.mark.parametrize("subject", ["alice", "olga"])
def test_outbound_shared_scope_grant_and_deny_are_per_copy(placement, target, subject):
    """alice is allowed on a copy iff that copy grants dev: a grant on one copy does not admit her on
    a copy with no grant (fail-open). olga is allowed on a copy iff that copy grants reader and does
    not deny ops: a deny on one copy blocks her on that copy only, as under target side."""
    allow_on, deny_on = _SHARED_PLACEMENTS[placement]
    allowed = target in allow_on and not (subject == "olga" and target in deny_on)
    rego = generate_outbound_rego(_shared_scope_model(allow_on, deny_on))
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input(subject, _CALL_SOURCE_READ, target), allowed)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("target, allowed", [(GH_TOOL, True), (GH_TOOL_TEAM2, False)], ids=["granted-copy", "no-rule"])
def test_outbound_session_on_a_shared_scope_copy_with_no_rule_is_denied(target, allowed):
    """``tools/list`` follows the per-copy decision: the copy with no rule for alice has no tool that
    passes ``tool_ok`` for her."""
    rego = generate_outbound_rego(_shared_scope_model(allow_on=(GH_TOOL,), deny_on=()))
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input("alice", {"method": "tools/list"}, target), allowed)


def test_outbound_subject_map_has_no_entry_for_a_copy_with_no_rule():
    """A grant on one copy of a shared scope gives no allow entry to the other copy, although the
    agent may call the other copy (it is in ``target_allow_scopes``)."""
    rego = generate_outbound_rego(_shared_scope_model(allow_on=(GH_TOOL,), deny_on=()))
    assert (
        f'subject_role_allow_scopes := {{\n    "dev": {{\n        "{GH_TOOL}": ["source-read"],\n    }},\n'
        f'    "reader": {{\n        "{GH_TOOL}": ["source-read"],\n    }},\n}}'
    ) in rego
    assert "subject_role_deny_scopes := {}" in rego


# The APM that the PCE gives when the SPMs of both copies deny ``dev`` and the SPM of ``tester_on`` also
# grants ``tester``: the PCE keeps the deny of each copy (one rule for each copy), in the order in which
# it reads the SPMs. alice holds dev and tester; tina holds tester only.
_READ_ORDERS = {"first-copy-read-first": _COPIES, "other-copy-read-first": tuple(reversed(_COPIES))}


def _deny_on_both_copies_model(read_order: tuple[str, ...], tester_on: str) -> AgentPolicyModel:
    dev = _user_role("dev", "alice")
    tester = _user_role("tester", "alice", "tina")
    copies = {owner: _scope("github-tool.source-read", owner) for owner in _COPIES}
    return _model(
        agent_id=GH_AGENT,
        subject_roles={"alice": [dev, tester], "tina": [tester]},
        target_allow_scopes={owner: [copy] for owner, copy in copies.items()},
        outbound_subject_allow_rules=[_rule(tester, copies[tester_on])],
        outbound_subject_deny_rules=[_rule(dev, copies[owner], RuleEffect.DENY) for owner in read_order],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("mcp", [_CALL_SOURCE_READ, {"method": "tools/list"}], ids=["tools-call", "tools-list"])
@pytest.mark.parametrize("read_order", list(_READ_ORDERS))
@pytest.mark.parametrize("tester_on", _COPIES, ids=["tester-on-first-copy", "tester-on-other-copy"])
@pytest.mark.parametrize("target", _COPIES, ids=["first-copy", "other-copy"])
@pytest.mark.parametrize("subject", ["alice", "tina"])
def test_outbound_deny_on_both_copies_blocks_the_user_on_both_copies(read_order, tester_on, target, subject, mcp):
    """Each copy's deny of dev blocks alice on that copy, also on the copy where she has the tester
    grant (both SPMs deny dev). tina does not hold dev, so no deny blocks her on the tester copy."""
    allowed = subject == "tina" and target == tester_on
    rego = generate_outbound_rego(_deny_on_both_copies_model(_READ_ORDERS[read_order], tester_on))
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input(subject, mcp, target), allowed)


@pytest.mark.parametrize("read_order", list(_READ_ORDERS))
def test_outbound_subject_deny_map_has_the_deny_of_each_copy_on_that_copy(read_order):
    """The deny of each copy is keyed by that copy, in the order of the deny rules."""
    order = _READ_ORDERS[read_order]
    rego = generate_outbound_rego(_deny_on_both_copies_model(order, GH_TOOL_TEAM2))
    assert (
        f'subject_role_deny_scopes := {{\n    "dev": {{\n        "{order[0]}": ["source-read"],\n'
        f'        "{order[1]}": ["source-read"],\n    }},\n}}'
    ) in rego


@pytest.mark.parametrize("deny_named", [GH_TOOL, GH_TOOL_TEAM2], ids=["first-copy", "other-copy"])
def test_outbound_subject_deny_map_keys_a_deny_only_on_its_own_copy(deny_named):
    """A deny rule is keyed only by the copy that it names, although the agent may call the other copy
    of its scope (same scope id) too: the other copy, whose SPM has no deny, gets no deny entry. The
    grant stays on its own copy."""
    ops = _user_role("ops", "olga")
    reader = _user_role("reader", "olga")
    copies = {owner: _scope("github-tool.source-read", owner) for owner in _COPIES}
    rego = generate_outbound_rego(
        _model(
            agent_id=GH_AGENT,
            subject_roles={"olga": [reader, ops]},
            target_allow_scopes={owner: [copy] for owner, copy in copies.items()},
            outbound_subject_allow_rules=[_rule(reader, copies[GH_TOOL_TEAM2])],
            outbound_subject_deny_rules=[_rule(ops, copies[deny_named], RuleEffect.DENY)],
        )
    )
    assert (
        f'subject_role_deny_scopes := {{\n    "ops": {{\n        "{deny_named}": ["source-read"],\n    }},\n}}' in rego
    )
    assert (
        f'subject_role_allow_scopes := {{\n    "reader": {{\n        "{GH_TOOL_TEAM2}": ["source-read"],\n    }},\n}}'
    ) in rego


@pytest.mark.parametrize("deny_named", _COPIES, ids=["allowed-copy", "denied-copy"])
def test_outbound_subject_deny_on_a_copy_that_the_agent_is_denied_stays_on_that_copy(deny_named):
    """The agent may call the first copy, and ``target_deny_scopes`` denies it the other copy. A deny
    rule is keyed only by the copy that it names, also when the agent is denied that copy (the target
    gate denies the agent there anyway), and never by the other copy."""
    ops = _user_role("ops", "olga")
    first, other = (_scope("github-tool.source-read", owner) for owner in _COPIES)
    rego = generate_outbound_rego(
        _model(
            agent_id=GH_AGENT,
            subject_roles={"olga": [ops]},
            target_allow_scopes={GH_TOOL: [first]},
            target_deny_scopes={GH_TOOL_TEAM2: [other]},
            outbound_subject_deny_rules=[_rule(ops, first if deny_named == GH_TOOL else other, RuleEffect.DENY)],
        )
    )
    assert (
        f'subject_role_deny_scopes := {{\n    "ops": {{\n        "{deny_named}": ["source-read"],\n    }},\n}}' in rego
    )


def test_outbound_subject_map_takes_each_target_tool_from_its_own_copy():
    """Each rule de-prefixes by the owner of the copy that it names, so the subject value of each
    target is the value that the target gate of that target has."""
    dev = _user_role("dev", "alice")
    copy1 = _scope("github-tool.source-read", GH_TOOL)
    mirror = _scope("github-tool.source-read", MIRROR_TOOL)  # the owner name is not the prefix
    rego = generate_outbound_rego(
        _model(
            agent_id=GH_AGENT,
            subject_roles={"alice": [dev]},
            target_allow_scopes={GH_TOOL: [copy1], MIRROR_TOOL: [mirror]},
            outbound_subject_allow_rules=[_rule(dev, copy1), _rule(dev, mirror)],
        )
    )
    assert (
        f'subject_role_allow_scopes := {{\n    "dev": {{\n        "{GH_TOOL}": ["source-read"],\n'
        f'        "{MIRROR_TOOL}": ["github-tool.source-read"],\n    }},\n}}'
    ) in rego


def test_outbound_subject_deny_map_takes_each_target_tool_from_its_own_copy():
    """Each deny rule (one for each copy) de-prefixes by the owner of the copy that it names, so the
    subject value of each target is the value that the target gate of that target has (the owner name
    of the mirror copy is not the prefix)."""
    ops = _user_role("ops", "olga")
    copy1 = _scope("github-tool.source-read", GH_TOOL)
    mirror = _scope("github-tool.source-read", MIRROR_TOOL)
    rego = generate_outbound_rego(
        _model(
            agent_id=GH_AGENT,
            subject_roles={"olga": [ops]},
            target_allow_scopes={GH_TOOL: [copy1], MIRROR_TOOL: [mirror]},
            outbound_subject_deny_rules=[_rule(ops, copy1, RuleEffect.DENY), _rule(ops, mirror, RuleEffect.DENY)],
        )
    )
    assert (
        f'subject_role_deny_scopes := {{\n    "ops": {{\n        "{GH_TOOL}": ["source-read"],\n'
        f'        "{MIRROR_TOOL}": ["github-tool.source-read"],\n    }},\n}}'
    ) in rego


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
def test_outbound_subject_map_escapes_its_keys_and_values():
    """The two-level map escapes each key and value like the flat maps (no broken Rego)."""
    odd = _user_role('dev "x"\n', "alice")
    tool = _scope('github-tool.say-"hi"', GH_TOOL)
    rego = generate_outbound_rego(
        _model(
            agent_id=GH_AGENT,
            subject_roles={"alice": [odd]},
            target_allow_scopes={GH_TOOL: [tool]},
            outbound_subject_allow_rules=[_rule(odd, tool)],
        )
    )
    mcp = {"method": "tools/call", "params": {"name": 'say-"hi"'}}
    _assert_opa_allow(rego, _OUTBOUND, _outbound_input("alice", mcp), True)


# =========================================================================== #
# Target side (D18c, D24, D26, D26a, D27; checkpoint B1)                      #
# =========================================================================== #
#
# The render input of a target-side CR is the stored SPM of the callee. The writer
# does no join: every edge that the callee checks is already on its own SPM.


# --- the pass-through package (D24) -----------------------------------------

_PASS_THROUGH_OUTBOUND = "package authbridge.client.outbound.request\nimport rego.v1\n\nallow := true\n"
_PASS_THROUGH_INBOUND = "package authbridge.client.inbound.request\nimport rego.v1\n\nallow := true\n"


def test_pass_through_package_is_the_header_and_allow_true():
    assert generate_pass_through_rego("outbound") == _PASS_THROUGH_OUTBOUND
    assert generate_pass_through_rego("inbound") == _PASS_THROUGH_INBOUND


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


def _agent_role(name: str, agent: str) -> Role:
    return Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.AGENT, actorIds=[agent])


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


# --- the agent inbound package under target side (D26a) ---------------------
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


# --- the outbound of every service under target side (D24) ------------------


@pytest.mark.parametrize("spm", [_tool_spm(), _agent_spm()], ids=["tool", "agent"])
def test_target_side_outbound_is_the_pass_through(spm):
    assert render_target_side(spm).outbound == _PASS_THROUGH_OUTBOUND


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("spm", [_tool_spm(), _agent_spm()], ids=["tool", "agent"])
def test_target_side_outbound_allows_an_ungranted_call(spm):
    # Under agent side this call is denied by the agent outbound; under target side the callee decides.
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
# Agent side (D18c, D24)                                                      #
# =========================================================================== #
#
# The render input is the APMs and the pass-through IDs. An agent CR has the agent inbound and the
# agent outbound (per-tool checks and the MCP session rule); a managed tool gets a pass-through CR.


# --- the pass-through CR of a managed tool (D24) -----------------------------


def test_agent_side_pass_through_cr_has_a_pass_through_in_both_tiers():
    assert render_pass_through() == ClientPolicies(inbound=_PASS_THROUGH_INBOUND, outbound=_PASS_THROUGH_OUTBOUND)


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize("tier", ["inbound", "outbound"])
@pytest.mark.parametrize(
    "input_doc",
    [
        {},  # no identity (D27 does not apply: a pass-through is not rules-based)
        {"identity": {"subject": "guest", "client_id": OTHER_AGENT}, "mcp": _call("delete-repo")},
        {"identity": {"subject": "guest", "service_id": GH_TOOL}, "mcp": {"method": "resources/read"}},
        {"identity": {"subject": "dev-user"}, "a2a": {"method": "message/send"}},
    ],
    ids=["no-identity", "ungranted-tools-call", "other-mcp-method", "a2a"],
)
def test_agent_side_pass_through_cr_allows_every_request(tier, input_doc):
    query = {"inbound": _INBOUND, "outbound": _OUTBOUND}[tier]
    _assert_opa_allow(getattr(render_pass_through(), tier), query, input_doc, True)


# --- the agent CR: the agent inbound and the agent outbound ------------------


def test_agent_side_agent_cr_has_the_agent_inbound_and_the_agent_outbound():
    apm = _github_agent()
    policies = render_agent_side(apm, platform_clients=("argocd",))
    # The agent inbound, agent-level (D26a), with the caller's platform clients.
    assert policies.inbound == generate_inbound_rego(apm, platform_clients=("argocd",))
    assert 'source_allow_ok if { input.identity.client_id == "argocd" }' in policies.inbound
    # The agent outbound: the per-tool checks and the MCP session rule, never a pass-through.
    assert policies.outbound == generate_outbound_rego(apm)
    assert (
        "allow if { input.mcp.method in session_methods; "
        "some tool in object.get(target_allow_scopes, input.identity.service_id, []); tool_ok(tool) }"
    ) in policies.outbound
    assert policies.outbound != _PASS_THROUGH_OUTBOUND


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "input_doc",
    [
        {"identity": {"subject": "dev-user", "service_id": GH_TOOL}, "a2a": {"method": "message/send"}},
        {"identity": {"subject": "dev-user", "service_id": GH_TOOL}},  # an LLM call: no MCP method
    ],
    ids=["a2a-message-send", "llm-call"],
)
def test_agent_side_agent_outbound_denies_a2a_and_llm_calls(input_doc):
    # The known limit of the agent side (b435aa1): only a granted tools/call and the MCP session pass.
    _assert_opa_allow(render_agent_side(_github_agent()).outbound, _OUTBOUND, input_doc, False)


# =========================================================================== #
# Empty maps: every map is read with object.get (OPA 1.21)                    #
# =========================================================================== #
#
# An empty map renders as ``{}``. OPA 1.21 types ``{}`` as an object with no keys, so a direct
# index ``m[key]`` into it is a type error that stops the whole bundle from activating (the
# sidecar then denies every request). The writer reads every map with ``object.get``.


def _empty_map_policies() -> dict[str, ClientPolicies]:
    """The CRs whose maps are all empty: a zero-rule agent and tool under each side."""
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
        "target-side-agent": render_target_side(agent_spm),
        "target-side-tool": render_target_side(tool_spm),
        "target-side-bootstrap-tool": render_target_side(bootstrap_tool_spm),
        "agent-side-agent": render_agent_side(_model(agent_id=GH_AGENT)),
    }


def _declared_maps(rego: str) -> list[str]:
    return re.findall(r"^(\w+) := \{", rego, flags=re.MULTILINE)


@pytest.mark.parametrize(
    "policies",
    [*_empty_map_policies().values(), render_agent_side(_github_agent())],
    ids=[*_empty_map_policies(), "agent-side-github-agent"],
)
def test_no_rule_indexes_a_declared_map(policies):
    # A direct index works only while the map has a key; object.get works on an empty map too.
    for rego in policies:
        for name in _declared_maps(rego):
            assert not re.search(rf"\b{name}\[", rego), f"{name} is indexed directly:\n{rego}"


def test_no_rule_loops_over_an_empty_list():
    # OPA 1.21 also rejects a loop over an empty array literal (some x in []); membership is fine.
    rego = _empty_map_policies()["target-side-bootstrap-tool"].inbound
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
    rego = _empty_map_policies()["target-side-bootstrap-tool"].inbound
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
