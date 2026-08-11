"""Unit tests for aiac.pdp.service.policy.opa.rego (fixed packages, ALLOW/DENY).

Targets the synthesized generator: fixed package names
(``authbridge.client.{inbound,outbound}.request`` + ``import rego.v1``), the
nested ``input.identity`` / ``input.mcp`` shape, the ``rossoctl`` platform
bypass, and outbound de-prefixing (provisioned ``<owner>.<tool>`` scope names
collapse to the bare ``input.mcp.params.name`` the live plugin sends) — now with
the deny-overrides ALLOW/DENY split. Each gate is emitted twice
(``*_allow_ok`` / ``*_deny_ok``) and ``allow`` requires every ALLOW gate and no
DENY gate. Scope maps are split symmetrically
(``subject_role_allow_scopes`` / ``_deny_scopes``, ``source_role_allow_scopes`` /
``_deny_scopes``, ``target_allow_scopes`` / ``target_deny_scopes``); the identity
maps (``subject_roles`` / ``source_roles`` / ``agent_roles``) keep their names.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from aiac.idp.configuration.models import Role, Scope
from aiac.pdp.service.policy.opa.rego import (
    generate_inbound_rego,
    generate_outbound_rego,
    identity_ref,
)
from aiac.policy.model.models import AgentPolicyModel, PolicyRule, RuleEffect

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
        target_allow_scopes={
            GH_TOOL: [source_read, source_write, issues_read, issues_write]
        },
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
    assert (
        'agent_scopes := ["github-agent.source_operations", '
        '"github-agent.issues_operations"]' in rego
    )


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
    assert (
        '"developer": ["github-agent.source_operations", '
        '"github-agent.issues_operations"]' in rego
    )
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
    assert "subject_allow_ok if {" in rego
    assert "subject_deny_ok if {" in rego
    assert "some role in subject_roles[input.identity.subject]" in rego
    assert "some scope in subject_role_allow_scopes[role]" in rego
    assert "some scope in subject_role_deny_scopes[role]" in rego
    assert "scope in agent_scopes" in rego


def test_inbound_platform_bypass_default_rossoctl():
    rego = generate_inbound_rego(_github_agent())
    assert "source_allow_ok if { not input.identity.client_id }" in rego
    assert 'source_allow_ok if { input.identity.client_id == "rossoctl" }' in rego
    assert "some role in source_roles[input.identity.client_id]" in rego
    assert "some scope in source_role_allow_scopes[role]" in rego


def test_inbound_platform_bypass_multiple_clients():
    rego = generate_inbound_rego(
        _github_agent(), platform_clients=("rossoctl", "argocd")
    )
    assert 'source_allow_ok if { input.identity.client_id == "rossoctl" }' in rego
    assert 'source_allow_ok if { input.identity.client_id == "argocd" }' in rego


def test_inbound_source_deny_gate_present():
    rego = generate_inbound_rego(_github_agent())
    assert "source_deny_ok if {" in rego
    assert "some scope in source_role_deny_scopes[role]" in rego


def test_inbound_has_default_deny_and_deny_overrides_allow():
    rego = generate_inbound_rego(_github_agent())
    assert "default allow := false" in rego
    assert (
        "allow if { subject_allow_ok; source_allow_ok; "
        "not subject_deny_ok; not source_deny_ok }" in rego
    )


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
    assert (
        "allow if { subject_allow_ok; source_allow_ok; "
        "not subject_deny_ok; not source_deny_ok }" in rego
    )


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
    # bare tool names, owner prefix stripped
    assert '"developer": ["source-read", "source-write", "issues-read"]' in rego
    assert '"tester": ["issues-read", "issues-write"]' in rego


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
    assert (
        'target_allow_scopes := {\n'
        '    "spiffe://localtest.me/ns/team1/sa/github-tool": ["source-read"],' in rego
    )
    assert (
        'target_deny_scopes := {\n'
        '    "spiffe://localtest.me/ns/team1/sa/github-tool": ["source-delete"],' in rego
    )


def test_outbound_no_prefixed_scope_leaks():
    rego = generate_outbound_rego(_github_agent())
    # Nothing prefixed leaks into the outbound package's scope values.
    assert "github-tool.source-read" not in rego
    assert "github-tool.issues-write" not in rego


def test_outbound_gates_use_nested_identity_and_mcp_input():
    rego = generate_outbound_rego(_github_agent())
    assert "subject_allow_ok if {" in rego
    assert "subject_deny_ok if {" in rego
    assert "some role in subject_roles[input.identity.subject]" in rego
    assert "input.mcp.params.name in subject_role_allow_scopes[role]" in rego
    assert "input.mcp.params.name in subject_role_deny_scopes[role]" in rego
    assert "target_allow_ok if {" in rego
    assert (
        "input.mcp.params.name in target_allow_scopes[input.identity.service_id]"
        in rego
    )
    assert "target_deny_ok if {" in rego
    assert (
        "input.mcp.params.name in target_deny_scopes[input.identity.service_id]"
        in rego
    )
    assert "default allow := false" in rego
    assert (
        "allow if { subject_allow_ok; target_allow_ok; "
        "not subject_deny_ok; not target_deny_ok }" in rego
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
    assert (
        '"spiffe://localtest.me/ns/team1/sa/github-tool": '
        '["source-read", "already-bare", "orphan"]' in rego
    )


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
        "allow if { subject_allow_ok; target_allow_ok; "
        "not subject_deny_ok; not target_deny_ok }" in rego
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
    assert '"u-role": ["scope-a", "scope-c", "scope-d"]' in rego  # subject allow gate
    assert (
        '"spiffe://localtest.me/ns/team1/sa/github-tool": '
        '["scope-b", "scope-c", "scope-d"]' in rego
    )  # capability allow gate
    assert "input.mcp.params.name in subject_role_allow_scopes[role]" in rego
    assert "input.mcp.params.name in subject_role_deny_scopes[role]" in rego
    assert (
        "input.mcp.params.name in target_allow_scopes[input.identity.service_id]"
        in rego
    )
    assert (
        "allow if { subject_allow_ok; target_allow_ok; "
        "not subject_deny_ok; not target_deny_ok }" in rego
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
            "mcp": {"params": {"name": tool_name}},
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


def _assert_opa_allow(rego: str, query: str, input_doc: dict, expected: bool) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego)
        cmd = [
            shutil.which("opa"), "eval", "-f", "json", "-d", str(path),
            "--stdin-input", query,
        ]
        out = subprocess.run(
            cmd,
            input=json.dumps(input_doc),
            capture_output=True, text=True, check=True,
        ).stdout
        result = json.loads(out)["result"][0]["expressions"][0]["value"]
    assert result is expected, f"input={input_doc!r}"
