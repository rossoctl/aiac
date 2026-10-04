"""The shared inbound projection (D18b): one SPM's edges split into the user gate and the
calling-agent gate, plus the effect-agnostic identity maps. ``_derive`` (agent side) and the
target-side renderer both use it, so one SPM gives the same inbound under both sides."""

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel
from aiac.policy.model.projection import project_inbound

_TOOL = "team1/github-tool"
_AGENT = "team1/github-agent"


def _user_role(id, *users):
    return Role(id=id, name=id, composite=False, kind=RoleKind.USER, actorIds=list(users))


def _agent_role(id, owner):
    return Role(id=id, name=id, composite=False, kind=RoleKind.AGENT, actorIds=[owner])


def _scope(id):
    return Scope(id=id, name=f"github-tool.{id}", serviceId=_TOOL)


def _spm(allow=(), deny=()) -> ServicePolicyModel:
    return ServicePolicyModel(
        service_id=_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[_scope("source-read"), _scope("issues-read")],
        inbound_allow_rules=list(allow),
        inbound_deny_rules=list(deny),
    )


DEV = _user_role("developer", "dev-user")
TEST = _user_role("tester", "test-user", "dev-user")
AGENT = _agent_role("source_operations", _AGENT)
READ = _scope("source-read")
ISSUES = _scope("issues-read")


def _ids(rules):
    return [(r.role.id, r.scope.id) for r in rules]


def test_user_edges_go_to_the_subject_gate_and_agent_edges_to_the_source_gate():
    allow = [PolicyRule(role=DEV, scope=READ), PolicyRule(role=AGENT, scope=READ)]
    deny = [PolicyRule(role=TEST, scope=READ, effect=RuleEffect.DENY)]

    p = project_inbound(_spm(allow, deny))

    assert _ids(p.subject_allow_rules) == [("developer", "source-read")]
    assert _ids(p.source_allow_rules) == [("source_operations", "source-read")]
    assert _ids(p.subject_deny_rules) == [("tester", "source-read")]
    assert p.source_deny_rules == []


def test_identity_maps_are_effect_agnostic():
    # tester appears only in a deny edge, but still resolves (else the deny never fires).
    allow = [PolicyRule(role=DEV, scope=READ), PolicyRule(role=AGENT, scope=ISSUES)]
    deny = [PolicyRule(role=TEST, scope=ISSUES, effect=RuleEffect.DENY)]

    p = project_inbound(_spm(allow, deny))

    assert {u: [r.id for r in roles] for u, roles in p.subject_roles.items()} == {
        "dev-user": ["developer", "tester"],
        "test-user": ["tester"],
    }
    assert {c: [r.id for r in roles] for c, roles in p.source_roles.items()} == {_AGENT: ["source_operations"]}


def test_duplicate_edges_collapse():
    allow = [PolicyRule(role=DEV, scope=READ), PolicyRule(role=DEV, scope=READ)]

    p = project_inbound(_spm(allow))

    assert _ids(p.subject_allow_rules) == [("developer", "source-read")]
    assert [r.id for r in p.subject_roles["dev-user"]] == ["developer"]


def test_an_spm_with_no_edges_projects_to_empty_gates():
    p = project_inbound(_spm())

    assert p.subject_allow_rules == p.subject_deny_rules == []
    assert p.source_allow_rules == p.source_deny_rules == []
    assert p.subject_roles == p.source_roles == {}
