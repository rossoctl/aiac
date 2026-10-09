"""Unit tests: under agent side, the APM keeps one outbound subject rule for each copy of a shared scope
(D32, LIM-02).

A shared scope (D32) is one scope (one id) with a copy on each owner (``scope.serviceId``). Each owner's
onboarding is its own PRB pass on its own copy, so each copy has the user rules of its own SPM. The
writer keys each outbound subject rule by the copy that it names (``scope.serviceId``). So the APM must
keep the user rule of EACH copy, also when two copies have the same rule (same role, same scope id,
same effect): with the rule of one copy only, the other copy has no rule. A grant lost on the other
copy denies the user there (fail-closed, but not the verdict of the target side). A deny lost on the
other copy admits the user there through a grant of another role (fail-open).

The read path is ``policy_model_for(agent)`` under agent side: it derives the APM from the stored SPMs
as a deploy does. The IdP (``Configuration``) and the Policy Store library are patched at the engine's
import boundary. Both read orders of the two SPMs are tested: the result must not depend on the order
that the store gives.
"""

import os
from contextlib import ExitStack
from unittest.mock import patch

import pytest

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import Role, RoleKind, Scope, Service, ServiceType
from aiac.policy.computation import engine
from aiac.policy.model.models import AgentPolicyModel, PolicyRule, RuleEffect, ServicePolicyModel

AGENT = "spiffe://localtest.me/ns/team1/sa/github-agent"
TOOL1 = "spiffe://localtest.me/ns/team1/sa/github-tool"
TOOL2 = "spiffe://localtest.me/ns/team2/sa/github-tool"
COPIES = (TOOL1, TOOL2)
SHARED = "s-source-read"  # the one id of the shared scope github-tool.source-read
_MANAGED = {"aiac.managed": ["true"]}


def _role(role_id: str, kind: RoleKind, *actors: str) -> Role:
    return Role(id=role_id, name=role_id, composite=False, attributes=_MANAGED, kind=kind, actorIds=list(actors))


AGENT_ROLE = _role("r-agent", RoleKind.AGENT, AGENT)
OTHER_AGENT_ROLE = _role("r-agent-other", RoleKind.AGENT, AGENT)
DEV = _role("r-dev", RoleKind.USER, "alice")
OPS = _role("r-ops", RoleKind.USER, "olga")


def _copy(owner: str) -> Scope:
    """The copy of the shared scope on ``owner``: the same id and name on each owner."""
    return Scope(id=SHARED, name="github-tool.source-read", attributes={"aiac.managed": "true"}, serviceId=owner)


def _rule(role: Role, scope: Scope, effect: RuleEffect = RuleEffect.ALLOW) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=effect)


def _tool_spm(owner: str, *, agent_roles=(AGENT_ROLE,), grant_dev: bool, deny_ops: bool) -> ServicePolicyModel:
    """The stored SPM of the copy on ``owner``: each of ``agent_roles`` is granted the copy (the agent
    may call it); with ``grant_dev``, DEV is granted the copy; with ``deny_ops``, OPS is denied it."""
    copy = _copy(owner)
    allow = [_rule(role, copy) for role in agent_roles] + ([_rule(DEV, copy)] if grant_dev else [])
    return ServicePolicyModel(
        service_id=owner,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[copy],
        inbound_allow_rules=allow,
        inbound_deny_rules=[_rule(OPS, copy, RuleEffect.DENY)] if deny_ops else [],
    )


def _derived_apm(tool_spms: list[ServicePolicyModel], agent_roles=(AGENT_ROLE,)) -> AgentPolicyModel:
    """The APM of AGENT that ``policy_model_for`` gives under agent side, from the stored SPMs of the
    agent and of the tools. The store gives the tool SPMs in the order of ``tool_spms``."""
    agent_spm = ServicePolicyModel(
        service_id=AGENT, service_type=ServiceType.AGENT, owned_roles=list(agent_roles), owned_scopes=[]
    )
    stored = {model.service_id: model for model in (agent_spm, *tool_spms)}
    catalog = [
        Service(id="uuid-agent", serviceId=AGENT, enabled=True, type=ServiceType.AGENT, roles=list(agent_roles)),
        *(
            Service(
                id=f"uuid-{m.service_id}",
                serviceId=m.service_id,
                enabled=True,
                type=ServiceType.TOOL,
                scopes=list(m.owned_scopes),
            )
            for m in tool_spms
        ),
    ]

    def get_service_policy(service_id: str) -> ServicePolicyModel:
        return stored[service_id].model_copy(deep=True)

    def get_service_policies_by_role(role: Role) -> list[ServicePolicyModel]:
        return [
            m.model_copy(deep=True)
            for m in stored.values()
            if any(r.role.id == role.id for r in m.inbound_allow_rules + m.inbound_deny_rules)
        ]

    def list_service_policies() -> list[ServicePolicyModel]:
        return [m.model_copy(deep=True) for m in stored.values()]

    with ExitStack() as stack:
        stack.enter_context(
            patch.dict(os.environ, {"KEYCLOAK_REALM": "test-realm", "AIAC_ENFORCEMENT_SIDE": "agent-side"})
        )
        stack.enter_context(patch.object(Configuration, "get_services", return_value=catalog))
        stack.enter_context(patch.object(Configuration, "get_roles", return_value=[DEV, OPS]))
        for fake in (get_service_policy, get_service_policies_by_role, list_service_policies):
            stack.enter_context(patch.object(engine, fake.__name__, side_effect=fake))
        model = engine.policy_model_for(AGENT)
    assert model is not None and len(model.agents) == 1
    return model.agents[0]


def _keys(rules: list[PolicyRule]) -> list[tuple[str, str, str, RuleEffect]]:
    """Each rule as (role id, scope id, copy owner, effect), sorted; a duplicate rule stays twice."""
    return sorted((r.role.id, r.scope.id, r.scope.serviceId, r.effect) for r in rules)


ORDERS = {"team1-first": COPIES, "team2-first": tuple(reversed(COPIES))}


@pytest.mark.parametrize("order", list(ORDERS))
def test_two_copies_with_the_same_user_rules_each_keep_their_own_rule(order):
    """Both copies grant DEV and deny OPS: the APM has the grant AND the deny of each copy, each rule
    naming its own copy. With the rule of one copy only, the writer gives the other copy no rule: a
    lost grant denies alice there, and a lost deny admits olga there through a grant of another role
    (fail-open)."""
    spms = [_tool_spm(owner, grant_dev=True, deny_ops=True) for owner in ORDERS[order]]

    apm = _derived_apm(spms)

    assert _keys(apm.outbound_subject_allow_rules) == [
        (DEV.id, SHARED, TOOL1, RuleEffect.ALLOW),
        (DEV.id, SHARED, TOOL2, RuleEffect.ALLOW),
    ]
    assert _keys(apm.outbound_subject_deny_rules) == [
        (OPS.id, SHARED, TOOL1, RuleEffect.DENY),
        (OPS.id, SHARED, TOOL2, RuleEffect.DENY),
    ]


@pytest.mark.parametrize("order", list(ORDERS))
@pytest.mark.parametrize("ruled", COPIES, ids=["team1-copy", "team2-copy"])
def test_a_user_rule_on_one_copy_stays_on_that_copy_only(order, ruled):
    """Only the copy on ``ruled`` grants DEV and denies OPS; the agent may call both copies. Each rule
    names that copy only: the other copy, whose SPM has no user rule, gets none (a grant there is
    fail-open, a deny there is an over-deny)."""
    spms = [_tool_spm(owner, grant_dev=owner == ruled, deny_ops=owner == ruled) for owner in ORDERS[order]]

    apm = _derived_apm(spms)

    assert sorted(apm.target_allow_scopes) == sorted(COPIES), "the agent may call both copies"
    assert _keys(apm.outbound_subject_allow_rules) == [(DEV.id, SHARED, ruled, RuleEffect.ALLOW)]
    assert _keys(apm.outbound_subject_deny_rules) == [(OPS.id, SHARED, ruled, RuleEffect.DENY)]


@pytest.mark.parametrize("order", list(ORDERS))
def test_a_copy_that_two_agent_roles_reach_gives_its_user_rule_once(order):
    """The agent reaches each copy through two of its own roles, so the PCE reads each copy two times:
    each user rule of a copy is still in the APM one time, and each user is in ``subject_roles`` one
    time for each role."""
    roles = (AGENT_ROLE, OTHER_AGENT_ROLE)
    spms = [_tool_spm(owner, agent_roles=roles, grant_dev=True, deny_ops=True) for owner in ORDERS[order]]

    apm = _derived_apm(spms, agent_roles=roles)

    assert _keys(apm.outbound_subject_allow_rules) == [
        (DEV.id, SHARED, TOOL1, RuleEffect.ALLOW),
        (DEV.id, SHARED, TOOL2, RuleEffect.ALLOW),
    ]
    assert _keys(apm.outbound_subject_deny_rules) == [
        (OPS.id, SHARED, TOOL1, RuleEffect.DENY),
        (OPS.id, SHARED, TOOL2, RuleEffect.DENY),
    ]
    assert {user: [r.id for r in held] for user, held in apm.subject_roles.items()} == {
        "alice": [DEV.id],
        "olga": [OPS.id],
    }
