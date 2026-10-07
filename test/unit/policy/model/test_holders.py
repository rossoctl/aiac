"""The render-time role holders (D32): who holds a role now, from current IdP data, not from the
``actorIds`` copy that a stored edge keeps. ``RoleHolders`` is pure: the tests give it the catalog
(``get_services()``) and the realm roles (``get_roles()``) and read what it gives back."""

from aiac.idp.configuration.models import Role, RoleKind, Scope, Service, ServiceType
from aiac.policy.model.holders import RoleHolders
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel

_AGENT_1 = "spiffe://localtest.me/ns/team1/sa/github-agent"
_AGENT_2 = "spiffe://localtest.me/ns/team2/sa/github-agent"
_TOOL = "spiffe://localtest.me/ns/team1/sa/github-tool"


def _agent_role(id, *holders):
    return Role(id=id, name=id, composite=False, kind=RoleKind.AGENT, actorIds=list(holders))


def _user_role(id, *users):
    return Role(id=id, name=id, composite=False, kind=RoleKind.USER, actorIds=list(users))


def _agent(service_id, *roles, enabled=True):
    # Each service's copy of a shared role names only that service (``GET /services/{id}/roles``).
    copies = [role.model_copy(update={"actorIds": [service_id]}) for role in roles]
    return Service(id=f"uuid-{service_id}", serviceId=service_id, enabled=enabled, type=ServiceType.AGENT, roles=copies)


SHARED = _agent_role("github-agent.source_operations")
DEV = _user_role("developer", "dev-user")
READ = Scope(id="source-read", name="github-tool.source-read", serviceId=_TOOL)


def _spm(allow=(), deny=()):
    return ServicePolicyModel(
        service_id=_TOOL,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[READ],
        inbound_allow_rules=list(allow),
        inbound_deny_rules=list(deny),
    )


# --------------------------------------------------------------------------- #
# Agent-kind roles — the live services in the catalog that hold the role.      #
# --------------------------------------------------------------------------- #
def test_an_agent_role_is_held_by_every_live_service_that_has_it():
    holders = RoleHolders([_agent(_AGENT_2, SHARED), _agent(_AGENT_1, SHARED)])

    assert holders.of(_agent_role(SHARED.id, _AGENT_1)) == [_AGENT_1, _AGENT_2]  # sorted, not the stored copy


def test_the_catalog_order_does_not_change_the_holders():
    one = RoleHolders([_agent(_AGENT_1, SHARED), _agent(_AGENT_2, SHARED)])
    two = RoleHolders([_agent(_AGENT_2, SHARED), _agent(_AGENT_1, SHARED)])

    assert one.of(SHARED) == two.of(SHARED) == [_AGENT_1, _AGENT_2]


def test_a_disabled_service_is_not_a_holder():
    holders = RoleHolders([_agent(_AGENT_1, SHARED), _agent(_AGENT_2, SHARED, enabled=False)])

    assert holders.of(SHARED) == [_AGENT_1]


def test_the_focus_service_is_a_holder_while_it_is_disabled():
    # A re-onboarding applies before ``reenable_service``: the focus service counts as live.
    holders = RoleHolders([_agent(_AGENT_1, SHARED, enabled=False)], focus_service=_AGENT_1)

    assert holders.of(SHARED) == [_AGENT_1]


def test_an_agent_role_that_no_live_service_has_has_no_holder():
    holders = RoleHolders([_agent(_AGENT_1)])

    assert holders.of(_agent_role(SHARED.id, _AGENT_1)) == []


def test_an_agent_role_is_not_resolved_from_the_realm_roles():
    # GET /roles lists every realm role, also an agent role (with its service-account members). The
    # holders of an Agent-kind role come from the catalog only.
    holders = RoleHolders([], [_user_role(SHARED.id, "service-account-github-agent")])

    assert holders.of(SHARED) == []


# --------------------------------------------------------------------------- #
# User-kind roles — the members that get_roles() gives now.                    #
# --------------------------------------------------------------------------- #
def test_a_user_role_is_held_by_its_current_members():
    holders = RoleHolders([], [_user_role("developer", "dev-user", "alice")])

    assert holders.of(DEV) == ["alice", "dev-user"]


def test_a_user_role_that_get_roles_does_not_list_has_no_holder():
    # A deleted role: fail closed.
    holders = RoleHolders([], [_user_role("ops", "ops-user")])

    assert holders.of(DEV) == []


def test_a_user_role_is_not_resolved_from_the_catalog():
    # The kind of the role in the edge selects the source of truth.
    holders = RoleHolders([_agent(_AGENT_1, _agent_role("developer"))], [])

    assert holders.of(DEV) == []


# --------------------------------------------------------------------------- #
# Refresh — a role, a rule and a whole SPM, as copies; the input is unchanged. #
# --------------------------------------------------------------------------- #
def test_refresh_role_sets_the_current_holders_on_a_copy():
    stale = _agent_role(SHARED.id, _AGENT_1)
    holders = RoleHolders([_agent(_AGENT_1, SHARED), _agent(_AGENT_2, SHARED)])

    fresh = holders.refresh_role(stale)

    assert fresh == stale.model_copy(update={"actorIds": [_AGENT_1, _AGENT_2]})
    assert stale.actorIds == [_AGENT_1]


def test_refresh_rule_keeps_the_scope_and_the_effect():
    rule = PolicyRule(role=_user_role("developer", "gone-user"), scope=READ, effect=RuleEffect.DENY)
    holders = RoleHolders([], [_user_role("developer", "dev-user")])

    assert holders.refresh_rule(rule) == PolicyRule(role=DEV, scope=READ, effect=RuleEffect.DENY)


def test_refresh_model_refreshes_every_edge_in_both_lists_and_keeps_their_order():
    stale_agent = _agent_role(SHARED.id, _AGENT_1)
    stale_user = _user_role("developer", "gone-user")
    tester = _user_role("tester", "test-user")
    model = _spm(
        allow=[PolicyRule(role=stale_user, scope=READ), PolicyRule(role=stale_agent, scope=READ)],
        deny=[PolicyRule(role=tester, scope=READ, effect=RuleEffect.DENY)],
    )
    holders = RoleHolders(
        [_agent(_AGENT_1, SHARED), _agent(_AGENT_2, SHARED)],
        [_user_role("developer", "dev-user"), _user_role("tester", "test-user")],
    )

    fresh = holders.refresh_model(model)

    assert fresh == _spm(
        allow=[
            PolicyRule(role=DEV, scope=READ),
            PolicyRule(role=_agent_role(SHARED.id, _AGENT_1, _AGENT_2), scope=READ),
        ],
        deny=[PolicyRule(role=tester, scope=READ, effect=RuleEffect.DENY)],
    )
    assert model.inbound_allow_rules[1].role.actorIds == [_AGENT_1]  # the input is unchanged


def test_a_refreshed_model_is_a_separate_copy():
    # The PCE changes its cached SPM in place (route, purge); that must not change the input.
    model = _spm(allow=[PolicyRule(role=DEV, scope=READ)])
    fresh = RoleHolders([], [DEV]).refresh_model(model)

    fresh.inbound_allow_rules.append(PolicyRule(role=SHARED, scope=READ))
    fresh.owned_scopes.append(Scope(id="other", name="other"))

    assert model == _spm(allow=[PolicyRule(role=DEV, scope=READ)])
