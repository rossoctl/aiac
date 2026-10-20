import pytest
from pydantic import ValidationError

from aiac.idp.configuration.models import (
    Role,
    RoleKind,
    Scope,
    ServiceType,
)
from aiac.policy.model.models import (
    PolicyModel,
    PolicyRule,
    RuleEffect,
    ServicePolicyModel,
)


def _role(id: str = "role-1", name: str = "admin") -> Role:
    return Role(id=id, name=name, composite=False)


def _scope(id: str = "scope-1", name: str = "read") -> Scope:
    return Scope(id=id, name=name)


# --- RoleKind enum + Role.kind / Role.actorIds (SPM redesign) ---


def test_role_kind_values_mirror_service_type_style():
    assert RoleKind.USER == "User"
    assert RoleKind.AGENT == "Agent"


def test_role_accepts_kind_and_actor_ids():
    role = Role(
        id="r1",
        name="weather-reader",
        composite=False,
        kind=RoleKind.AGENT,
        actorIds=["weather-agent"],
    )
    assert role.kind == RoleKind.AGENT
    assert role.actorIds == ["weather-agent"]


def test_role_kind_and_actor_ids_round_trip():
    role = Role(
        id="r1",
        name="reader",
        composite=False,
        kind=RoleKind.USER,
        actorIds=["alice", "bob"],
    )
    restored = Role.model_validate(role.model_dump(mode="json"))
    assert restored.kind == RoleKind.USER
    assert restored.actorIds == ["alice", "bob"]


def test_role_rejects_malformed_kind():
    with pytest.raises(ValidationError):
        Role(id="r1", name="reader", composite=False, kind="Bogus")


def test_role_rejects_non_list_actor_ids():
    with pytest.raises(ValidationError):
        Role(
            id="r1",
            name="reader",
            composite=False,
            kind=RoleKind.USER,
            actorIds="alice",
        )


# --- RuleEffect enum (ALLOW/DENY) ---


def test_rule_effect_values_mirror_service_type_style():
    assert RuleEffect.ALLOW == "Allow"
    assert RuleEffect.DENY == "Deny"


def test_rule_effect_serializes_as_string():
    rule = PolicyRule(role=_role(), scope=_scope(), effect=RuleEffect.DENY)
    assert rule.model_dump(mode="json")["effect"] == "Deny"


# --- Scope.serviceId (SPM routing key) ---


def test_scope_accepts_service_id():
    scope = Scope(id="s1", name="read", serviceId="github-tool")
    assert scope.serviceId == "github-tool"


def test_scope_service_id_round_trip():
    scope = Scope(id="s1", name="read", serviceId="github-tool")
    restored = Scope.model_validate(scope.model_dump(mode="json"))
    assert restored.serviceId == "github-tool"


# --- ServicePolicyModel (persistent source of truth) ---


def test_service_policy_model_constructs_with_split_rule_lists():
    role = _role()
    scope = _scope()
    allow = PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)
    deny = PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)
    spm = ServicePolicyModel(
        service_id="github-tool",
        service_type=ServiceType.TOOL,
        owned_roles=[role],
        owned_scopes=[scope],
        inbound_allow_rules=[allow],
        inbound_deny_rules=[deny],
    )
    assert spm.service_id == "github-tool"
    assert spm.service_type == ServiceType.TOOL
    assert spm.owned_roles == [role]
    assert spm.owned_scopes == [scope]
    assert spm.inbound_allow_rules == [allow]
    assert spm.inbound_deny_rules == [deny]


def test_service_policy_model_has_no_intermixed_inbound_rules_field():
    spm = ServicePolicyModel(
        service_id="svc",
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[],
    )
    # The single intermixed list is gone — allow/deny are explicitly separated.
    assert "inbound_rules" not in ServicePolicyModel.model_fields
    assert not hasattr(spm, "inbound_rules")


def test_service_policy_model_rule_lists_default_empty():
    spm = ServicePolicyModel(
        service_id="svc",
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[],
    )
    assert spm.inbound_allow_rules == []
    assert spm.inbound_deny_rules == []


def test_service_policy_model_round_trip_string_keys_only():
    role = _role()
    scope = _scope()
    spm = ServicePolicyModel(
        service_id="weather-agent",
        service_type=ServiceType.AGENT,
        owned_roles=[role],
        owned_scopes=[scope],
        inbound_allow_rules=[PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)],
        inbound_deny_rules=[PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)],
    )
    dumped = spm.model_dump(mode="json")
    assert all(isinstance(k, str) for k in dumped.keys())
    restored = ServicePolicyModel.model_validate(dumped)
    assert restored == spm


def test_service_policy_model_ignores_extra_fields():
    spm = ServicePolicyModel.model_validate(
        {
            "service_id": "svc",
            "service_type": "Tool",
            "owned_roles": [],
            "owned_scopes": [],
            "inbound_allow_rules": [],
            "inbound_deny_rules": [],
            "unknown_field": "ignored",
        }
    )
    assert not hasattr(spm, "unknown_field")


# --- PolicyRule construction ---


def test_policy_rule_with_typed_role_and_scope():
    role = _role()
    scope = _scope()
    rule = PolicyRule(role=role, scope=scope)
    assert rule.role == role
    assert rule.scope == scope


def test_policy_rule_rejects_plain_str_role():
    with pytest.raises(ValidationError):
        PolicyRule(role="admin", scope=_scope())


def test_policy_rule_rejects_plain_str_scope():
    with pytest.raises(ValidationError):
        PolicyRule(role=_role(), scope="read")


def test_policy_rule_effect_defaults_to_allow():
    rule = PolicyRule(role=_role(), scope=_scope())
    assert rule.effect == RuleEffect.ALLOW


def test_policy_rule_accepts_explicit_deny():
    rule = PolicyRule(role=_role(), scope=_scope(), effect=RuleEffect.DENY)
    assert rule.effect == RuleEffect.DENY


def test_same_role_scope_coexists_as_allow_and_deny():
    role = _role()
    scope = _scope()
    allow = PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)
    deny = PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)
    # Dedup identity is (role.id, scope.id, effect): differing only in effect keeps them distinct,
    # so both survive side by side in a rule list.
    assert allow != deny
    rules = [allow, deny]
    assert rules == [allow, deny]


# --- extra='ignore' on the model types ---


def test_policy_rule_ignores_extra_fields():
    role = _role()
    scope = _scope()
    rule = PolicyRule.model_validate({"role": role.model_dump(), "scope": scope.model_dump(), "unknown": "x"})
    assert not hasattr(rule, "unknown")


def test_policy_model_ignores_extra_fields():
    model = PolicyModel.model_validate({"services": [], "extra_key": "ignored"})
    assert not hasattr(model, "extra_key")


# --- The policy model (D18a) ---


def _spm_body(service_id="team1/github-tool") -> dict:
    return {
        "service_id": service_id,
        "service_type": "Tool",
        "owned_roles": [],
        "owned_scopes": [{"id": "s1", "name": "github-tool.source-read"}],
    }


def test_policy_model_body_parses_to_its_services():
    model = PolicyModel.model_validate({"services": [_spm_body()]})
    assert [spm.service_id for spm in model.services] == ["team1/github-tool"]


def test_policy_model_without_services_is_rejected():
    with pytest.raises(ValidationError):
        PolicyModel.model_validate({})


def test_policy_model_round_trips_through_json():
    model = PolicyModel(services=[ServicePolicyModel.model_validate(_spm_body())])
    dumped = model.model_dump(mode="json")
    assert set(dumped) == {"services"}
    assert PolicyModel.model_validate(dumped) == model
