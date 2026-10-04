"""Unit tests for aiac.pdp.policy.library.api.

The PDP Policy Writer HTTP boundary is mocked; no live service is required.

``aiac.pdp.policy.library`` is a *pass-through* over the canonical policy models:
``api.py`` imports ``AgentPolicyModel`` / ``PolicyModel`` straight from
``aiac.policy.model.models`` (there is no separate library ``models`` module). So the
model-shape + round-trip assertions here exercise the same canonical ALLOW/DENY models the
library serializes over the wire, and the HTTP-client transport stays a pass-through
``model_dump()`` (no ``?realm=``).
"""

from unittest.mock import MagicMock, patch

import pytest

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.policy.model.models import (
    AgentPolicyModel,
    PolicyRule,
    RuleEffect,
    ServicePolicyModel,
    TargetSidePolicyModel,
)

BASE = "http://127.0.0.1:7072"


# ---------------------------------------------------------------------------
# New-shape fixtures (ALLOW/DENY model)
#
# Built from real Role/Scope objects so the fixture dicts are exactly what the
# canonical models serialize to — the HTTP-client body assertions then compare a
# genuine ``model_dump()`` round-trip, and a DENY tuple is present in the fixture.
# ---------------------------------------------------------------------------


def _role(id: str = "role-1", name: str = "reader") -> Role:
    return Role(id=id, name=name, composite=False, kind=RoleKind.AGENT, actorIds=["weather-agent"])


def _scope(id: str = "scope-1", name: str = "read") -> Scope:
    return Scope(id=id, name=name, serviceId="weather-tool")


def _agent_policy_model() -> AgentPolicyModel:
    """A representative agent policy exercising the new ALLOW/DENY shape.

    Populates identity maps, both split target-scope maps, and at least one ALLOW rule and one
    DENY rule across the 8 entity×effect rule lists, so a ``model_dump()`` round-trip is lossless
    for both effects.
    """
    role = _role()
    deny_role = _role(id="role-2", name="blocked")
    scope = _scope()
    allow = PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)
    deny = PolicyRule(role=deny_role, scope=scope, effect=RuleEffect.DENY)
    return AgentPolicyModel(
        agent_id="weather-agent",
        agent_roles=[role],
        agent_scopes=[scope],
        # Effect-agnostic identity maps must include the deny-only role.
        source_roles={"caller-agent": [role]},
        subject_roles={"alice": [role, deny_role]},
        # Split outbound target maps.
        target_allow_scopes={"weather-tool": [scope]},
        target_deny_scopes={"secret-tool": [scope]},
        # 8 entity×effect rule lists (ALLOW + DENY populated).
        inbound_subject_allow_rules=[allow],
        inbound_subject_deny_rules=[deny],
        inbound_source_allow_rules=[allow],
        inbound_source_deny_rules=[deny],
        outbound_target_allow_rules=[allow],
        outbound_target_deny_rules=[deny],
        outbound_subject_allow_rules=[allow],
        outbound_subject_deny_rules=[deny],
    )


_AGENT_MODEL = _agent_policy_model()


def _policy_model() -> TargetSidePolicyModel:
    """A target-side policy model with one tool SPM that carries an allow and a deny edge."""
    scope = Scope(id="scope-1", name="weather-tool.read", serviceId="team1/weather-tool")
    allow = PolicyRule(role=_role(), scope=scope)
    deny = PolicyRule(role=_role(id="role-2", name="blocked"), scope=scope, effect=RuleEffect.DENY)
    return TargetSidePolicyModel(
        services=[
            ServicePolicyModel(
                service_id="team1/weather-tool",
                service_type=ServiceType.TOOL,
                owned_roles=[],
                owned_scopes=[scope],
                inbound_allow_rules=[allow],
                inbound_deny_rules=[deny],
            )
        ]
    )


def _ok(status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.ok = True
    return resp


def _err(status: int = 500) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.ok = False
    resp.text = "internal error"
    return resp


# ---------------------------------------------------------------------------
# Model shape — ALLOW/DENY (field-set assertions)
# ---------------------------------------------------------------------------


class TestModelShape:
    def test_policy_rule_carries_role_scope_effect(self):
        fields = set(PolicyRule.model_fields)
        assert {"role", "scope", "effect"} <= fields

    def test_policy_rule_effect_defaults_to_allow(self):
        rule = PolicyRule(role=_role(), scope=_scope())
        assert rule.effect == RuleEffect.ALLOW

    def test_agent_policy_model_has_split_target_maps(self):
        fields = set(AgentPolicyModel.model_fields)
        assert {"target_allow_scopes", "target_deny_scopes"} <= fields
        # The pre-ALLOW/DENY single map is gone.
        assert "target_scopes" not in fields

    def test_agent_policy_model_has_eight_split_rule_lists(self):
        fields = set(AgentPolicyModel.model_fields)
        assert {
            "inbound_subject_allow_rules",
            "inbound_subject_deny_rules",
            "inbound_source_allow_rules",
            "inbound_source_deny_rules",
            "outbound_target_allow_rules",
            "outbound_target_deny_rules",
            "outbound_subject_allow_rules",
            "outbound_subject_deny_rules",
        } <= fields
        # The pre-ALLOW/DENY intermixed lists are gone.
        assert "inbound_rules" not in fields
        assert "outbound_rules" not in fields

    def test_agent_policy_model_keeps_effect_agnostic_identity_maps(self):
        fields = set(AgentPolicyModel.model_fields)
        assert {"agent_roles", "agent_scopes", "source_roles", "subject_roles"} <= fields


# ---------------------------------------------------------------------------
# Round-trip — lossless, including a DENY tuple
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_agent_policy_model_round_trips_losslessly(self):
        restored = AgentPolicyModel.model_validate(_AGENT_MODEL.model_dump(mode="json"))
        assert restored == _AGENT_MODEL

    def test_deny_tuple_survives_round_trip(self):
        restored = AgentPolicyModel.model_validate(_AGENT_MODEL.model_dump(mode="json"))
        deny_rule = restored.outbound_target_deny_rules[0]
        assert deny_rule.effect == RuleEffect.DENY
        assert deny_rule.role.name == "blocked"
        assert deny_rule.scope.name == "read"
        # DENY-only role still resolvable via the effect-agnostic subject map.
        assert any(r.name == "blocked" for r in restored.subject_roles["alice"])
        # Split target maps survive with the right sides.
        assert "weather-tool" in restored.target_allow_scopes
        assert "secret-tool" in restored.target_deny_scopes

    def test_policy_model_round_trips_losslessly(self):
        model = _policy_model()
        restored = TargetSidePolicyModel.model_validate(model.model_dump(mode="json"))
        assert restored == model
        assert restored.services[0].inbound_deny_rules[0].effect == RuleEffect.DENY


# ---------------------------------------------------------------------------
# apply_policy — POST /policy (upsert one CR per entry)
# ---------------------------------------------------------------------------


class TestApplyPolicy:
    def test_posts_the_tagged_policy_model(self):
        model = _policy_model()
        with patch("aiac.pdp.policy.library.api.requests.post", return_value=_ok()) as m:
            from aiac.pdp.policy.library.api import apply_policy

            result = apply_policy(model)
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/policy"
        body = m.call_args.kwargs["json"]
        assert body == model.model_dump(mode="json")
        assert body["enforcement_side"] == "target-side"
        assert m.call_args.kwargs.get("params") is None

    def test_raises_on_non_2xx(self):
        with patch("aiac.pdp.policy.library.api.requests.post", return_value=_err()):
            from aiac.pdp.policy.library.api import apply_policy

            with pytest.raises(RuntimeError):
                apply_policy(_policy_model())


# ---------------------------------------------------------------------------
# replace_policy — PUT /policy (upsert every entry, then delete every other AIAC CR)
# ---------------------------------------------------------------------------


class TestReplacePolicy:
    def test_puts_the_tagged_policy_model(self):
        model = _policy_model()
        with patch("aiac.pdp.policy.library.api.requests.put", return_value=_ok(204)) as m:
            from aiac.pdp.policy.library.api import replace_policy

            result = replace_policy(model)
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/policy"
        assert m.call_args.kwargs["json"] == model.model_dump(mode="json")

    def test_raises_on_non_2xx(self):
        with patch("aiac.pdp.policy.library.api.requests.put", return_value=_err(502)):
            from aiac.pdp.policy.library.api import replace_policy

            with pytest.raises(RuntimeError):
                replace_policy(_policy_model())


# ---------------------------------------------------------------------------
# delete_service_cr — DELETE /policy/services/{service_id:path}
# ---------------------------------------------------------------------------


class TestDeleteServiceCr:
    def test_deletes_the_service_path_with_the_id_encoded_as_one_segment(self):
        with patch("aiac.pdp.policy.library.api.requests.delete", return_value=_ok(204)) as m:
            from aiac.pdp.policy.library.api import delete_service_cr

            result = delete_service_cr("team1/weather-tool")
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/policy/services/team1%2Fweather-tool"
        assert m.call_args.kwargs.get("params") is None

    def test_raises_on_non_2xx(self):
        with patch("aiac.pdp.policy.library.api.requests.delete", return_value=_err(502)):
            from aiac.pdp.policy.library.api import delete_service_cr

            with pytest.raises(RuntimeError):
                delete_service_cr("team1/weather-tool")

    def test_rejects_an_empty_id(self):
        with patch("aiac.pdp.policy.library.api.requests.delete") as m:
            from aiac.pdp.policy.library.api import delete_service_cr

            with pytest.raises(ValueError):
                delete_service_cr("")
        m.assert_not_called()


class TestRetiredFunctions:
    def test_the_per_agent_functions_are_gone(self):
        import aiac.pdp.policy.library.api as api

        assert not hasattr(api, "apply_agent_policy")
        assert not hasattr(api, "delete_agent_policy")


# ---------------------------------------------------------------------------
# delete_policy — DELETE /policy (every AIAC CR; no AIAC caller, C1)
# ---------------------------------------------------------------------------


class TestDeletePolicy:
    def test_deletes_policy_path(self):
        with patch("aiac.pdp.policy.library.api.requests.delete", return_value=_ok(204)) as m:
            from aiac.pdp.policy.library.api import delete_policy

            result = delete_policy()
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/policy"
        assert m.call_args.kwargs.get("params") is None

    def test_raises_on_non_2xx(self):
        with patch("aiac.pdp.policy.library.api.requests.delete", return_value=_err(500)):
            from aiac.pdp.policy.library.api import delete_policy

            with pytest.raises(RuntimeError):
                delete_policy()


# ---------------------------------------------------------------------------
# AIAC_PDP_POLICY_URL fallback
# ---------------------------------------------------------------------------


class TestUrlFallback:
    def test_defaults_to_localhost_7072_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("AIAC_PDP_POLICY_URL", raising=False)
        with patch("aiac.pdp.policy.library.api.requests.post", return_value=_ok()) as m:
            from aiac.pdp.policy.library.api import apply_policy

            apply_policy(_policy_model())
        assert m.call_args[0][0] == "http://127.0.0.1:7072/policy"


# ---------------------------------------------------------------------------
# No realm query parameter on any request
# ---------------------------------------------------------------------------


class TestNoRealmParam:
    def test_none_of_the_four_functions_append_realm(self):
        policy = _policy_model()
        with (
            patch("aiac.pdp.policy.library.api.requests.post", return_value=_ok()) as post,
            patch("aiac.pdp.policy.library.api.requests.put", return_value=_ok(204)) as put,
            patch("aiac.pdp.policy.library.api.requests.delete", return_value=_ok(204)) as delete,
        ):
            from aiac.pdp.policy.library.api import (
                apply_policy,
                delete_policy,
                delete_service_cr,
                replace_policy,
            )

            apply_policy(policy)
            replace_policy(policy)
            delete_service_cr("team1/weather-tool")
            delete_policy()

        for call in list(post.call_args_list) + list(put.call_args_list) + list(delete.call_args_list):
            assert call.kwargs.get("params") is None
            assert "realm" not in call.args[0]
