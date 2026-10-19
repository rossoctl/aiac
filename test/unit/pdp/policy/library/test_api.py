"""Unit tests for aiac.pdp.policy.library.api.

The PDP Policy Writer HTTP boundary is mocked; no live service is required.

``aiac.pdp.policy.library`` is a *pass-through* over the canonical policy models:
``api.py`` imports ``PolicyModel`` straight from ``aiac.policy.model.models`` (there is
no separate library ``models`` module). So the model-shape + round-trip assertions here
exercise the same canonical ALLOW/DENY models (``PolicyModel`` with its SPMs)
that the library serializes over the wire, and the HTTP-client transport stays a
pass-through ``model_dump()`` (no ``?realm=``).
"""

from unittest.mock import MagicMock, patch

import pytest

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.policy.model.models import (
    PolicyModel,
    PolicyRule,
    RuleEffect,
    ServicePolicyModel,
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


def _policy_model() -> PolicyModel:
    """A policy model with one tool SPM that carries an allow and a deny edge."""
    scope = Scope(id="scope-1", name="weather-tool.read", serviceId="team1/weather-tool")
    allow = PolicyRule(role=_role(), scope=scope)
    deny = PolicyRule(role=_role(id="role-2", name="blocked"), scope=scope, effect=RuleEffect.DENY)
    return PolicyModel(
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


# ---------------------------------------------------------------------------
# Round-trip — lossless, including a DENY tuple
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_policy_model_round_trips_losslessly(self):
        model = _policy_model()
        restored = PolicyModel.model_validate(model.model_dump(mode="json"))
        assert restored == model
        assert restored.services[0].inbound_deny_rules[0].effect == RuleEffect.DENY


# ---------------------------------------------------------------------------
# apply_policy — POST /policy (upsert one CR per entry)
# ---------------------------------------------------------------------------


class TestApplyPolicy:
    def test_posts_the_policy_model(self):
        model = _policy_model()
        with patch("aiac.pdp.policy.library.api.requests.post", return_value=_ok()) as m:
            from aiac.pdp.policy.library.api import apply_policy

            result = apply_policy(model)
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/policy"
        body = m.call_args.kwargs["json"]
        assert body == model.model_dump(mode="json")
        assert set(body) == {"services"}
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
    def test_puts_the_policy_model(self):
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


class TestTimeout:
    # A hung writer must not block the caller, which holds the PCE lock, indefinitely.
    @pytest.mark.parametrize(
        ("method", "call"),
        [
            ("post", lambda api: api.apply_policy(_policy_model())),
            ("put", lambda api: api.replace_policy(_policy_model())),
            ("delete", lambda api: api.delete_service_cr("team1/weather-tool")),
            ("delete", lambda api: api.delete_policy()),
        ],
        ids=["apply_policy", "replace_policy", "delete_service_cr", "delete_policy"],
    )
    def test_every_call_sends_the_timeout(self, method, call):
        import aiac.pdp.policy.library.api as api

        with patch(f"aiac.pdp.policy.library.api.requests.{method}", return_value=_ok(204)) as m:
            call(api)
        assert m.call_args.kwargs["timeout"] == api._HTTP_TIMEOUT_DEFAULT

    @pytest.mark.parametrize(
        ("value", "expected"), [("15", 15.0), ("60s", 60.0), ("", 60.0), ("0", 60.0), ("inf", 60.0)]
    )
    def test_a_bad_value_falls_back_to_the_default(self, monkeypatch, value, expected):
        import aiac.pdp.policy.library.api as api

        monkeypatch.setenv("AIAC_PDP_HTTP_TIMEOUT", value)
        assert api._http_timeout() == expected


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
