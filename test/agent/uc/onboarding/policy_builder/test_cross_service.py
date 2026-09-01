"""Unit tests for the cross-service applied-rule gatherer (#2504).

``applied_rules_for_scopes`` supplies the OTHER half of cross-service conflict detection: the
already-applied inbound rules (allow AND deny) of the services that OWN the scopes a build touches,
read from the Policy Store. The builder unions them with its own rules and runs the #2502 core over
the combined state, so this gatherer must (a) read exactly the owning SPMs, once each, (b) return
BOTH inbound lists, (c) never mutate the store, and (d) tolerate a brand-new owner (empty SPM).
These are deterministic (NOT ``integration``/``llm``): the store read is patched, no HTTP happens.

It lives in the onboarding use-case layer (next to ``builder.py``), NOT the PRB package, so the
PRB stays store-free (``test_isolation``) — this test mirrors that source location.
"""

from unittest.mock import patch

from aiac.agent.uc.onboarding.policy_builder.cross_service import applied_rules_for_scopes
from aiac.idp.configuration.models import Role, Scope
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel, ServiceType

_CROSS = "aiac.agent.uc.onboarding.policy_builder.cross_service"

_TESTER = Role(id="r-tester", name="tester", composite=False)
_DEV = Role(id="r-dev", name="developer", composite=False)
# Two scopes owned by two different services (serviceId is the SPM key / owner).
_ISSUES = Scope(id="s-iss", name="issues", serviceId="svc-tool")
_SOURCE = Scope(id="s-src", name="source", serviceId="svc-other")


def _allow(role: Role, scope: Scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)


def _deny(role: Role, scope: Scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)


def _spm(service_id: str, *, allow=None, deny=None) -> ServicePolicyModel:
    return ServicePolicyModel(
        service_id=service_id,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[],
        inbound_allow_rules=allow or [],
        inbound_deny_rules=deny or [],
    )


def test_reads_both_inbound_lists_of_the_scope_owner():
    # The owning SPM already carries a deny on (tester, issues); the gatherer returns it (and any
    # allow) so the builder can intersect it against a fresh allow on the same pair.
    stored = _spm("svc-tool", allow=[_allow(_DEV, _ISSUES)], deny=[_deny(_TESTER, _ISSUES)])
    with patch(f"{_CROSS}.get_service_policy", return_value=stored) as get:
        applied = applied_rules_for_scopes([_allow(_TESTER, _ISSUES)])

    get.assert_called_once_with("svc-tool")  # exactly the scope owner, once
    assert {(r.role.id, r.scope.id, r.effect) for r in applied} == {
        ("r-dev", "s-iss", RuleEffect.ALLOW),
        ("r-tester", "s-iss", RuleEffect.DENY),
    }


def test_reads_each_distinct_owner_once():
    # Rules touching two scopes owned by two services -> one read per distinct owner (deduped),
    # deterministic (sorted) order.
    def _by_id(service_id: str) -> ServicePolicyModel:
        return _spm(service_id, deny=[_deny(_TESTER, _ISSUES if service_id == "svc-tool" else _SOURCE)])

    with patch(f"{_CROSS}.get_service_policy", side_effect=_by_id) as get:
        applied = applied_rules_for_scopes(
            [_allow(_TESTER, _ISSUES), _allow(_DEV, _SOURCE), _deny(_DEV, _ISSUES)]
        )

    assert sorted(c.args[0] for c in get.call_args_list) == ["svc-other", "svc-tool"]
    assert len(applied) == 2


def test_new_owner_with_empty_spm_contributes_nothing():
    # A brand-new scope owner has no stored edges (the store returns a fresh empty SPM on 404).
    with patch(f"{_CROSS}.get_service_policy", return_value=_spm("svc-tool")):
        assert applied_rules_for_scopes([_allow(_TESTER, _ISSUES)]) == []


def test_scopes_without_serviceid_are_skipped():
    # A scope with no resolved owner has no SPM to read — it is simply skipped, never a store call.
    orphan = Scope(id="s-orphan", name="orphan", serviceId="")
    with patch(f"{_CROSS}.get_service_policy") as get:
        assert applied_rules_for_scopes([_allow(_TESTER, orphan)]) == []
    get.assert_not_called()


def test_empty_rules_reads_nothing():
    with patch(f"{_CROSS}.get_service_policy") as get:
        assert applied_rules_for_scopes([]) == []
    get.assert_not_called()
