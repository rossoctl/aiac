"""Unit tests for the Policy Computation Engine (``aiac.policy.computation.engine``, SPM-based).

The engine routes each pre-flattened ``PolicyRule`` to the ``ServicePolicyModel`` (SPM) of the
service that *owns* the rule's scope (``scope.serviceId``), persists the changed SPMs, and then
deploys the policy model of the affected live services with one ``apply_policy`` call (D23): a
``PolicyModel`` (the touched SPMs). Quarantine and decommission delete the CR of the service
(``delete_service_cr``, D20); ``resync`` replaces every AIAC CR (``replace_policy``, D28);
``policy_model_for`` reads one service's entry (D18); ``bootstrap`` writes the focus tool's first CR.

Tests assert external behaviour — what the engine writes to the Policy Store (SPMs) and pushes to
the PDP (policy models, CR deletes) — not internal merge logic. All downstream dependencies are
mocked at the engine's import boundary via a small in-memory ``FakeStore`` that behaves like the
real Policy Store library (fresh-empty SPM on 404, ``get_service_policies_by_role`` scanning both
inbound lists, ``list_service_policies`` returning every stored SPM):
  - ``Configuration.get_services``                          (IdP catalog: type + own roles/scopes)
  - ``Configuration.get_roles``                             (the current members of each user role)
  - ``engine.get_service_policy`` / ``get_service_policies_by_role`` / ``list_service_policies`` /
    ``apply_service_policy`` / ``delete_service_policy``    (Policy Store library)
  - ``engine.apply_policy`` / ``replace_policy`` / ``delete_service_cr``  (PDP Policy Writer library)

The expected values are literals.
"""

import os
import threading
from contextlib import ExitStack, contextmanager
from unittest.mock import MagicMock, patch

import pytest

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import Role, RoleKind, Scope, Service, ServiceType
from aiac.policy.model.models import (
    PolicyModel,
    PolicyRule,
    RuleEffect,
    ServicePolicyModel,
)
from aiac.policy.model.projection import project_inbound


# --------------------------------------------------------------------------- #
# builders                                                                    #
# --------------------------------------------------------------------------- #
def _role(
    id, name=None, *, kind=RoleKind.USER, actor_ids=None, composite=False, children=None, aiac_managed=True
) -> Role:
    attributes = {"aiac.managed": ["true"]} if aiac_managed else {}
    return Role(
        id=id,
        name=name or id,
        composite=composite,
        childRoles=children or [],
        attributes=attributes,
        kind=kind,
        actorIds=actor_ids or [],
    )


def _user_role(id, name=None, *, users) -> Role:
    return _role(id, name, kind=RoleKind.USER, actor_ids=users)


def _agent_role(id, name=None, *, owner) -> Role:
    return _role(id, name, kind=RoleKind.AGENT, actor_ids=[owner])


def _scope(id, name=None, *, service_id="", aiac_managed=True) -> Scope:
    attributes = {"aiac.managed": "true"} if aiac_managed else {}
    return Scope(id=id, name=name or id, attributes=attributes, serviceId=service_id)


def _service(service_id, *, type=None, roles=None, scopes=None, enabled=True) -> Service:
    return Service(
        id=f"uuid-{service_id}",
        serviceId=service_id,
        enabled=enabled,
        type=type,
        roles=roles or [],
        scopes=scopes or [],
    )


def _agent(service_id, *, roles=None, scopes=None, enabled=True) -> Service:
    return _service(service_id, type=ServiceType.AGENT, roles=roles, scopes=scopes, enabled=enabled)


def _tool(service_id, *, roles=None, scopes=None, enabled=True) -> Service:
    return _service(service_id, type=ServiceType.TOOL, roles=roles, scopes=scopes, enabled=enabled)


def _rule(role, scope, effect=RuleEffect.ALLOW) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=effect)


def _deny(role, scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)


def _spm(
    service_id, *, type=ServiceType.AGENT, owned_roles=None, owned_scopes=None, inbound=None
) -> ServicePolicyModel:
    # ``inbound`` accepts a mixed list of rules; each is filed into the allow/deny list by its
    # ``effect`` (so existing all-allow call sites keep working and deny edges route correctly).
    rules = inbound or []
    return ServicePolicyModel(
        service_id=service_id,
        service_type=type,
        owned_roles=owned_roles or [],
        owned_scopes=owned_scopes or [],
        inbound_allow_rules=[r for r in rules if r.effect == RuleEffect.ALLOW],
        inbound_deny_rules=[r for r in rules if r.effect == RuleEffect.DENY],
    )


def _inbound(spm) -> list[PolicyRule]:
    """Both inbound lists of an SPM concatenated — a combined view for assertions."""
    return spm.inbound_allow_rules + spm.inbound_deny_rules


# --------------------------------------------------------------------------- #
# harness — an in-memory Policy Store behaving like the real library          #
# --------------------------------------------------------------------------- #
class FakeStore:
    def __init__(self, initial=None):
        self.data = {sid: m.model_copy(deep=True) for sid, m in (initial or {}).items()}
        self.calls = []  # [(op, arg)] — every store write and PDP call, in order
        self.service_writes = []  # [(service_id, SPM)] captured from apply_service_policy
        self.by_role_calls = []  # [Role] captured from get_service_policies_by_role
        self.policy_pushes = []  # [PolicyModel] captured from apply_policy (POST /policy)
        self.policy_replaces = []  # [PolicyModel] captured from replace_policy (PUT /policy)
        self.service_deletes = []  # [service_id] captured from delete_service_policy
        self.cr_deletes = []  # [service_id] captured from delete_service_cr

    def get_service_policy(self, service_id):
        if service_id in self.data:
            return self.data[service_id].model_copy(deep=True)
        return _spm(service_id)  # real lib returns a fresh empty SPM on 404

    def find_service_policy(self, service_id):
        return self.data[service_id].model_copy(deep=True) if service_id in self.data else None

    def _scan_by_role(self, role):
        return [
            m.model_copy(deep=True)
            for m in self.data.values()
            if any(r.role.id == role.id for r in (m.inbound_allow_rules + m.inbound_deny_rules))
        ]

    def get_service_policies_by_role(self, role):
        self.by_role_calls.append(role)
        return self._scan_by_role(role)

    def list_service_policies(self):
        return [m.model_copy(deep=True) for m in self.data.values()]

    def apply_service_policy(self, service_id, spm):
        self.calls.append(("write", service_id))
        self.service_writes.append((service_id, spm.model_copy(deep=True)))
        self.data[service_id] = spm.model_copy(deep=True)

    def delete_service_policy(self, service_id):
        self.calls.append(("delete", service_id))
        self.service_deletes.append(service_id)
        self.data.pop(service_id, None)

    def apply_policy(self, model):
        self.calls.append(("apply_policy", model))
        self.policy_pushes.append(model.model_copy(deep=True))

    def replace_policy(self, model):
        self.calls.append(("replace_policy", model))
        self.policy_replaces.append(model.model_copy(deep=True))

    def delete_service_cr(self, service_id):
        self.calls.append(("delete_service_cr", service_id))
        self.cr_deletes.append(service_id)

    # ---- assertion helpers ------------------------------------------------ #
    @property
    def apply_policy_count(self):
        return len(self.policy_pushes)

    @property
    def last_push(self):
        return self.policy_pushes[-1] if self.policy_pushes else None

    def pushed_service(self, service_id):
        """The most recent entry (an SPM) for ``service_id`` across all pushes."""
        for push in reversed(self.policy_pushes):
            for spm in push.services:
                if spm.service_id == service_id:
                    return spm
        return None

    @property
    def pushed_service_ids(self):
        return {spm.service_id for push in self.policy_pushes for spm in push.services}


_BOUNDARY = (
    "get_service_policy",
    "find_service_policy",
    "get_service_policies_by_role",
    "list_service_policies",
    "apply_service_policy",
    "delete_service_policy",
    "apply_policy",
    "replace_policy",
    "delete_service_cr",
)


@contextmanager
def engine_env(catalog, store, roles=None):
    """Patch the engine boundary; yield ``compute_and_apply``. Multiple calls share the store.

    ``Configuration.get_roles`` (the current members of each user role, D32) gives ``roles`` when the
    test gives them. Else the realm agrees with every snapshot the test gives: each User-kind role in
    the store and in the rules given so far, with its own ``actorIds`` (the latest rule wins). A test
    that changes the membership of a user role gives ``roles``."""
    given: dict[str, Role] = {}

    def get_roles():
        if roles is not None:
            return list(roles)
        found = {r.role.id: r.role for m in store.data.values() for r in _inbound(m) if r.role.kind == RoleKind.USER}
        return list({**found, **given}.values())

    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"KEYCLOAK_REALM": "test-realm"}))
        stack.enter_context(patch.object(Configuration, "get_services", return_value=list(catalog)))
        stack.enter_context(patch.object(Configuration, "get_roles", side_effect=get_roles))
        for name in _BOUNDARY:
            stack.enter_context(patch(f"aiac.policy.computation.engine.{name}", side_effect=getattr(store, name)))
        from aiac.policy.computation.engine import compute_and_apply

        def compute(rules, *args, **kwargs):
            given.update({r.role.id: r.role for r in rules if r.role.kind == RoleKind.USER})
            return compute_and_apply(rules, *args, **kwargs)

        yield compute


def run_engine(rules, *, catalog=None, store_initial=None, override=False, focus_service=None, roles=None) -> FakeStore:
    store = FakeStore(store_initial)
    with engine_env(catalog or [], store, roles) as compute_and_apply:
        if focus_service is None:
            compute_and_apply(rules, override=override)
        else:
            compute_and_apply(rules, override=override, focus_service=focus_service)
    return store


# --------------------------------------------------------------------------- #
# comparison helpers                                                          #
# --------------------------------------------------------------------------- #
def _pairs(rules):
    return sorted((r.role.id, r.scope.id) for r in rules)


# --------------------------------------------------------------------------- #
# shared repro fixture — the order-dependence scenario                        #
#   UR (user role) -> AS (agent A's scope)  and  -> TS (tool T's scope)        #
#   AR (agent A's client role) -> TS                                           #
# --------------------------------------------------------------------------- #
def _repro():
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [
        _agent("github-agent", roles=[AR], scopes=[AS]),
        _tool("github-tool", scopes=[TS]),
    ]
    return AR, UR, AS, TS, catalog


# --------------------------------------------------------------------------- #
# Cycle 1 — tracer: a (user role, agent scope) rule lands as an inbound edge    #
# on SPM(A); the stored SPM(A) is pushed as A's entry, once.                   #
# --------------------------------------------------------------------------- #
def test_user_role_agent_scope_lands_inbound_and_pushes_once():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS)], catalog=catalog)

    # persisted on SPM(github-agent) — an Allow (user role, agent scope) edge
    assert store.service_writes[0][0] == "github-agent"
    assert _pairs(store.data["github-agent"].inbound_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert store.data["github-agent"].inbound_deny_rules == []
    # deployed as the agent's entry: the stored SPM itself
    assert store.apply_policy_count == 1
    assert isinstance(store.last_push, PolicyModel)
    assert store.last_push.services == [store.data["github-agent"]]


# --------------------------------------------------------------------------- #
# Cycle 4 — HEADLINE: both onboarding orders converge — the same stored       #
# SPM(T) and the same deployed entry of T.                                    #
# --------------------------------------------------------------------------- #
def _both_orders():
    AR, UR, AS, TS, catalog = _repro()

    # order A-then-T: agent onboarded (UR->AS), then tool onboarded (AR->TS, UR->TS)
    store_at = FakeStore()
    with engine_env(catalog, store_at) as compute:
        compute([_rule(UR, AS)])
        compute([_rule(AR, TS), _rule(UR, TS)])

    # order T-then-A: tool onboarded first, then agent
    store_ta = FakeStore()
    with engine_env(catalog, store_ta) as compute:
        compute([_rule(AR, TS), _rule(UR, TS)])
        compute([_rule(UR, AS)])
    return store_at, store_ta


def test_both_orders_yield_identical_entry_for_the_tool():
    store_at, store_ta = _both_orders()

    assert store_at.data["github-tool"] == store_ta.data["github-tool"]
    assert store_at.pushed_service("github-tool") == store_ta.pushed_service("github-tool")
    assert _pairs(store_at.pushed_service("github-tool").inbound_allow_rules) == [
        ("r-agent-src", "s-tool-read"),
        ("r-user-dev", "s-tool-read"),
    ]


# --------------------------------------------------------------------------- #
# Cycle 5 — latent sibling bug: after A+T exist, a late (UR2 -> TS) user-role    #
# rule routes to SPM(T); only T's entry is redeployed, with UR2.                #
# --------------------------------------------------------------------------- #
def _late_user_role_store():
    AR, UR, AS, TS, catalog = _repro()
    store = FakeStore()
    with engine_env(catalog, store) as compute:
        compute([_rule(UR, AS), _rule(AR, TS), _rule(UR, TS)])  # A + T established
        UR2 = _user_role("r-user-ops", "ops", users=["ops-user"])
        compute([_rule(UR2, TS)])  # late UC3 user role on the tool
    return store


def test_late_user_role_on_tool_redeploys_only_the_tool_entry():
    store = _late_user_role_store()

    late = store.last_push
    assert [spm.service_id for spm in late.services] == ["github-tool"]  # T changed; A did not
    assert ("r-user-ops", "s-tool-read") in _pairs(late.services[0].inbound_allow_rules)


# --------------------------------------------------------------------------- #
# Cycle 6 — agent -> agent (AR -> BS): stored on SPM(B); only B's entry is    #
# deployed.                                                                   #
# --------------------------------------------------------------------------- #
def _agent_to_agent():
    AR = _agent_role("r-a-caller", "a-caller", owner="agent-a")
    BS = _scope("s-b-inbound", "b-inbound", service_id="agent-b")
    catalog = [
        _agent("agent-a", roles=[AR], scopes=[_scope("s-a-inbound", service_id="agent-a")]),
        _agent("agent-b", scopes=[BS]),
    ]
    return run_engine([_rule(AR, BS)], catalog=catalog)


def test_agent_to_agent_edge_deploys_only_the_callee_entry():
    store = _agent_to_agent()

    assert store.pushed_service_ids == {"agent-b"}  # SPM(A) did not change
    assert "agent-a" not in store.data
    assert _pairs(store.pushed_service("agent-b").inbound_allow_rules) == [("r-a-caller", "s-b-inbound")]


# --------------------------------------------------------------------------- #
# Cycle 7 — override purge across SPMs: an input role present on multiple SPMs   #
# is purged from every one of them, once, before the fresh rule is appended.     #
# --------------------------------------------------------------------------- #
def test_override_purges_input_role_from_every_spm():
    shared = _user_role("r-shared", "shared", users=["u"])
    s1 = _scope("s-one", service_id="svc-one")
    s2 = _scope("s-two", service_id="svc-two")
    catalog = [_agent("svc-one", scopes=[s1]), _agent("svc-two", scopes=[s2])]
    initial = {
        "svc-one": _spm("svc-one", owned_scopes=[s1], inbound=[_rule(shared, s1)]),
        "svc-two": _spm("svc-two", owned_scopes=[s2], inbound=[_rule(shared, s2)]),
    }
    # override with the same role targeting only svc-one now
    store = run_engine([_rule(shared, s1)], catalog=catalog, store_initial=initial, override=True)

    # svc-two's stale mapping for the shared role is gone; svc-one keeps the fresh one
    assert _pairs(_inbound(store.data["svc-two"])) == []
    assert _pairs(_inbound(store.data["svc-one"])) == [("r-shared", "s-one")]
    # purge scanned by role, once for the single distinct input role
    assert [r.id for r in store.by_role_calls].count("r-shared") == 1


# --------------------------------------------------------------------------- #
# Cycle 8 — override, two input rules sharing one role: the role is purged once  #
# up-front, so the SECOND rule's freshly-appended mapping is not wiped.          #
# --------------------------------------------------------------------------- #
def test_override_shared_role_purged_once_second_mapping_survives():
    shared = _user_role("r-shared", "shared", users=["u"])
    s1 = _scope("s-one", service_id="svc-one")
    s2 = _scope("s-two", service_id="svc-two")
    catalog = [_agent("svc-one", scopes=[s1]), _agent("svc-two", scopes=[s2])]
    initial = {
        "svc-one": _spm("svc-one", owned_scopes=[s1], inbound=[_rule(shared, s1)]),
        "svc-two": _spm("svc-two", owned_scopes=[s2]),
    }
    store = run_engine(
        [_rule(shared, s1), _rule(shared, s2)],
        catalog=catalog,
        store_initial=initial,
        override=True,
    )

    assert _pairs(_inbound(store.data["svc-one"])) == [("r-shared", "s-one")]
    assert _pairs(_inbound(store.data["svc-two"])) == [("r-shared", "s-two")]  # not wiped


# --------------------------------------------------------------------------- #
# Cycle 9 — append dedup: a rule already on the target SPM (same role.id +       #
# scope.id) is not appended a second time.                                      #
# --------------------------------------------------------------------------- #
def test_duplicate_rule_not_appended_twice():
    AR, UR, AS, TS, catalog = _repro()
    initial = {"github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(UR, AS)])}
    store = run_engine([_rule(UR, AS)], catalog=catalog, store_initial=initial)

    assert len(_inbound(store.data["github-agent"])) == 1


# --------------------------------------------------------------------------- #
# Cycle 10 — no flattening: a composite input role never triggers per-child      #
# get_service_policies_by_role calls.                                            #
# --------------------------------------------------------------------------- #
def test_composite_role_is_not_flattened():
    child_a = _agent_role("r-child-a", "child-a", owner="github-agent")
    child_b = _agent_role("r-child-b", "child-b", owner="github-agent")
    composite = _agent_role("r-comp", "composite", owner="github-agent")
    composite = composite.model_copy(update={"composite": True, "childRoles": [child_a, child_b]})
    TS = _scope("s-tool-read", service_id="github-tool")
    catalog = [_agent("github-agent", roles=[composite]), _tool("github-tool", scopes=[TS])]

    store = run_engine([_rule(composite, TS)], catalog=catalog, override=True)

    queried = {r.id for r in store.by_role_calls}
    assert "r-child-a" not in queried and "r-child-b" not in queried


# --------------------------------------------------------------------------- #
# Cycle 11 — every managed service gets a CR (rule P4 is gone): a tool's stored  #
# SPM is its entry.                                                             #
# --------------------------------------------------------------------------- #
def test_tool_gets_its_stored_spm_as_its_entry():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(AR, TS)], catalog=catalog)

    assert _pairs(store.data["github-tool"].inbound_allow_rules) == [("r-agent-src", "s-tool-read")]
    assert store.last_push.services == [store.data["github-tool"]]
    assert store.last_push.services[0].service_type == ServiceType.TOOL


# --------------------------------------------------------------------------- #
# Cycle 12 — P2 identity from owned_*: the deployed SPM embeds the agent's own   #
# aiac.managed roles/scopes; built-ins are filtered; an agent with none keeps []. #
# --------------------------------------------------------------------------- #
def test_p2_identity_embeds_aiac_managed_owned_roles_and_scopes():
    helper = _agent_role("r-helper", "helper", owner="github-agent")
    builtin = _agent_role("r-default", "default-roles-aiac", owner="github-agent")
    builtin = builtin.model_copy(update={"attributes": {}})  # not aiac.managed
    src = _scope("s-src", "source", service_id="github-agent")
    profile = _scope("s-profile", "profile", service_id="github-agent", aiac_managed=False)
    agent = _agent("github-agent", roles=[helper, builtin], scopes=[src, profile])
    UR = _user_role("r-user", users=["u"])
    store = run_engine([_rule(UR, src)], catalog=[agent])

    spm = store.pushed_service("github-agent")
    assert [r.id for r in spm.owned_roles] == ["r-helper"]  # built-in role dropped
    assert [s.id for s in spm.owned_scopes] == ["s-src"]  # profile scope dropped


def test_p2_identity_empty_when_no_owned_entities():
    agent = _agent("github-agent")  # no catalog roles/scopes
    UR = _user_role("r-user", users=["u"])
    store = run_engine([_rule(UR, _scope("s-x", service_id="github-agent"))], catalog=[agent])

    spm = store.pushed_service("github-agent")
    assert spm.owned_roles == [] and spm.owned_scopes == []


# --------------------------------------------------------------------------- #
# Cycle 14 — the affected set is the changed set: a service unrelated to the     #
# batch is never deployed, even though it exists in the catalog and the store.   #
# --------------------------------------------------------------------------- #
def test_unrelated_service_is_not_deployed():
    AR, UR, AS, TS, catalog = _repro()
    OS = _scope("s-other", service_id="other-agent")
    catalog = catalog + [_agent("other-agent", scopes=[OS])]
    initial = {"other-agent": _spm("other-agent", owned_scopes=[OS], inbound=[_rule(UR, OS)])}
    store = run_engine([_rule(UR, AS)], catalog=catalog, store_initial=initial)

    assert store.pushed_service_ids == {"github-agent"}


# --------------------------------------------------------------------------- #
# The affected set (D23): the touched SPMs. An agent that targets the touched   #
# tool, and an unrelated agent, are not deployed.                                 #
# --------------------------------------------------------------------------- #
def test_the_affected_set_is_the_touched_spms():
    AR, UR, AS, TS, catalog = _repro()
    US = _scope("s-other", service_id="other-agent")
    catalog = catalog + [_agent("other-agent", scopes=[US])]
    initial = {
        "github-tool": _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS)]),
        "other-agent": _spm("other-agent", owned_scopes=[US], inbound=[_rule(UR, US)]),
    }
    store = run_engine([_rule(UR, TS)], catalog=catalog, store_initial=initial, focus_service="github-tool")

    tool = _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS), _rule(UR, TS)])
    assert store.data["github-tool"] == tool
    assert store.policy_pushes == [PolicyModel(services=[tool])]


# --------------------------------------------------------------------------- #
# Cycle 15 — apply_policy is called exactly once, after every SPM write.          #
# --------------------------------------------------------------------------- #
def test_apply_policy_called_exactly_once_after_all_spm_writes():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS), _rule(AR, TS), _rule(UR, TS)], catalog=catalog)

    assert store.apply_policy_count == 1
    # both SPMs (agent + tool) were persisted before the single push, which carries both
    assert [op for op, _ in store.calls] == ["write", "write", "apply_policy"]
    assert {sid for sid, _ in store.service_writes} == {"github-agent", "github-tool"}
    assert store.pushed_service_ids == {"github-agent", "github-tool"}


# --------------------------------------------------------------------------- #
# D21 — the zero-rule focus SPM. A run with a focus service always stores        #
# SPM(focus), seeded from the catalog, also with zero rules, and deploys it: the #
# focus service joins the managed set and gets a CR.                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kind", [ServiceType.TOOL, ServiceType.AGENT])
def test_zero_rule_focus_spm_is_stored_and_deployed(kind):
    own_role = _agent_role("r-own", "own", owner="new-svc")
    own_scope = _scope("s-own", "own", service_id="new-svc")
    builtin = _scope("s-profile", "profile", service_id="new-svc", aiac_managed=False)
    catalog = [_service("new-svc", type=kind, roles=[own_role], scopes=[own_scope, builtin])]
    store = run_engine([], catalog=catalog, focus_service="new-svc")

    expected = _spm("new-svc", type=kind, owned_roles=[own_role], owned_scopes=[own_scope])
    assert store.data == {"new-svc": expected}  # seeded from the catalog (aiac.managed only)
    assert store.policy_pushes == [PolicyModel(services=[expected])]


# --------------------------------------------------------------------------- #
# D31 — the shared subject scope aiac-username-sub. Provision links it to every   #
# managed client, but it has no aiac.managed marker, so it is never an own scope  #
# of a service: the catalog seed keeps it out of every SPM identity.              #
# --------------------------------------------------------------------------- #
def _subject_scope(service_id) -> Scope:
    # One Keycloak scope linked to many clients: the IdP library sets serviceId per linking client.
    return _scope("s-subject", "aiac-username-sub", service_id=service_id, aiac_managed=False)


def test_subject_scope_is_never_an_owned_scope():
    AR, UR, AS, TS, _ = _repro()
    catalog = [
        _agent("github-agent", roles=[AR], scopes=[AS, _subject_scope("github-agent")]),
        _tool("github-tool", scopes=[TS, _subject_scope("github-tool")]),
    ]
    store = run_engine([_rule(UR, AS), _rule(AR, TS)], catalog=catalog)

    assert store.data["github-agent"].owned_scopes == [AS]
    assert store.data["github-tool"].owned_scopes == [TS]


def test_zero_rule_reonboarding_stores_and_redeploys_the_focus_spm():
    AR, UR, AS, TS, catalog = _repro()
    stored = _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS)])
    store = run_engine([], catalog=catalog, store_initial={"github-tool": stored}, focus_service="github-tool")

    assert store.service_writes == [("github-tool", stored)]  # its rules stay
    assert store.policy_pushes == [PolicyModel(services=[stored])]


def test_zero_rule_focus_spm_is_reconciled_before_it_is_stored():
    # The focus SPM is touched like a routed one: an edge on a retired scope is pruned.
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    retired = _scope("s-retired", "retired", service_id="github-tool")
    catalog = [_tool("github-tool", scopes=[TS])]
    initial = {
        "github-tool": _spm(
            "github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(UR, TS), _rule(UR, retired)]
        )
    }
    store = run_engine([], catalog=catalog, store_initial=initial, focus_service="github-tool")

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-user-dev", "s-tool-read")]
    assert _pairs(_inbound(store.pushed_service("github-tool"))) == [("r-user-dev", "s-tool-read")]


def test_focus_spm_is_deployed_with_the_other_changed_services():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, TS)], catalog=catalog, focus_service="github-agent")

    # the zero-rule focus agent joins the tool whose SPM got the rule — one push, both entries
    assert store.apply_policy_count == 1
    assert [spm.service_id for spm in store.last_push.services] == ["github-agent", "github-tool"]
    assert _inbound(store.data["github-agent"]) == []


# --------------------------------------------------------------------------- #
# Cycle 16 — a service absent from the store (404) is seeded from the catalog     #
# and still persisted.                                                            #
# --------------------------------------------------------------------------- #
def test_absent_service_is_seeded_and_persisted():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS)], catalog=catalog)  # empty store -> 404 for both

    spm = store.data["github-agent"]
    assert spm.service_type == ServiceType.AGENT
    assert [r.id for r in spm.owned_roles] == ["r-agent-src"]  # seeded from catalog
    assert _pairs(spm.inbound_allow_rules) == [("r-user-dev", "s-agent-inbound")]


# --------------------------------------------------------------------------- #
# Cycle 17 — a dependency failure is logged and RE-RAISED (not swallowed), so the  #
# caller (Controller) surfaces it as a real error instead of a silent 200 with     #
# nothing applied; nothing is pushed to the PDP.                                 #
# --------------------------------------------------------------------------- #
def test_dependency_exception_propagates(caplog):
    store = FakeStore()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"KEYCLOAK_REALM": "test-realm"}))
        stack.enter_context(patch.object(Configuration, "get_roles", return_value=[]))
        stack.enter_context(patch.object(Configuration, "get_services", side_effect=RuntimeError("boom")))
        stack.enter_context(
            patch("aiac.policy.computation.engine.get_service_policy", side_effect=store.get_service_policy)
        )
        stack.enter_context(
            patch(
                "aiac.policy.computation.engine.get_service_policies_by_role",
                side_effect=store.get_service_policies_by_role,
            )
        )
        stack.enter_context(
            patch("aiac.policy.computation.engine.apply_service_policy", side_effect=store.apply_service_policy)
        )
        stack.enter_context(patch("aiac.policy.computation.engine.apply_policy", side_effect=store.apply_policy))
        from aiac.policy.computation.engine import compute_and_apply

        UR = _user_role("r-user", users=["u"])
        with pytest.raises(RuntimeError, match="boom"):
            compute_and_apply([_rule(UR, _scope("s-x", service_id="svc"))])
        assert store.apply_policy_count == 0
        assert "compute_and_apply failed" in caplog.text  # still logged before re-raising


# --------------------------------------------------------------------------- #
# Reconcile — drift GC. Keycloak UUIDs churn on delete/recreate,                #
# so an append-only merge would grow stale edges beside their superseded         #
# generations (issue 6.3 / RC-A: SPM(github-agent) held 53 edges). On every      #
# compute the engine reconciles each TOUCHED SPM against the current             #
# get_services() catalog (no extra IdP read), dropping dangling edges. It        #
# removes only edges whose entity is gone, so live edges / order-independence    #
# are untouched.                                                                 #
# --------------------------------------------------------------------------- #
def test_reconcile_drops_retired_scope_edge():
    # A pre-fix ``*-aud`` scope no longer in the catalog is pruned on re-onboarding; the current
    # edge survives. Reconcile alone changes the SPM, so it is (re-)persisted.
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    aud = _scope("s-aud", "agent-team1-github-agent-aud", service_id="github-agent")
    catalog = [_agent("github-agent", scopes=[AS])]  # ``aud`` no longer exists
    initial = {"github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(UR, aud), _rule(UR, AS)])}
    store = run_engine([_rule(UR, AS)], catalog=catalog, store_initial=initial)

    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-agent-inbound")]


def test_reconcile_drops_churned_scope_uuid_same_name():
    # The scope was recreated with a fresh UUID (same name); the old-UUID edge is pruned.
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    as_v1 = _scope("s-as-v1", "agent-inbound", service_id="github-agent")
    as_v2 = _scope("s-as-v2", "agent-inbound", service_id="github-agent")
    catalog = [_agent("github-agent", scopes=[as_v2])]  # only the current generation
    initial = {"github-agent": _spm("github-agent", owned_scopes=[as_v1], inbound=[_rule(UR, as_v1)])}
    store = run_engine([_rule(UR, as_v2)], catalog=catalog, store_initial=initial)

    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-as-v2")]


def test_reconcile_collapses_churned_duplicate_user_role():
    # Two same-name/different-id ``developer`` edges on one scope (Keycloak delete+recreate). The
    # batch carries the current generation, so the old-generation edge is dropped; the deployed
    # inbound then names only the current role.
    dev_old = _user_role("r-dev-v1", "developer", users=["dev-user"])
    dev_new = _user_role("r-dev-v2", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    catalog = [_agent("github-agent", scopes=[AS])]
    initial = {
        "github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(dev_old, AS), _rule(dev_new, AS)])
    }
    store = run_engine([_rule(dev_new, AS)], catalog=catalog, store_initial=initial)

    assert _pairs(_inbound(store.data["github-agent"])) == [("r-dev-v2", "s-agent-inbound")]
    assert _subject_roles(store.pushed_service("github-agent")) == {"dev-user": ["r-dev-v2"]}


def test_reconcile_drops_retired_agent_role_self_reference():
    # An impossible focus-agent self-reference (an Agent-kind role the current builder can no longer
    # emit) references a role id absent from the catalog — pruned.
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")  # current agent role
    selfref = _agent_role("r-selfref", "github-agent.agent", owner="github-agent")  # retired
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    catalog = [_agent("github-agent", roles=[AR], scopes=[AS])]  # r-selfref not present
    initial = {"github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(selfref, AS), _rule(UR, AS)])}
    store = run_engine([_rule(UR, AS)], catalog=catalog, store_initial=initial)

    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-agent-inbound")]


def test_reconcile_preserves_live_edges_and_is_idempotent():
    # Re-onboarding a service whose edges are all current prunes nothing (order-independence): the
    # canonical repro's full edge set survives a second identical compute.
    AR, UR, AS, TS, catalog = _repro()
    initial = {
        "github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(UR, AS)]),
        "github-tool": _spm(
            "github-tool",
            type=ServiceType.TOOL,
            owned_scopes=[TS],
            inbound=[_rule(AR, TS), _rule(UR, TS)],
        ),
    }
    store = run_engine([_rule(UR, AS), _rule(AR, TS), _rule(UR, TS)], catalog=catalog, store_initial=initial)

    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-agent-inbound")]
    assert _pairs(_inbound(store.data["github-tool"])) == sorted(
        [("r-agent-src", "s-tool-read"), ("r-user-dev", "s-tool-read")]
    )


def test_reconcile_skips_when_service_absent_from_catalog():
    # A transient catalog miss (owning service not returned by get_services()) must never wipe an
    # SPM — reconcile is skipped and the stale edge is left intact rather than dropped. Called
    # directly: compute_and_apply's routing guard already drops a rule for an absent owner.
    from aiac.policy.computation.engine import _reconcile

    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    orphan_scope = _scope("s-orphan", "orphan", service_id="orphan")
    model = _spm("orphan", owned_scopes=[], inbound=[_rule(UR, orphan_scope)])

    assert _reconcile(model, {}, set(), {UR.id}) is False
    assert _pairs(_inbound(model)) == [("r-user-dev", "s-orphan")]


# --------------------------------------------------------------------------- #
# decommission (service offboard) — the onboard→offboard drift case (case 3).    #
# Reconcile's catalog-anchored GC skips a decommissioned service (absent from    #
# get_services()); decommission() is the authoritative teardown: purge X's       #
# outbound footprint from other SPMs, delete the CR of X (agent or tool, D20),   #
# redeploy the live services whose SPM the purge changed, and then write the     #
# purged SPMs and delete SPM(X) (the store changes last).                        #
# Two-phase: onboard the repro into a shared store, then decommission against a #
# catalog with X removed.                                                         #
# --------------------------------------------------------------------------- #
def _onboard_repro(store):
    """Onboard the canonical repro into ``store`` (mutates it); return ``(AR, UR, AS, TS)``."""
    AR, UR, AS, TS, catalog = _repro()
    with engine_env(catalog, store) as compute_and_apply:
        compute_and_apply([_rule(UR, AS), _rule(AR, TS), _rule(UR, TS)])
    return AR, UR, AS, TS


def run_decommission(service_id, *, catalog, store) -> FakeStore:
    with engine_env(catalog, store):
        from aiac.policy.computation.engine import decommission

        decommission(service_id)
    return store


def test_decommission_tool_deletes_its_cr_and_strands_no_edges():
    # Onboard agent A (targets tool T), then offboard T. SPM(T) is deleted (with its user→T and
    # agent→T inbound edges) and the CR of T is deleted. The tool owns no role, so no other SPM
    # changed: A's CR is not redeployed (its outbound is a pass-through).
    store = FakeStore()
    _onboard_repro(store)
    pushes_before = len(store.policy_pushes)

    # Phase 2: the tool is gone from the catalog (its Keycloak client was deleted).
    run_decommission("github-tool", catalog=[_agent("github-agent", scopes=[])], store=store)

    assert "github-tool" in store.service_deletes
    assert "github-tool" not in store.data
    assert store.cr_deletes == ["github-tool"]
    assert len(store.policy_pushes) == pushes_before


def test_decommission_agent_deletes_its_cr_and_purges_outbound_footprint():
    # Offboard the agent A itself. SPM(A) is deleted, the CR of A is deleted, and A's outbound
    # footprint (AR→TS stored on SPM(T)) is purged while the tool keeps its user grant. The purged
    # SPM(T) is redeployed; there is no entry for the deleted agent.
    store = FakeStore()
    _onboard_repro(store)
    pushes_before = len(store.policy_pushes)

    # Phase 2: the agent is gone from the catalog.
    run_decommission("github-agent", catalog=[_tool("github-tool", scopes=[])], store=store)

    assert "github-agent" in store.service_deletes
    assert "github-agent" not in store.data
    assert store.cr_deletes == ["github-agent"]

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-user-dev", "s-tool-read")]
    assert len(store.policy_pushes) == pushes_before + 1
    assert store.last_push == PolicyModel(services=[store.data["github-tool"]])


def test_decommission_of_a_caller_redeploys_the_callee_that_lost_its_role():
    # agent-a calls agent-b (AR→BS on SPM(agent-b)); agent-b does not call agent-a. Offboarding
    # agent-a purges AR→BS: the purged SPM(agent-b) is redeployed.
    AR = _agent_role("r-a-caller", "a-caller", owner="agent-a")
    BS = _scope("s-b-inbound", "b-inbound", service_id="agent-b")
    store = FakeStore({"agent-b": _spm("agent-b", owned_scopes=[BS], inbound=[_rule(AR, BS)])})
    store.data["agent-a"] = _spm("agent-a", owned_roles=[AR])

    run_decommission("agent-a", catalog=[_agent("agent-b", scopes=[BS])], store=store)

    assert store.policy_pushes == [PolicyModel(services=[_spm("agent-b", owned_scopes=[BS])])]


def test_decommission_deletes_the_cr_then_redeploys_then_writes_the_store_then_deletes_the_spm():
    # The store changes last, and the delete of SPM(X) is the last step: a retry of a decommission
    # that failed part way finds SPM(X) again.
    store = FakeStore()
    _onboard_repro(store)
    store.calls.clear()

    run_decommission("github-agent", catalog=[_tool("github-tool", scopes=[])], store=store)

    assert [op for op, _ in store.calls] == ["delete_service_cr", "apply_policy", "write", "delete"]


def test_decommission_of_a_never_onboarded_service_is_a_no_op():
    store = run_decommission("never-seen", catalog=[], store=FakeStore())

    assert store.calls == []  # no store delete, no CR delete, no push


# =========================================================================== #
# Effect (ALLOW / DENY) routing and derivation (#118). Every inbound edge      #
# carries a ``RuleEffect``; the engine files each into the owning SPM's         #
# effect-matching list; the writer projects each edge into its gate by         #
# role.kind AND effect (deny-overrides at request time).                        #
# =========================================================================== #
def test_deny_and_allow_rules_route_to_separate_inbound_lists():
    # A Deny edge lands in the owning SPM's inbound_deny_rules; an Allow edge in inbound_allow_rules.
    AR, UR, AS, TS, catalog = _repro()
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    store = run_engine([_rule(UR, AS), _deny(barred, AS)], catalog=catalog)

    spm = store.data["github-agent"]
    assert _pairs(spm.inbound_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert _pairs(spm.inbound_deny_rules) == [("r-user-ops", "s-agent-inbound")]


def test_same_role_scope_allow_and_deny_coexist():
    # Dedup identity is (role.id, scope.id, effect): the SAME (role, scope) may be present once as
    # Allow and once as Deny — the two live in the separate lists, neither displacing the other.
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS), _deny(UR, AS)], catalog=catalog)

    spm = store.data["github-agent"]
    assert _pairs(spm.inbound_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert _pairs(spm.inbound_deny_rules) == [("r-user-dev", "s-agent-inbound")]


def test_override_purges_input_role_from_both_lists_on_one_spm():
    # override is role-level revocation over BOTH lists: a role present as an Allow edge and a Deny
    # edge on the same SPM is purged from both before the fresh rule is re-appended.
    shared = _user_role("r-shared", "shared", users=["u"])
    s1 = _scope("s-one", service_id="svc")
    s2 = _scope("s-two", service_id="svc")
    catalog = [_agent("svc", scopes=[s1, s2])]
    initial = {
        "svc": _spm("svc", owned_scopes=[s1, s2], inbound=[_rule(shared, s1), _deny(shared, s2)]),
    }
    # re-onboard the shared role as a single Allow edge on s1
    store = run_engine([_rule(shared, s1)], catalog=catalog, store_initial=initial, override=True)

    assert _pairs(store.data["svc"].inbound_allow_rules) == [("r-shared", "s-one")]
    assert store.data["svc"].inbound_deny_rules == []  # the stale Deny edge purged too


def test_override_purges_role_across_spms_from_the_deny_list():
    # The role is an Allow edge on svc-one and a Deny edge on svc-two; override purges it from every
    # SPM containing it in EITHER list, scanning by role once.
    shared = _user_role("r-shared", "shared", users=["u"])
    s1 = _scope("s-one", service_id="svc-one")
    s2 = _scope("s-two", service_id="svc-two")
    catalog = [_agent("svc-one", scopes=[s1]), _agent("svc-two", scopes=[s2])]
    initial = {
        "svc-one": _spm("svc-one", owned_scopes=[s1], inbound=[_rule(shared, s1)]),
        "svc-two": _spm("svc-two", owned_scopes=[s2], inbound=[_deny(shared, s2)]),
    }
    store = run_engine([_rule(shared, s1)], catalog=catalog, store_initial=initial, override=True)

    assert _inbound(store.data["svc-two"]) == []  # stale Deny edge on the other SPM is gone
    assert _pairs(store.data["svc-one"].inbound_allow_rules) == [("r-shared", "s-one")]
    assert [r.id for r in store.by_role_calls].count("r-shared") == 1


def test_reconcile_drops_dangling_deny_edge_and_keeps_live_deny():
    # Reconcile scans the deny list too: a retired-scope DENY edge is pruned while the current DENY
    # edge survives.
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    aud = _scope("s-aud", "agent-team1-github-agent-aud", service_id="github-agent")  # retired
    catalog = [_agent("github-agent", scopes=[AS])]  # ``aud`` no longer exists
    initial = {"github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_deny(barred, aud), _deny(barred, AS)])}
    store = run_engine([_deny(barred, AS)], catalog=catalog, store_initial=initial)

    assert store.data["github-agent"].inbound_allow_rules == []
    assert _pairs(store.data["github-agent"].inbound_deny_rules) == [("r-user-ops", "s-agent-inbound")]


def test_reconcile_churn_collapse_is_per_list_so_a_live_deny_survives():
    # The user-role churn collapse is computed independently per list. An Allow edge whose
    # (scope, name) matches a Deny edge of a DIFFERENT id must not cause the live Deny edge to be
    # pruned (a cross-list collapse would be a bug).
    dev_allow = _user_role("r-dev-allow", "developer", users=["dev-user"])
    dev_deny = _user_role("r-dev-deny", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    catalog = [_agent("github-agent", scopes=[AS])]
    initial = {
        "github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(dev_allow, AS), _deny(dev_deny, AS)])
    }
    store = run_engine([_rule(dev_allow, AS)], catalog=catalog, store_initial=initial)  # allow gen only

    assert _pairs(store.data["github-agent"].inbound_allow_rules) == [("r-dev-allow", "s-agent-inbound")]
    assert _pairs(store.data["github-agent"].inbound_deny_rules) == [("r-dev-deny", "s-agent-inbound")]


def test_reconcile_preserves_live_deny_edge_and_is_idempotent():
    # A live Deny edge (all entities current) is never pruned; a second identical compute leaves both
    # lists unchanged (order-independence over both lists).
    AR, UR, AS, TS, catalog = _repro()
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    initial = {
        "github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(UR, AS), _deny(barred, AS)]),
    }
    store = FakeStore(initial)
    with engine_env(catalog, store) as compute:
        compute([_rule(UR, AS), _deny(barred, AS)])
        first = (
            _pairs(store.data["github-agent"].inbound_allow_rules),
            _pairs(store.data["github-agent"].inbound_deny_rules),
        )
        compute([_rule(UR, AS), _deny(barred, AS)])  # idempotent second pass

    assert first == ([("r-user-dev", "s-agent-inbound")], [("r-user-ops", "s-agent-inbound")])
    assert _pairs(store.data["github-agent"].inbound_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert _pairs(store.data["github-agent"].inbound_deny_rules) == [("r-user-ops", "s-agent-inbound")]


def test_decommission_purges_agent_deny_footprint_from_other_spm():
    # A's agent role carries a DENY edge on the tool (AR→TS deny). Offboarding A purges that edge
    # from SPM(T)'s inbound_deny_rules — the footprint scan covers the deny list too — while the
    # tool keeps its unrelated user allow grant.
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [_agent("github-agent", roles=[AR], scopes=[AS]), _tool("github-tool", scopes=[TS])]
    store = FakeStore()
    with engine_env(catalog, store) as compute:
        compute([_rule(UR, AS), _deny(AR, TS), _rule(UR, TS)])

    assert _pairs(store.data["github-tool"].inbound_deny_rules) == [("r-agent-src", "s-tool-read")]

    run_decommission("github-agent", catalog=[_tool("github-tool", scopes=[TS])], store=store)

    assert "github-agent" in store.service_deletes
    assert store.cr_deletes == ["github-agent"]
    assert store.data["github-tool"].inbound_deny_rules == []  # A's deny footprint purged
    assert _pairs(store.data["github-tool"].inbound_allow_rules) == [("r-user-dev", "s-tool-read")]


# --------------------------------------------------------------------------- #
# always DENY — the PCE carries no default effect.                            #
# --------------------------------------------------------------------------- #
def test_compute_and_apply_takes_no_default_effect():
    import inspect

    from aiac.policy.computation import engine

    for fn in (engine.compute_and_apply, engine._run):
        assert "default_effect" not in inspect.signature(fn).parameters, fn.__name__


# --------------------------------------------------------------------------- #
# PCE lock — one module-level lock serializes every read-modify-write of the   #
# store and every deploy (compute_and_apply, decommission, quarantine, resync, #
# bootstrap; the resync and bootstrap tests are below). Without it two runs     #
# that route rules into one shared SPM both read the old SPM, and the second   #
# write removes the first run's rules (a lost update, no error).               #
# --------------------------------------------------------------------------- #
class PausingStore(FakeStore):
    """A ``FakeStore`` whose first read of ``pause_on`` waits (bounded) for a second reader.

    Without a lock the second run reads the same, not-yet-written SPM while the first waits, so the
    two runs interleave read → read → write → write. With the lock the second run cannot read until
    the first has written; the first waits only until ``timeout`` and then continues."""

    def __init__(self, pause_on, timeout=0.5, initial=None):
        super().__init__(initial)
        self.pause_on = pause_on
        self.timeout = timeout
        self.first_read = threading.Event()
        self.second_read = threading.Event()
        self._reads = 0
        self._reads_lock = threading.Lock()

    def get_service_policy(self, service_id):
        model = super().get_service_policy(service_id)
        if service_id == self.pause_on:
            with self._reads_lock:
                self._reads += 1
                reads = self._reads
            if reads == 1:
                self.first_read.set()
                self.second_read.wait(self.timeout)
            else:
                self.second_read.set()
        return model


def _two_agents_one_tool():
    A1 = _agent_role("r-a1", "a1-src", owner="agent-1")
    A2 = _agent_role("r-a2", "a2-src", owner="agent-2")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [
        _agent("agent-1", roles=[A1]),
        _agent("agent-2", roles=[A2]),
        _tool("github-tool", scopes=[TS]),
    ]
    return A1, A2, TS, catalog


def _run_in_threads(*calls):
    errors = []

    def wrap(fn):
        def target():
            try:
                fn()
            except Exception as exc:  # surfaced to the test thread below
                errors.append(exc)

        return target

    threads = [threading.Thread(target=wrap(fn)) for fn in calls]
    threads[0].start()
    return threads, errors


def test_concurrent_runs_into_one_shared_spm_keep_both_rules():
    A1, A2, TS, catalog = _two_agents_one_tool()
    store = PausingStore(pause_on="github-tool")
    with engine_env(catalog, store) as compute_and_apply:
        threads, errors = _run_in_threads(
            lambda: compute_and_apply([_rule(A1, TS)]),
            lambda: compute_and_apply([_rule(A2, TS)]),
        )
        assert store.first_read.wait(2)  # run 1 is between its read and its write of SPM(tool)
        threads[1].start()
        for t in threads:
            t.join(5)
        assert not errors

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-a1", "s-tool-read"), ("r-a2", "s-tool-read")]


def _blocks_while_pce_lock_held(fn) -> None:
    """Hold the PCE lock in the test thread; ``fn`` in a worker must not finish until it is released."""
    from aiac.policy.computation import engine

    done = threading.Event()

    def target():
        fn()
        done.set()

    with engine._pce_lock:
        worker = threading.Thread(target=target)
        worker.start()
        assert not done.wait(0.3), "ran while another holder had the PCE lock"
    worker.join(5)
    assert done.is_set()


def test_compute_and_apply_holds_the_pce_lock():
    AR, UR, AS, TS, catalog = _repro()
    store = FakeStore()
    with engine_env(catalog, store) as compute_and_apply:
        _blocks_while_pce_lock_held(lambda: compute_and_apply([_rule(UR, AS)]))


def test_decommission_holds_the_pce_lock():
    store = FakeStore()
    _onboard_repro(store)
    with engine_env([_agent("github-agent")], store):
        from aiac.policy.computation.engine import decommission

        _blocks_while_pce_lock_held(lambda: decommission("github-tool"))


# --------------------------------------------------------------------------- #
# Routing guard — under the PCE lock, after the catalog read, drop each rule    #
# that touches a disabled (quarantined) service: its scope owner is disabled,   #
# or its agent role belongs to a disabled service. The focus service (the one   #
# this onboarding builds, passed as its clientId) is exempt: its client is      #
# still disabled while a re-onboarding applies.                                 #
# --------------------------------------------------------------------------- #
def _guard_catalog(*, agent_enabled=True, tool_enabled=True):
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [
        _agent("github-agent", roles=[AR], scopes=[AS], enabled=agent_enabled),
        _tool("github-tool", scopes=[TS], enabled=tool_enabled),
    ]
    return AR, UR, AS, TS, catalog


def test_guard_drops_rule_whose_scope_owner_is_disabled():
    AR, UR, AS, TS, catalog = _guard_catalog(tool_enabled=False)
    store = run_engine([_rule(AR, TS), _rule(UR, TS), _rule(UR, AS)], catalog=catalog, focus_service="github-agent")

    assert "github-tool" not in store.data
    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-agent-inbound")]
    assert store.pushed_service_ids == {"github-agent"}  # the disabled tool is never deployed


def test_guard_drops_rule_whose_agent_role_belongs_to_a_disabled_service():
    AR, UR, AS, TS, catalog = _guard_catalog(agent_enabled=False)
    store = run_engine([_rule(AR, TS), _rule(UR, TS)], catalog=catalog, focus_service="github-tool")

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-user-dev", "s-tool-read")]
    assert store.pushed_service_ids == {"github-tool"}  # the disabled agent is never deployed


def test_guard_keeps_the_focus_service_rules_while_it_is_disabled():
    AR, UR, AS, TS, catalog = _guard_catalog(agent_enabled=False)
    store = run_engine([_rule(AR, TS), _rule(UR, AS)], catalog=catalog, focus_service="github-agent")

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-agent-src", "s-tool-read")]
    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-agent-inbound")]
    # the disabled focus service counts as live: its entry is deployed with the tool's
    assert store.pushed_service_ids == {"github-agent", "github-tool"}


def test_guard_does_not_exempt_a_focus_service_given_by_its_keycloak_uuid():
    # focus_service is the clientId (the catalog key). A Keycloak UUID matches no catalog key, so
    # the disabled agent is not exempt and its rules are dropped.
    AR, UR, AS, TS, catalog = _guard_catalog(agent_enabled=False)
    store = run_engine([_rule(AR, TS), _rule(UR, AS)], catalog=catalog, focus_service="uuid-github-agent")

    assert "github-agent" not in store.data
    assert "github-tool" not in store.data
    assert store.apply_policy_count == 0


def test_guard_without_focus_drops_every_rule_that_touches_a_disabled_service():
    AR, UR, AS, TS, catalog = _guard_catalog(agent_enabled=False)
    store = run_engine([_rule(AR, TS), _rule(UR, AS), _rule(UR, TS)], catalog=catalog)

    assert "github-agent" not in store.data
    assert _pairs(_inbound(store.data["github-tool"])) == [("r-user-dev", "s-tool-read")]
    assert store.apply_policy_count == 1
    assert store.pushed_service_ids == {"github-tool"}  # the live tool only


def test_guard_keeps_every_rule_when_all_services_are_enabled():
    AR, UR, AS, TS, catalog = _guard_catalog()
    store = run_engine([_rule(AR, TS), _rule(UR, AS)], catalog=catalog)

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-agent-src", "s-tool-read")]
    assert _pairs(_inbound(store.data["github-agent"])) == [("r-user-dev", "s-agent-inbound")]


# --------------------------------------------------------------------------- #
# quarantine — the failure-path teardown of a failed onboarding. Keyed by the   #
# clientId (the SPM key), as decommission is; the service is still in the       #
# catalog (disabled). Removes X's roles from the other SPMs, deletes the CR of  #
# X — agent or tool (D20: the combiner denies a pod that has no CR) — and       #
# redeploys the live services whose SPM lost X's roles, in one call; then it    #
# writes those SPMs and deletes SPM(X) (the store changes last).                #
# --------------------------------------------------------------------------- #
def _quarantine_fixture():
    """X = github-agent (failed, disabled). It targets the tool and other-agent; other-agent targets X."""
    AR = _agent_role("r-x-src", "x-source", owner="github-agent")
    BR = _agent_role("r-b-src", "b-source", owner="other-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-x-in", "x-inbound", service_id="github-agent")
    BS = _scope("s-b-in", "b-inbound", service_id="other-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    initial = {
        "github-agent": _spm(
            "github-agent", owned_roles=[AR], owned_scopes=[AS], inbound=[_rule(UR, AS), _rule(BR, AS)]
        ),
        "github-tool": _spm(
            "github-tool",
            type=ServiceType.TOOL,
            owned_scopes=[TS],
            inbound=[_rule(AR, TS), _rule(BR, TS), _rule(UR, TS)],
        ),
        "other-agent": _spm("other-agent", owned_roles=[BR], owned_scopes=[BS], inbound=[_rule(AR, BS), _rule(UR, BS)]),
    }
    catalog = [
        _agent("github-agent", roles=[AR], scopes=[AS], enabled=False),
        _agent("other-agent", roles=[BR], scopes=[BS]),
        _tool("github-tool", scopes=[TS]),
    ]
    return catalog, initial


def run_quarantine(service_id, *, catalog, store) -> FakeStore:
    with engine_env(catalog, store):
        from aiac.policy.computation import quarantine

        quarantine(service_id)
    return store


def test_quarantine_agent_deletes_its_spm_and_removes_its_roles_from_other_spms():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert store.service_deletes == ["github-agent"]
    assert "github-agent" not in store.data
    assert _pairs(_inbound(store.data["github-tool"])) == [("r-b-src", "s-tool-read"), ("r-user-dev", "s-tool-read")]
    assert _pairs(_inbound(store.data["other-agent"])) == [("r-user-dev", "s-b-in")]


def test_quarantine_agent_deletes_its_cr():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert store.cr_deletes == ["github-agent"]  # a delete, not a no-rules CR
    assert "github-agent" not in store.pushed_service_ids


def test_quarantine_redeploys_the_services_whose_spm_lost_its_roles_in_one_call():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert store.apply_policy_count == 1
    assert [spm.service_id for spm in store.last_push.services] == ["github-tool", "other-agent"]
    tool, other = store.last_push.services
    assert _pairs(_inbound(tool)) == [("r-b-src", "s-tool-read"), ("r-user-dev", "s-tool-read")]
    assert _pairs(_inbound(other)) == [("r-user-dev", "s-b-in")]
    assert store.last_push.services == [store.data["github-tool"], store.data["other-agent"]]


def test_quarantine_deletes_the_cr_then_redeploys_then_writes_the_store_then_deletes_the_spm():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert [op for op, _ in store.calls] == ["delete_service_cr", "apply_policy", "write", "write", "delete"]


def test_quarantine_tool_deletes_its_cr():
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    initial = {
        "github-tool": _spm(
            "github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS), _rule(UR, TS)]
        )
    }
    catalog = [_agent("github-agent", roles=[AR]), _tool("github-tool", scopes=[TS], enabled=False)]

    store = run_quarantine("github-tool", catalog=catalog, store=FakeStore(initial))

    assert "github-tool" not in store.data
    assert store.cr_deletes == ["github-tool"]
    # The tool owns no role, so no other SPM changed: the callers' CRs stay (their outbound is a
    # pass-through).
    assert store.apply_policy_count == 0


def test_quarantine_twice_gives_the_same_result():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))
    after_first = {sid: m.model_dump() for sid, m in store.data.items()}

    run_quarantine("github-agent", catalog=catalog, store=store)

    assert {sid: m.model_dump() for sid, m in store.data.items()} == after_first
    assert store.cr_deletes == ["github-agent", "github-agent"]  # deleted again; a 404 is success


def test_quarantine_unknown_service_is_a_no_op():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("not-there", catalog=catalog, store=FakeStore(initial))

    assert store.service_deletes == []
    assert store.service_writes == []
    assert store.cr_deletes == []
    assert store.apply_policy_count == 0


def test_quarantine_given_a_keycloak_uuid_is_a_no_op():
    # The PCE takes only the clientId: a Keycloak UUID is not an SPM key, so it finds nothing.
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("uuid-github-agent", catalog=catalog, store=FakeStore(initial))

    assert store.service_deletes == []
    assert store.cr_deletes == []
    assert store.apply_policy_count == 0


def test_quarantine_removes_the_grants_of_roles_the_rollback_deleted():
    # X's first onboarding created r-x-new. A concurrent run stored its grant on SPM(other-agent)
    # (r-x-new → s-b-in). Then X's build failed and the rollback deleted r-x-new, so the catalog no
    # longer lists it. The orchestrator passes it as a deleted role: the quarantine must remove the
    # grant and redeploy other-agent, or other-agent keeps allowing X.
    XR = _agent_role("r-x-new", "x-new", owner="github-agent")
    catalog, initial = _quarantine_fixture()
    initial["other-agent"].inbound_allow_rules.append(_rule(XR, initial["other-agent"].owned_scopes[0]))
    store = FakeStore(initial)
    with engine_env(catalog, store):
        from aiac.policy.computation import quarantine

        quarantine("github-agent", [XR])

    assert _pairs(_inbound(store.data["other-agent"])) == [("r-user-dev", "s-b-in")]
    assert _pairs(_inbound(store.pushed_service("other-agent"))) == [("r-user-dev", "s-b-in")]


def test_quarantine_without_the_deleted_roles_keeps_their_grants():
    # The gap the deleted_roles argument closes: the catalog alone does not name r-x-new.
    XR = _agent_role("r-x-new", "x-new", owner="github-agent")
    catalog, initial = _quarantine_fixture()
    initial["other-agent"].inbound_allow_rules.append(_rule(XR, initial["other-agent"].owned_scopes[0]))
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert ("r-x-new", "s-b-in") in _pairs(_inbound(store.data["other-agent"]))


def test_quarantine_holds_the_pce_lock():
    catalog, initial = _quarantine_fixture()
    store = FakeStore(initial)
    with engine_env(catalog, store):
        from aiac.policy.computation import quarantine

        _blocks_while_pce_lock_held(lambda: quarantine("github-agent"))


# --------------------------------------------------------------------------- #
# Absent services — a service missing from the catalog (its client was deleted, #
# e.g. offboarded while its onboarding was still building) is treated like a    #
# disabled one: its rules are dropped, and _run never deploys (writes a CR for) #
# a service that is not in the catalog. The store's 404 placeholder SPM says    #
# service_type=AGENT, so without this a deleted tool got a CR.                  #
# --------------------------------------------------------------------------- #
def test_guard_drops_rule_whose_scope_owner_is_absent_from_the_catalog():
    AR, UR, AS, TS, catalog = _guard_catalog()
    live = [svc for svc in catalog if svc.serviceId != "github-tool"]  # the tool's client was deleted
    store = run_engine([_rule(AR, TS), _rule(UR, TS)], catalog=live, focus_service="github-tool")

    assert "github-tool" not in store.data
    assert store.service_writes == []  # an absent focus service gets no zero-rule SPM either
    assert store.apply_policy_count == 0


def test_guard_drops_rule_whose_agent_role_owner_is_absent_from_the_catalog():
    AR, UR, AS, TS, catalog = _guard_catalog()
    live = [svc for svc in catalog if svc.serviceId != "github-agent"]  # the agent's client was deleted
    store = run_engine([_rule(AR, TS), _rule(UR, TS)], catalog=live)

    assert _pairs(_inbound(store.data["github-tool"])) == [("r-user-dev", "s-tool-read")]
    assert store.pushed_service_ids == {"github-tool"}


def test_run_never_deploys_a_service_that_is_absent_from_the_catalog():
    # Override-purge touches the stored SPM of a deleted agent (its persisted type is AGENT). The
    # purge is persisted, but no CR is written for the deleted agent.
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    ghost_scope = _scope("s-ghost-in", "ghost-inbound", service_id="ghost-agent")
    AR, _, AS, _, catalog = _repro()
    initial = {"ghost-agent": _spm("ghost-agent", owned_scopes=[ghost_scope], inbound=[_rule(UR, ghost_scope)])}

    store = run_engine([_rule(UR, AS)], catalog=catalog, store_initial=initial, override=True)

    assert _inbound(store.data["ghost-agent"]) == []  # the purge still lands
    assert store.pushed_service_ids == {"github-agent"}


# --------------------------------------------------------------------------- #
# PR 227 review fixes — the override purge set comes from the unfiltered input; #
# quarantine and decommission deploy only live services, and keep the grants of #
# a role that another service also holds.                                       #
# --------------------------------------------------------------------------- #
def test_override_purges_a_role_whose_every_new_rule_the_guard_drops():
    # The only new rule for r-user-dev targets the disabled tool, so the guard drops it. Under
    # override the role's old grant on SPM(github-agent) must still go.
    AR, UR, AS, TS, catalog = _guard_catalog(tool_enabled=False)
    initial = {"github-agent": _spm("github-agent", owned_roles=[AR], owned_scopes=[AS], inbound=[_rule(UR, AS)])}

    store = run_engine([_rule(UR, TS)], catalog=catalog, store_initial=initial, override=True)

    assert _inbound(store.data["github-agent"]) == []
    assert "github-tool" not in store.data
    assert store.pushed_service_ids == {"github-agent"}
    assert _inbound(store.pushed_service("github-agent")) == []  # the revoked grant leaves its CR


def _shared_role_fixture():
    """r-shared is one realm role on the service accounts of github-agent (X) and other-agent. Its
    grant on the tool is other-agent's grant too."""
    catalog, initial = _quarantine_fixture()
    SX = _agent_role("r-shared", "shared", owner="github-agent")
    SB = _agent_role("r-shared", "shared", owner="other-agent")
    TS = initial["github-tool"].owned_scopes[0]
    catalog[0].roles.append(SX)
    catalog[1].roles.append(SB)
    initial["github-agent"].owned_roles.append(SX)
    initial["github-tool"].inbound_allow_rules.append(_rule(SB, TS))
    return catalog, initial


def test_quarantine_keeps_the_grants_of_a_role_another_service_also_holds():
    catalog, initial = _shared_role_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert ("r-shared", "s-tool-read") in _pairs(_inbound(store.data["github-tool"]))
    assert ("r-x-src", "s-tool-read") not in _pairs(_inbound(store.data["github-tool"]))
    assert ("r-shared", "s-tool-read") in _pairs(_inbound(store.pushed_service("github-tool")))


def test_decommission_keeps_the_grants_of_a_role_another_service_also_holds():
    catalog, initial = _shared_role_fixture()
    live = [svc for svc in catalog if svc.serviceId != "github-agent"]  # X was offboarded
    store = run_decommission("github-agent", catalog=live, store=FakeStore(initial))

    assert ("r-shared", "s-tool-read") in _pairs(_inbound(store.data["github-tool"]))
    assert ("r-x-src", "s-tool-read") not in _pairs(_inbound(store.data["github-tool"]))


def _ghost_target_fixture(*, ghost_in_catalog, ghost_enabled=False):
    """X (github-agent) holds a grant on ghost-agent, whose stored SPM remains. ghost-agent is
    either absent from the catalog (its client was deleted without an offboard) or disabled."""
    catalog, initial = _quarantine_fixture()
    AR = catalog[0].roles[0]
    GS = _scope("s-ghost-in", "ghost-inbound", service_id="ghost-agent")
    initial["ghost-agent"] = _spm("ghost-agent", owned_scopes=[GS], inbound=[_rule(AR, GS)])
    if ghost_in_catalog:
        catalog.append(_agent("ghost-agent", scopes=[GS], enabled=ghost_enabled))
    return catalog, initial


def test_quarantine_never_deploys_a_service_that_is_absent_from_the_catalog():
    catalog, initial = _ghost_target_fixture(ghost_in_catalog=False)
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert _inbound(store.data["ghost-agent"]) == []  # the purge still lands
    assert store.pushed_service_ids == {"github-tool", "other-agent"}


def test_quarantine_never_deploys_a_disabled_service():
    # A disabled service stays with no CR (its quarantine deleted it): a redeploy must not write one.
    catalog, initial = _ghost_target_fixture(ghost_in_catalog=True)
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert _inbound(store.data["ghost-agent"]) == []
    assert store.pushed_service_ids == {"github-tool", "other-agent"}


def test_decommission_never_deploys_a_service_that_is_absent_from_the_catalog():
    catalog, initial = _ghost_target_fixture(ghost_in_catalog=False)
    live = [svc for svc in catalog if svc.serviceId != "github-agent"]  # X was offboarded
    store = run_decommission("github-agent", catalog=live, store=FakeStore(initial))

    assert _inbound(store.data["ghost-agent"]) == []  # the purge still lands
    assert store.pushed_service_ids == {"github-tool", "other-agent"}


# --------------------------------------------------------------------------- #
# resync (D28, checkpoint O3) — at every Controller start, under the PCE lock:  #
# (1) one replace_policy (PUT /policy) with every stored SPM of a LIVE service  #
# (in the catalog and enabled) — the PUT also deletes every other AIAC CR;      #
# (2) quarantine each disabled service that still has a stored SPM.             #
# --------------------------------------------------------------------------- #
def _resync_fixture():
    """github-agent and github-tool are live. failed-agent is disabled (a client disabled by hand,
    C2) and still has an SPM; its role holds a grant on the tool. ghost-agent has an SPM but is
    absent from the catalog (deleted, not decommissioned)."""
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    FR = _agent_role("r-failed-src", "failed-source", owner="failed-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    FS = _scope("s-failed-in", "failed-inbound", service_id="failed-agent")
    GS = _scope("s-ghost-in", "ghost-inbound", service_id="ghost-agent")
    initial = {
        "github-agent": _spm("github-agent", owned_roles=[AR], owned_scopes=[AS], inbound=[_rule(UR, AS)]),
        "github-tool": _spm(
            "github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS), _rule(FR, TS)]
        ),
        "failed-agent": _spm("failed-agent", owned_roles=[FR], owned_scopes=[FS], inbound=[_rule(UR, FS)]),
        "ghost-agent": _spm("ghost-agent", owned_scopes=[GS], inbound=[_rule(UR, GS)]),
    }
    catalog = [
        _agent("github-agent", roles=[AR], scopes=[AS]),
        _tool("github-tool", scopes=[TS]),
        _agent("failed-agent", roles=[FR], scopes=[FS], enabled=False),
    ]
    return catalog, initial


def run_resync(*, catalog, store) -> FakeStore:
    with engine_env(catalog, store):
        from aiac.policy.computation import resync

        resync()
    return store


def _without_holder(model, role_id):
    """``model`` with no holder on the edges of ``role_id`` — a role whose only holder is disabled
    (D32: the render uses the current holders, and a disabled service is not one)."""
    fresh = model.model_copy(deep=True)
    for edge in _inbound(fresh):
        if edge.role.id == role_id:
            edge.role.actorIds = []
    return fresh


def test_resync_replaces_every_cr_with_the_live_stored_spms():
    catalog, initial = _resync_fixture()
    store = run_resync(catalog=catalog, store=FakeStore(initial))

    # one PUT; the disabled and the absent services are not in it (the PUT deletes their CRs), and
    # the disabled failed-agent is not a holder of its role on the tool
    assert store.policy_replaces == [
        PolicyModel(services=[initial["github-agent"], _without_holder(initial["github-tool"], "r-failed-src")]),
    ]


def test_resync_quarantines_each_disabled_service_that_has_an_spm():
    catalog, initial = _resync_fixture()
    store = run_resync(catalog=catalog, store=FakeStore(initial))

    assert "failed-agent" not in store.data
    assert store.cr_deletes == ["failed-agent"]
    # its role leaves the tool's SPM, and the tool's CR is redeployed without it
    assert _pairs(_inbound(store.data["github-tool"])) == [("r-agent-src", "s-tool-read")]
    assert store.policy_pushes == [PolicyModel(services=[store.data["github-tool"]])]
    # the PUT comes first, then the quarantine
    assert [op for op, _ in store.calls] == [
        "replace_policy",
        "delete_service_cr",
        "apply_policy",
        "write",
        "delete",
    ]


@pytest.mark.parametrize("operation", ["resync", "rerender_role", "policy_model_for"])
def test_a_render_that_writes_no_spm_seeds_the_identity_from_the_catalog(operation):
    # An admin removed a scope from the tool in Keycloak. compute_and_apply renders the tool with the
    # identity of the catalog, so a render that writes no SPM must too: else the CR changes back and
    # forth with the path that rendered it.
    catalog, initial = _resync_fixture()
    removed = _scope("s-tool-removed", "tool-removed", service_id="github-tool")
    initial["github-tool"].owned_scopes.append(removed)
    store = FakeStore(initial)
    if operation == "resync":
        run_resync(catalog=catalog, store=store)
        (push,) = store.policy_replaces
    elif operation == "rerender_role":
        run_rerender("r-agent-src", catalog=catalog, store=store)
        push = store.last_push
    else:
        push = _read_model("github-tool", store=store, catalog=catalog)

    tool = next(spm for spm in push.services if spm.service_id == "github-tool")
    assert [scope.id for scope in tool.owned_scopes] == ["s-tool-read"]


def test_resync_with_an_empty_store_replaces_with_the_empty_model():
    store = run_resync(catalog=[_tool("github-tool")], store=FakeStore())

    assert store.policy_replaces == [PolicyModel(services=[])]  # the PUT deletes every AIAC CR
    assert [op for op, _ in store.calls] == ["replace_policy"]


def test_resync_keeps_the_spm_of_a_service_absent_from_the_catalog():
    # Removing a deleted service's SPM is decommission's job; the PUT already removed its CR.
    catalog, initial = _resync_fixture()
    store = run_resync(catalog=catalog, store=FakeStore(initial))

    assert store.data["ghost-agent"] == initial["ghost-agent"]
    assert "ghost-agent" not in store.cr_deletes


def test_resync_failure_is_logged_and_reraised(caplog):
    catalog, initial = _resync_fixture()
    store = FakeStore(initial)
    with (
        engine_env(catalog, store),
        patch("aiac.policy.computation.engine.replace_policy", side_effect=RuntimeError("writer down")),
    ):
        from aiac.policy.computation import resync

        with pytest.raises(RuntimeError, match="writer down"):
            resync()

    assert "resync failed" in caplog.text
    assert store.calls == []  # the quarantine does not run after a failed PUT


def test_resync_holds_the_pce_lock():
    catalog, initial = _resync_fixture()
    store = FakeStore(initial)
    with engine_env(catalog, store):
        from aiac.policy.computation import resync

        _blocks_while_pce_lock_held(resync)


def test_a_zero_rule_onboarding_joins_the_managed_set_that_resync_writes():
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [_tool("github-tool", scopes=[TS])]
    store = run_engine([], catalog=catalog, focus_service="github-tool")

    run_resync(catalog=catalog, store=store)

    zero_rule = _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS])
    assert store.policy_replaces == [PolicyModel(services=[zero_rule])]


# --------------------------------------------------------------------------- #
# policy_model_for (D18) — the read model: the policy model with only the      #
# stored SPM of the service, or None if the store has no SPM for it.            #
# Read-only; takes no lock.                                                     #
# --------------------------------------------------------------------------- #
def _read_model(service_id, *, store, catalog=()):
    with engine_env(catalog, store):
        from aiac.policy.computation import policy_model_for

        return policy_model_for(service_id)


def test_policy_model_for_returns_the_stored_spm_as_the_only_entry():
    catalog, initial = _resync_fixture()
    store = FakeStore(initial)

    # the stored SPM with the current holders: the disabled failed-agent is not one
    assert _read_model("github-tool", store=store, catalog=catalog) == PolicyModel(
        services=[_without_holder(initial["github-tool"], "r-failed-src")]
    )
    assert store.calls == []  # writes nothing


def test_policy_model_for_returns_none_when_the_store_has_no_spm():
    catalog, initial = _resync_fixture()

    assert _read_model("never-seen", store=FakeStore(initial), catalog=catalog) is None


def test_policy_model_for_returns_a_stored_spm_with_no_content():
    # A stored zero-rule SPM with no aiac.managed roles or scopes is still in the managed set: the
    # read model goes by the stored SPMs, not by the content of get_service_policy (whose 404
    # placeholder looks the same).
    bare = _spm("bare-agent")
    store = FakeStore({"bare-agent": bare})

    assert _read_model("bare-agent", store=store) == PolicyModel(services=[bare])


def test_policy_model_for_takes_no_lock():
    from aiac.policy.computation import engine

    catalog, initial = _resync_fixture()
    store = FakeStore(initial)
    result = []
    with engine_env(catalog, store), engine._pce_lock:
        from aiac.policy.computation import policy_model_for

        worker = threading.Thread(target=lambda: result.append(policy_model_for("github-agent")))
        worker.start()
        worker.join(2)  # it finishes while another holder has the PCE lock
        assert not worker.is_alive(), "policy_model_for waited on the PCE lock"
    assert result == [PolicyModel(services=[initial["github-agent"]])]


# --------------------------------------------------------------------------- #
# bootstrap (checkpoint B1) — before UC-1 Provision, under the PCE lock, write   #
# the focus tool's first CR so that discovery (tools/list through the tool's own #
# inbound) passes D20: apply_policy with SPM(focus) — the stored SPM, or a       #
# zero-rule SPM of the given type, its identity seeded from the catalog. It      #
# stores no SPM.                                                                 #
# --------------------------------------------------------------------------- #
def run_bootstrap(service_id, service_type, *, catalog, store) -> FakeStore:
    with engine_env(catalog, store):
        from aiac.policy.computation import bootstrap

        bootstrap(service_id, service_type)
    return store


def test_bootstrap_pushes_a_zero_rule_spm_of_the_given_type_and_stores_nothing():
    # Before Provision the client exists, but it has no type and no aiac.managed scope yet.
    profile = _scope("s-profile", "profile", service_id="new-tool", aiac_managed=False)
    catalog = [_service("new-tool", type=None, scopes=[profile])]
    store = run_bootstrap("new-tool", ServiceType.TOOL, catalog=catalog, store=FakeStore())

    assert store.policy_pushes == [PolicyModel(services=[_spm("new-tool", type=ServiceType.TOOL)])]
    assert store.data == {}
    assert [op for op, _ in store.calls] == ["apply_policy"]


def test_bootstrap_seeds_the_zero_rule_spm_from_the_catalog():
    TS = _scope("s-tool-read", "tool-read", service_id="new-tool")
    catalog = [_service("new-tool", type=None, scopes=[TS])]
    store = run_bootstrap("new-tool", ServiceType.TOOL, catalog=catalog, store=FakeStore())

    expected = _spm("new-tool", type=ServiceType.TOOL, owned_scopes=[TS])
    assert store.policy_pushes == [PolicyModel(services=[expected])]


def test_bootstrap_of_a_service_absent_from_the_catalog_pushes_a_bare_zero_rule_spm():
    store = run_bootstrap("new-tool", ServiceType.TOOL, catalog=[], store=FakeStore())

    assert store.policy_pushes == [PolicyModel(services=[_spm("new-tool", type=ServiceType.TOOL)])]


def test_bootstrap_pushes_the_stored_spm_of_a_managed_tool():
    AR, UR, AS, TS, catalog = _repro()
    stored = _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS), _rule(UR, TS)])
    store = run_bootstrap("github-tool", ServiceType.TOOL, catalog=catalog, store=FakeStore({"github-tool": stored}))

    assert store.policy_pushes == [PolicyModel(services=[stored])]
    assert store.service_writes == []


def test_drop_bootstrap_deletes_the_cr_of_a_service_with_no_spm():
    store = FakeStore()
    with engine_env([], store):
        from aiac.policy.computation import drop_bootstrap

        drop_bootstrap("new-tool")

    assert store.cr_deletes == ["new-tool"]


def test_drop_bootstrap_keeps_the_cr_of_a_managed_service():
    store = FakeStore({"github-tool": _spm("github-tool", type=ServiceType.TOOL)})
    with engine_env([], store):
        from aiac.policy.computation import drop_bootstrap

        drop_bootstrap("github-tool")

    assert store.cr_deletes == []


def test_drop_bootstrap_holds_the_pce_lock():
    store = FakeStore()
    with engine_env([], store):
        from aiac.policy.computation import drop_bootstrap

        _blocks_while_pce_lock_held(lambda: drop_bootstrap("new-tool"))

    assert store.cr_deletes == ["new-tool"]


def test_bootstrap_holds_the_pce_lock():
    store = FakeStore()
    with engine_env([], store):
        from aiac.policy.computation import bootstrap

        _blocks_while_pce_lock_held(lambda: bootstrap("new-tool", ServiceType.TOOL))


def test_bootstrap_failure_is_logged_and_reraised(caplog):
    store = FakeStore()
    with (
        engine_env([], store),
        patch("aiac.policy.computation.engine.apply_policy", side_effect=RuntimeError("writer down")),
    ):
        from aiac.policy.computation import bootstrap

        with pytest.raises(RuntimeError, match="writer down"):
            bootstrap("new-tool", ServiceType.TOOL)

    assert "bootstrap failed" in caplog.text


# --------------------------------------------------------------------------- #
# The IdP read under the PCE lock (D22, D32) — each operation that writes     #
# reads the IdP one time, after it takes the PCE lock. A read before the lock #
# gives the IdP as it was before the operation that held the lock finished,   #
# so the operation could write back what that one removed.                    #
# --------------------------------------------------------------------------- #
_ENTRY_POINTS = {
    "compute_and_apply": lambda pce: pce.compute_and_apply([], focus_service="github-agent"),
    "decommission": lambda pce: pce.decommission("github-agent"),
    "quarantine": lambda pce: pce.quarantine("github-agent"),
    "resync": lambda pce: pce.resync(),
    "bootstrap": lambda pce: pce.bootstrap("github-tool", ServiceType.TOOL),
    "policy_model_for": lambda pce: pce.policy_model_for("github-agent"),
    "rerender_role": lambda pce: pce.rerender_role("r-agent-src"),
}


_WRITING_ENTRY_POINTS = [name for name in _ENTRY_POINTS if name != "policy_model_for"]


@pytest.mark.parametrize("entry_point", _WRITING_ENTRY_POINTS)
def test_every_writing_entry_point_reads_the_idp_once_under_the_pce_lock(entry_point):
    from aiac import policy
    from aiac.policy.computation import engine

    catalog, initial = _resync_fixture()
    store = FakeStore(initial)
    reads = []  # (the IdP read, the PCE lock is held) — one thread, so a held lock is the operation's
    given = []  # what get_roles returned: the catalog read takes it, so GET /roles is sent one time
    with engine_env(catalog, store):
        members = Configuration.get_roles.side_effect

        def get_services(roles=None):
            reads.append(("get_services", engine._pce_lock.locked(), roles))
            return list(catalog)

        def get_roles():
            reads.append(("get_roles", engine._pce_lock.locked()))
            given.append(members())
            return given[-1]

        with (
            patch.object(Configuration, "get_services", side_effect=get_services),
            patch.object(Configuration, "get_roles", side_effect=get_roles),
        ):
            _ENTRY_POINTS[entry_point](policy.computation)

    assert reads == [("get_roles", True), ("get_services", True, given[0])]


def test_a_run_that_waits_for_the_pce_lock_reads_the_idp_after_it_takes_the_lock():
    # A run waits for the PCE lock while another operation holds it. In that time the rollback of the
    # tool's failed onboarding disables the tool. The run reads the catalog after it takes the lock, so
    # its routing guard sees the tool disabled and drops the rule: a build that started before the
    # failure does not write its rule into the footprint that the quarantine removes.
    from aiac.policy.computation import engine

    AR, UR, AS, TS, catalog = _guard_catalog()
    *_, disabled = _guard_catalog(tool_enabled=False)
    idp = {"catalog": catalog}
    store = FakeStore()
    with (
        engine_env(catalog, store) as compute,
        patch.object(Configuration, "get_services", side_effect=lambda roles=None: list(idp["catalog"])),
    ):
        with engine._pce_lock:  # another operation holds the lock
            threads, errors = _run_in_threads(lambda: compute([_rule(UR, TS)]))
            threads[0].join(0.3)
            assert threads[0].is_alive(), "the run did not wait for the PCE lock"
            idp["catalog"] = disabled  # the rollback disables the tool
        threads[0].join(5)
    assert not errors

    assert "github-tool" not in store.data
    assert store.policy_pushes == []


# =========================================================================== #
# Render-time role holders (D32). A stored edge                                #
# keeps a copy of ``Role.actorIds`` from the run that built it (a snapshot).   #
# Every render uses the current holders instead: an Agent-kind role is held by #
# each live service in the catalog that has it, and a User-kind role by the    #
# members that get_roles() gives now. A membership change needs no PRB run.    #
# =========================================================================== #
_A1 = "spiffe://localtest.me/ns/team1/sa/github-agent"
_A2 = "spiffe://localtest.me/ns/team2/sa/github-agent"
_T1 = "spiffe://localtest.me/ns/team1/sa/github-tool"


def _shared(*holders) -> Role:
    """The shared realm role ``github-agent.source_operations`` (Provision reuses it by name in team1
    and team2). ``GET /services/{id}/roles`` gives each service's copy with only that service."""
    return _role("r-src-op", "github-agent.source_operations", kind=RoleKind.AGENT, actor_ids=list(holders))


def _source_read() -> Scope:
    return _scope("s-source-read", "github-tool.source-read", service_id=_T1)


def _sharing_catalog(*, a2_enabled=True):
    """Both agents hold the shared role; the tool owns the scope."""
    return [
        _agent(_A1, roles=[_shared(_A1)]),
        _agent(_A2, roles=[_shared(_A2)], enabled=a2_enabled),
        _tool(_T1, scopes=[_source_read()]),
    ]


def _stored_tool(*rules) -> ServicePolicyModel:
    return _spm(_T1, type=ServiceType.TOOL, owned_scopes=[_source_read()], inbound=list(rules))


def _source_roles(model):
    """The callers that the CR of ``model`` names (the writer's ``project_inbound``)."""
    return {caller: [r.id for r in roles] for caller, roles in project_inbound(model).source_roles.items()}


def _subject_roles(model):
    return {user: [r.id for r in roles] for user, roles in project_inbound(model).subject_roles.items()}


def _render_tool(path, *, catalog, initial, roles=None, role_id="r-src-op") -> ServicePolicyModel:
    """Run one render path that makes no PRB call, and return the tool's entry that it
    deploys: ``rerender_role`` (the role-members event), ``resync`` (the Controller start),
    ``bootstrap`` (the tool's CR before the Provision of its re-onboarding: the store has its SPM), or
    an unrelated ``compute_and_apply`` (a new user rule on the tool)."""
    store = FakeStore(initial)
    with engine_env(catalog, store, roles) as compute:
        from aiac.policy import computation

        if path == "rerender_role":
            computation.rerender_role(role_id)
        elif path == "resync":
            computation.resync()
        elif path == "bootstrap":
            computation.bootstrap(_T1, ServiceType.TOOL)
        else:
            compute([_rule(_user_role("r-user-ops", "ops", users=["ops-user"]), _source_read())])
    pushes = store.policy_replaces if path == "resync" else store.policy_pushes
    return next(spm for push in pushes for spm in push.services if spm.service_id == _T1)


_RENDER_PATHS = ["rerender_role", "resync", "bootstrap", "compute_and_apply"]


# ---- Bug 1: every holder of a shared role is in the tool CR --------------- #
@pytest.mark.parametrize("first, second", [(_A1, _A2), (_A2, _A1)], ids=["team1-first", "team2-first"])
def test_both_onboarding_orders_put_every_holder_of_a_shared_role_in_the_tool_cr(first, second):
    # Each agent's build sees only its own copy of the role, so the second rule is a duplicate of
    # the first (same role, scope and effect). The tool's CR still names both holders.
    TS = _source_read()
    tool = _tool(_T1, scopes=[TS])
    agents = {sid: _agent(sid, roles=[_shared(sid)]) for sid in (_A1, _A2)}
    store = FakeStore({_T1: _stored_tool()})
    with engine_env([tool, agents[first]], store) as compute:
        compute([_rule(_shared(first), TS)], focus_service=first)
    with engine_env([tool, agents[first], agents[second]], store) as compute:
        compute([_rule(_shared(second), TS)], focus_service=second)

    assert _source_roles(store.pushed_service(_T1)) == {_A1: ["r-src-op"], _A2: ["r-src-op"]}
    assert store.data[_T1] == _stored_tool(_rule(_shared(_A1, _A2), TS))  # the same in both orders


def test_a_duplicate_rule_whose_holders_are_current_writes_nothing_and_deploys_the_spm():
    # The SPM is touched, so it is deployed (a render with no SPM write can have left its CR with
    # other holders than its snapshot); its rules and its snapshot did not change, so it is not written.
    TS = _source_read()
    initial = {_T1: _stored_tool(_rule(_shared(_A1, _A2), TS))}
    store = run_engine([_rule(_shared(_A2), TS)], catalog=_sharing_catalog(), store_initial=initial)

    assert store.policy_pushes == [PolicyModel(services=[initial[_T1]])]
    assert store.service_writes == []


@pytest.mark.parametrize("path", _RENDER_PATHS)
def test_a_holder_added_later_is_in_the_next_render(path):
    # The stored edge is the old snapshot (team1 only); team2 got the role after the rule was stored.
    initial = {_T1: _stored_tool(_rule(_shared(_A1), _source_read()))}
    tool = _render_tool(path, catalog=_sharing_catalog(), initial=initial)

    assert _source_roles(tool) == {_A1: ["r-src-op"], _A2: ["r-src-op"]}


@pytest.mark.parametrize("path", _RENDER_PATHS)
@pytest.mark.parametrize("gone", ["disabled", "absent", "unassigned"])
def test_a_removed_or_disabled_holder_is_gone_from_the_next_render(path, gone):
    catalog = {
        "disabled": _sharing_catalog(a2_enabled=False),
        "absent": [svc for svc in _sharing_catalog() if svc.serviceId != _A2],
        "unassigned": [_agent(_A1, roles=[_shared(_A1)]), _agent(_A2), _tool(_T1, scopes=[_source_read()])],
    }[gone]
    initial = {_T1: _stored_tool(_rule(_shared(_A1, _A2), _source_read()))}
    tool = _render_tool(path, catalog=catalog, initial=initial)

    assert _source_roles(tool) == {_A1: ["r-src-op"]}


# ---- Bug 4: the members of a user role ------------------------------------ #
def _developer(*users) -> Role:
    return _user_role("r-user-dev", "developer", users=list(users))


@pytest.mark.parametrize("path", ["rerender_role", "resync", "bootstrap"])
def test_a_user_who_gets_a_role_after_the_rule_was_stored_is_in_subject_roles(path):
    initial = {_T1: _stored_tool(_rule(_developer("dev-user"), _source_read()))}
    roles = [_developer("dev-user", "new-user")]
    tool = _render_tool(path, catalog=_sharing_catalog(), initial=initial, roles=roles, role_id="r-user-dev")

    assert _subject_roles(tool) == {"dev-user": ["r-user-dev"], "new-user": ["r-user-dev"]}


@pytest.mark.parametrize("path", ["rerender_role", "resync", "bootstrap"])
def test_a_user_who_loses_a_role_is_not_in_subject_roles(path):
    # The revocation reaches the CR, although the stored snapshot still names dev-user.
    initial = {_T1: _stored_tool(_rule(_developer("dev-user", "ops-user"), _source_read()))}
    roles = [_developer("ops-user")]
    tool = _render_tool(path, catalog=_sharing_catalog(), initial=initial, roles=roles, role_id="r-user-dev")

    assert _subject_roles(tool) == {"ops-user": ["r-user-dev"]}


def test_a_user_role_that_get_roles_does_not_list_has_no_holder():
    # A deleted role: fail closed, no user keeps its grant.
    initial = {_T1: _stored_tool(_rule(_developer("dev-user"), _source_read()))}
    tool = _render_tool("resync", catalog=_sharing_catalog(), initial=initial, roles=[])

    assert _subject_roles(tool) == {}


# ---- the kind of a role comes from the catalog (composite-kind) ------------ #
def _child_copy() -> Role:
    """The shared role as a child of a composite role: the composites endpoint gives it with no
    per-service kind, so it keeps kind=User and no holders."""
    return Role(id="r-src-op", name="github-agent.source_operations", composite=False)


def _realm_copy() -> Role:
    """GET /roles: the shared role as a realm role, with the service accounts of its holders."""
    return _role(
        "r-src-op", "github-agent.source_operations", kind=RoleKind.USER, actor_ids=["service-account-github-agent"]
    )


@pytest.mark.parametrize("path", _RENDER_PATHS)
@pytest.mark.parametrize("effect", [RuleEffect.ALLOW, RuleEffect.DENY])
def test_an_edge_whose_role_a_service_holds_names_its_holders_as_callers(path, effect):
    # The holders of the role are services, so the CR names them in source_roles, and a deny of the
    # role is a source deny. Before the fix, the User kind of the stored edge put the service
    # account in subject_roles and lost the source gate.
    initial = {_T1: _stored_tool(_rule(_child_copy(), _source_read(), effect))}
    tool = _render_tool(path, catalog=_sharing_catalog(), initial=initial, roles=[_realm_copy()])

    assert _source_roles(tool) == {_A1: ["r-src-op"], _A2: ["r-src-op"]}
    assert "service-account-github-agent" not in _subject_roles(tool)
    projection = project_inbound(tool)
    source = projection.source_allow_rules if effect == RuleEffect.ALLOW else projection.source_deny_rules
    assert _pairs(source) == [("r-src-op", "s-source-read")]


# ---- bootstrap: the service is the focus, so it counts as live ------------- #
# The re-onboarding of a disabled service that still has an SPM: a quarantine that failed before it
# deleted the SPM, or a client that an admin disabled before the resync (C2). The service holds an
# agent role that is mapped to its own scope (a self-mapping, which D32 allows). The service is the
# focus of its onboarding, so it holds the role while its client is disabled, and its CR keeps its
# own grant until the onboarding's run (else the CR drops the grant, fail closed).
def test_bootstrap_of_a_disabled_tool_keeps_the_tool_as_the_holder_of_its_self_mapped_role():
    TS = _source_read()
    own = _agent_role("r-tool-self", "github-tool.self", owner=_T1)
    stored = _spm(_T1, type=ServiceType.TOOL, owned_roles=[own], owned_scopes=[TS], inbound=[_rule(own, TS)])
    catalog = [_tool(_T1, roles=[own], scopes=[TS], enabled=False)]
    store = run_bootstrap(_T1, ServiceType.TOOL, catalog=catalog, store=FakeStore({_T1: stored}))

    assert _source_roles(store.pushed_service(_T1)) == {_T1: ["r-tool-self"]}
    assert store.policy_pushes == [PolicyModel(services=[stored])]
    assert store.service_writes == []


# ---- rerender_role (R7) ---------------------------------------------------- #
def _rerender_fixture():
    """The shared role has edges on the live tool, on a disabled tool and on a tool that is absent
    from the catalog (deleted). other-tool has no edge of the role."""
    TS = _source_read()
    DS = _scope("s-disabled-read", service_id="disabled-tool")
    GS = _scope("s-ghost-read", service_id="ghost-tool")
    OS = _scope("s-other-read", service_id="other-tool")
    stale = _shared(_A1)
    initial = {
        _T1: _stored_tool(_rule(stale, TS), _rule(_developer("dev-user"), TS)),
        "disabled-tool": _spm("disabled-tool", type=ServiceType.TOOL, owned_scopes=[DS], inbound=[_rule(stale, DS)]),
        "ghost-tool": _spm("ghost-tool", type=ServiceType.TOOL, owned_scopes=[GS], inbound=[_rule(stale, GS)]),
        "other-tool": _spm(
            "other-tool", type=ServiceType.TOOL, owned_scopes=[OS], inbound=[_rule(_developer("dev-user"), OS)]
        ),
    }
    catalog = _sharing_catalog() + [
        _tool("disabled-tool", scopes=[DS], enabled=False),
        _tool("other-tool", scopes=[OS]),
    ]
    return catalog, initial


def run_rerender(role_id, *, catalog, store, roles=None) -> FakeStore:
    with engine_env(catalog, store, roles):
        from aiac.policy.computation import rerender_role

        rerender_role(role_id)
    return store


def test_rerender_role_applies_the_live_spms_that_have_the_role_and_writes_no_spm():
    catalog, initial = _rerender_fixture()
    store = run_rerender("r-src-op", catalog=catalog, store=FakeStore(initial))

    TS = _source_read()
    expected = _stored_tool(_rule(_shared(_A1, _A2), TS), _rule(_developer("dev-user"), TS))
    assert store.policy_pushes == [PolicyModel(services=[expected])]
    assert [op for op, _ in store.calls] == ["apply_policy"]  # no SPM write, no CR delete, no PUT
    assert store.data == initial  # the stored snapshot stays
    assert [r.id for r in store.by_role_calls] == ["r-src-op"]


def test_rerender_role_of_a_role_that_no_spm_has_makes_no_call():
    catalog, initial = _rerender_fixture()
    store = run_rerender("r-unused", catalog=catalog, store=FakeStore(initial))

    assert store.calls == []


def test_rerender_role_holds_the_pce_lock():
    catalog, initial = _rerender_fixture()
    store = FakeStore(initial)
    with engine_env(catalog, store):
        from aiac.policy.computation import rerender_role

        _blocks_while_pce_lock_held(lambda: rerender_role("r-src-op"))


def test_rerender_role_failure_is_logged_and_reraised(caplog):
    catalog, initial = _rerender_fixture()
    with (
        engine_env(catalog, FakeStore(initial)),
        patch("aiac.policy.computation.engine.apply_policy", side_effect=RuntimeError("writer down")),
    ):
        from aiac.policy.computation import rerender_role

        with pytest.raises(RuntimeError, match="writer down"):
            rerender_role("r-src-op")

    assert "rerender_role failed" in caplog.text


# ---- the routing guard with a shared role (R4) ----------------------------- #
def test_guard_routes_a_shared_role_that_a_live_service_still_holds():
    # The build saw only the copy of team2, now disabled. team1 still holds the role, so the grant is
    # team1's too: the rule is routed, with the live holder only.
    TS = _source_read()
    store = run_engine([_rule(_shared(_A2), TS)], catalog=_sharing_catalog(a2_enabled=False))

    assert store.data[_T1].inbound_allow_rules == [_rule(_shared(_A1), TS)]
    assert _source_roles(store.pushed_service(_T1)) == {_A1: ["r-src-op"]}


def test_guard_drops_a_role_that_no_live_service_holds_now():
    # The stale copy names team1, which is live but does not hold the role now; its only holder,
    # team2, is disabled.
    TS = _source_read()
    catalog = [_agent(_A1), _agent(_A2, roles=[_shared(_A2)], enabled=False), _tool(_T1, scopes=[TS])]
    store = run_engine([_rule(_shared(_A1), TS)], catalog=catalog)

    assert _T1 not in store.data
    assert store.apply_policy_count == 0


# ---- the read model (R8) --------------------------------------------------- #
def test_policy_model_for_shows_the_current_holders():
    TS = _source_read()
    store = FakeStore({_T1: _stored_tool(_rule(_shared(_A1), TS), _rule(_developer("dev-user"), TS))})
    with engine_env(_sharing_catalog(), store, roles=[_developer("new-user")]):
        from aiac.policy.computation import policy_model_for

        model = policy_model_for(_T1)

    assert model == PolicyModel(
        services=[_stored_tool(_rule(_shared(_A1, _A2), TS), _rule(_developer("new-user"), TS))]
    )
    assert store.calls == []


# ---- quarantine and decommission of one holder of a shared role ------------ #
# The removed holder's role stays (team1 still holds it), so no SPM loses an     #
# edge. The callees that have an edge of the role still get a new render: their  #
# CRs must not name the removed holder. A client delete gives no role-mapping     #
# event, so nothing else repairs the CRs before the resync.                       #
def _shared_removal_fixture(op):
    """team1 and team2 hold the shared role, and both call the tool and agent-b; the stored edges name
    both. team2 is removed: quarantined (disabled, still in the catalog) or decommissioned (absent)."""
    TS = _source_read()
    BS = _scope("s-b-inbound", "agent-b.inbound", service_id="agent-b")
    both = _shared(_A1, _A2)
    initial = {
        _T1: _stored_tool(_rule(both, TS)),
        "agent-b": _spm("agent-b", owned_scopes=[BS], inbound=[_rule(both, BS)]),
        _A1: _spm(_A1, owned_roles=[_shared(_A1)]),
        _A2: _spm(_A2, owned_roles=[_shared(_A2)]),
    }
    catalog = [_agent(_A1, roles=[_shared(_A1)]), _agent("agent-b", scopes=[BS]), _tool(_T1, scopes=[TS])]
    if op == "quarantine":
        catalog.append(_agent(_A2, roles=[_shared(_A2)], enabled=False))
    return catalog, initial


def _remove(op, service_id, *, catalog, store) -> FakeStore:
    with engine_env(catalog, store):
        from aiac.policy import computation

        getattr(computation, op)(service_id)
    return store


@pytest.mark.parametrize("op", ["quarantine", "decommission"])
def test_removing_one_holder_of_a_shared_role_redeploys_its_callees_without_it(op):
    catalog, initial = _shared_removal_fixture(op)
    store = _remove(op, _A2, catalog=catalog, store=FakeStore(initial))

    (push,) = store.policy_pushes  # one call, with the callees of the shared role
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1]
    assert [_source_roles(spm) for spm in push.services] == [{_A1: ["r-src-op"]}] * 2
    # Their rules did not change, so the store keeps them as they are: only SPM(team2) goes.
    assert store.service_writes == []
    assert store.data == {sid: m for sid, m in initial.items() if sid != _A2}
    assert [call for call, _ in store.calls] == ["delete_service_cr", "apply_policy", "delete"]


# A disabled holder still holds the shared role in the catalog (Keycloak keeps #
# the mapping of a disabled client), so the removal of the other holder purges #
# no edge of the role: the edges are the grants of the disabled holder too,    #
# and its lift gives them back. It is not live, so it is not a holder in the   #
# CRs until then.                                                              #
def _disabled_holder_fixture(op):
    """``_shared_removal_fixture``, but team1 was quarantined first: it is disabled, and its SPM is
    gone. team2, the other holder, is removed now."""
    catalog, initial = _shared_removal_fixture(op)
    catalog = [svc.model_copy(update={"enabled": False}) if svc.serviceId == _A1 else svc for svc in catalog]
    del initial[_A1]
    return catalog, initial


@pytest.mark.parametrize("op", ["quarantine", "decommission"])
def test_a_disabled_holder_keeps_a_shared_role_but_the_crs_name_no_holder_of_it(op):
    catalog, initial = _disabled_holder_fixture(op)
    store = _remove(op, _A2, catalog=catalog, store=FakeStore(initial))

    (push,) = store.policy_pushes
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1]
    assert [_pairs(_inbound(spm)) for spm in push.services] == [
        [("r-src-op", "s-b-inbound")],
        [("r-src-op", "s-source-read")],
    ]
    assert [_source_roles(spm) for spm in push.services] == [{}] * 2  # neither holder is live
    assert store.service_writes == []  # no edge is purged
    assert store.data == {sid: m for sid, m in initial.items() if sid != _A2}


@pytest.mark.parametrize("op", ["quarantine", "decommission"])
def test_the_lift_of_a_disabled_holder_gives_it_back_the_kept_shared_role(op):
    # The re-onboarding of team1 routes no rule to the callees (their edges came from their own
    # onboardings), so only the kept edges give team1 its grants back.
    catalog, initial = _disabled_holder_fixture(op)
    store = _remove(op, _A2, catalog=catalog, store=FakeStore(initial))
    before = len(store.policy_pushes)

    with engine_env(catalog, store) as compute:
        compute([], focus_service=_A1)

    (push,) = store.policy_pushes[before:]
    deployed = {spm.service_id: spm for spm in push.services}
    assert sorted(deployed) == sorted(["agent-b", _T1, _A1])
    assert [_source_roles(deployed[sid]) for sid in ("agent-b", _T1)] == [{_A1: ["r-src-op"]}] * 2


# ---- the snapshot repair (D-08, LIM-07) ----------------------------------- #
# A render that writes no SPM (rerender_role, the resync) can leave a CR with    #
# more holders than the stored snapshot. A holder that then loses the role with  #
# no event (a lost event) does not make the SPM stale. A later run that touches  #
# the SPM, also with a duplicate rule only, deploys it with the current holders. #
_SKILL = _agent_role("r-skill", "agent-a.skill", owner="agent-a")
_C_READ = _scope("s-c-read", "tool-c.read", service_id="tool-c")


def _snapshot_store(*holders) -> FakeStore:
    """The tool's edge of the skill names ``holders`` (the snapshot); agent-a and agent-b are stored."""
    edge = _rule(_SKILL.model_copy(update={"actorIds": list(holders)}), _C_READ)
    return FakeStore(
        {
            "tool-c": _spm("tool-c", type=ServiceType.TOOL, owned_scopes=[_C_READ], inbound=[edge]),
            "agent-a": _spm("agent-a", owned_roles=[_SKILL]),
            "agent-b": _spm("agent-b"),
        }
    )


def _skill_catalog(*holders):
    """agent-a and agent-b; each one in ``holders`` holds the skill. The tool owns the scope."""
    agents = [_agent(sid, roles=[_SKILL] if sid in holders else []) for sid in ("agent-a", "agent-b")]
    return [*agents, _tool("tool-c", scopes=[_C_READ])]


@pytest.mark.parametrize("render", ["rerender_role", "resync"])
def test_a_later_run_repairs_a_cr_that_a_render_with_no_write_left_with_a_lost_holder(render):
    store = _snapshot_store("agent-a")
    with engine_env(_skill_catalog("agent-a", "agent-b"), store):  # agent-b got the skill
        from aiac.policy import computation

        computation.rerender_role("r-skill") if render == "rerender_role" else computation.resync()
    rendered = (store.policy_replaces if render == "resync" else store.policy_pushes)[-1]
    tool = next(spm for spm in rendered.services if spm.service_id == "tool-c")
    assert _source_roles(tool) == {"agent-a": ["r-skill"], "agent-b": ["r-skill"]}, "the render named agent-b"
    assert [r.role.actorIds for r in store.data["tool-c"].inbound_allow_rules] == [["agent-a"]], "no write"

    # agent-b loses the skill and the event is lost. agent-a re-onboards: a duplicate rule on the tool.
    before = len(store.policy_pushes)
    with engine_env(_skill_catalog("agent-a"), store) as compute:
        compute([_rule(_SKILL, _C_READ)], focus_service="agent-a")

    (push,) = store.policy_pushes[before:]
    assert [spm.service_id for spm in push.services] == ["agent-a", "tool-c"]
    assert _source_roles(push.services[1]) == {"agent-a": ["r-skill"]}
    assert "tool-c" not in [sid for sid, _ in store.service_writes], "its snapshot is current: not written"


# ---- decommission of a holder that got a shared role later (B-04, B-05) ----- #
# An admin assigned the shared role to team2 after SPM(team2) was written. The   #
# role-members event re-rendered the callees with team2 and wrote no SPM, so     #
# SPM(team2).owned_roles does not list the role, and the stored edges do not     #
# name team2. Then team2's client is deleted and the operator offboards it. X is #
# gone from the IdP, so only a decommission takes it out of those CRs.           #
def _later_holder_fixture(*, other_holder):
    """The store before the admin's assignment: the edges of the shared role on the tool and on
    agent-b name team1 only; SPM(team2) lists no role. ``other_holder``: team1 still holds the role,
    or no other service holds it (team1 is gone too)."""
    TS = _source_read()
    BS = _scope("s-b-inbound", "agent-b.inbound", service_id="agent-b")
    A2S = _scope("s-a2-inbound", "a2.inbound", service_id=_A2)
    initial = {
        _T1: _stored_tool(_rule(_shared(_A1), TS)),
        "agent-b": _spm("agent-b", owned_scopes=[BS], inbound=[_rule(_shared(_A1), BS)]),
        _A2: _spm(_A2, owned_scopes=[A2S]),
    }
    others = [_agent("agent-b", scopes=[BS]), _tool(_T1, scopes=[TS])]
    if other_holder:
        initial[_A1] = _spm(_A1, owned_roles=[_shared(_A1)])
        others.append(_agent(_A1, roles=[_shared(_A1)]))
    with_team2 = [*others, _agent(_A2, roles=[_shared(_A2)], scopes=[A2S])]
    return with_team2, others, initial


def _assign_then_decommission(*, other_holder) -> tuple[FakeStore, int]:
    """The role-members event of the admin's assignment, then the decommission of team2. Returns the
    store and the number of pushes before the decommission."""
    with_team2, without_team2, initial = _later_holder_fixture(other_holder=other_holder)
    store = run_rerender("r-src-op", catalog=with_team2, store=FakeStore(initial))
    before = len(store.policy_pushes)
    run_decommission(_A2, catalog=without_team2, store=store)
    return store, before


@pytest.mark.parametrize("other_holder", [True, False], ids=["team1-holds-it", "no-other-holder"])
def test_decommission_takes_a_later_holder_of_a_shared_role_out_of_its_callee_crs(other_holder):
    store, before = _assign_then_decommission(other_holder=other_holder)
    (event_push,) = store.policy_pushes[:before]
    tool_before = next(spm for spm in event_push.services if spm.service_id == _T1)
    holders_before = {_A1: ["r-src-op"], _A2: ["r-src-op"]} if other_holder else {_A2: ["r-src-op"]}
    assert _source_roles(tool_before) == holders_before, "the role-members event put team2 in the CR"

    (push,) = store.policy_pushes[before:]  # one call, with the callees of the role
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1]
    expected = {_A1: ["r-src-op"]} if other_holder else {}
    assert [_source_roles(spm) for spm in push.services] == [expected] * 2
    # Their rules did not change, so only SPM(team2) goes from the store.
    assert store.service_writes == []
    assert [op for op, _ in store.calls[-3:]] == ["delete_service_cr", "apply_policy", "delete"]


def _composite_child_fixture():
    """The edges on the tool and on agent-b are of a child of a composite role: the composites
    endpoint gives it with no per-service kind, so they carry ``kind=User``, and no service or user
    held it when they were stored. Then an admin maps the child to team2 alone, after SPM(team2) was
    written. Returns the catalog with team2, the catalog without it, and the store."""
    TS = _source_read()
    BS = _scope("s-b-inbound", "agent-b.inbound", service_id="agent-b")
    A2S = _scope("s-a2-inbound", "a2.inbound", service_id=_A2)
    child = _role("r-child", "child", kind=RoleKind.USER, actor_ids=[])
    initial = {
        _T1: _stored_tool(_rule(child, TS)),
        "agent-b": _spm("agent-b", owned_scopes=[BS], inbound=[_rule(child, BS)]),
        _A2: _spm(_A2, owned_scopes=[A2S]),
    }
    others = [_agent("agent-b", scopes=[BS]), _tool(_T1, scopes=[TS])]
    held = _role("r-child", "child", kind=RoleKind.AGENT, actor_ids=[_A2])
    return [*others, _agent(_A2, roles=[held], scopes=[A2S])], others, initial


def test_decommission_takes_the_only_holder_of_a_user_kind_edge_out_of_its_callee_crs():
    # The role-members event renders team2 as a caller (a service holds the child, so it is an agent
    # role). After the client delete, no service and no user holds the child, and the edges still
    # carry kind=User: the decommission must still render them again, with no holder.
    with_team2, without_team2, initial = _composite_child_fixture()
    store = run_rerender("r-child", catalog=with_team2, store=FakeStore(initial))
    before = len(store.policy_pushes)
    assert _source_roles(store.pushed_service(_T1)) == {_A2: ["r-child"]}, "the event put team2 in the CR"

    run_decommission(_A2, catalog=without_team2, store=store)

    (push,) = store.policy_pushes[before:]
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1]
    assert [_source_roles(spm) for spm in push.services] == [{}, {}]
    assert store.service_writes == []


def test_decommission_does_not_redeploy_an_spm_whose_edges_are_of_user_roles_with_members():
    # A user role with members cannot name a service as a caller (Assumption 1), so the CR of the
    # tool cannot name X: it is not redeployed.
    TS = _source_read()
    xs = _scope("s-x", "x.in", service_id="x")
    initial = {
        _T1: _stored_tool(_rule(_user_role("r-user-dev", "developer", users=["dev-user"]), TS)),
        "x": _spm("x", owned_scopes=[xs]),
    }
    store = run_decommission("x", catalog=[_tool(_T1, scopes=[TS])], store=FakeStore(initial))

    assert store.policy_pushes == []
    assert [op for op, _ in store.calls] == ["delete_service_cr", "delete"]


# ---- a removal that fails part way is done again by its retry --------------- #
# The removal changes the store last: first the CR delete and the redeploy, then #
# the writes of the purged SPMs, and then the delete of SPM(X). So when a step    #
# fails, SPM(X) is still stored, and the retry (the operator's, or the resync's   #
# for a quarantine) finds the whole footprint again: the purged SPMs, which only #
# the store (SPM(X) and the unpurged edges) can give.                             #
def _retry_fixture(op):
    """team2 holds the shared role (with team1) and its own role ``r-a2-own``; agent-c holds
    ``r-c-src`` and targets team2. The edges: the shared role on the tool and on agent-b, ``r-a2-own``
    on agent-c (purged at the removal, and agent-c has no other edge), ``r-c-src`` on SPM(team2).
    team2 is removed: quarantined (disabled) or decommissioned (absent)."""
    TS = _source_read()
    BS = _scope("s-b-inbound", "agent-b.inbound", service_id="agent-b")
    CS = _scope("s-c-inbound", "agent-c.inbound", service_id="agent-c")
    A2S = _scope("s-a2-inbound", "a2.inbound", service_id=_A2)
    own = _agent_role("r-a2-own", "a2-own", owner=_A2)
    c_src = _agent_role("r-c-src", "c-source", owner="agent-c")
    both = _shared(_A1, _A2)
    initial = {
        _T1: _stored_tool(_rule(both, TS)),
        "agent-b": _spm("agent-b", owned_scopes=[BS], inbound=[_rule(both, BS)]),
        "agent-c": _spm("agent-c", owned_roles=[c_src], owned_scopes=[CS], inbound=[_rule(own, CS)]),
        _A1: _spm(_A1, owned_roles=[_shared(_A1)]),
        _A2: _spm(_A2, owned_roles=[_shared(_A2), own], owned_scopes=[A2S], inbound=[_rule(c_src, A2S)]),
    }
    catalog = [
        _agent(_A1, roles=[_shared(_A1)]),
        _agent("agent-b", scopes=[BS]),
        _agent("agent-c", roles=[c_src], scopes=[CS]),
        _tool(_T1, scopes=[TS]),
    ]
    if op == "quarantine":
        catalog.append(_agent(_A2, roles=[_shared(_A2), own], scopes=[A2S], enabled=False))
    return catalog, initial


def _fail_once(store, name):
    """Make the boundary call ``name`` of ``store`` raise one time (the next call works)."""
    real = getattr(store, name)
    failed = []

    def flaky(*args):
        if not failed:
            failed.append(name)
            raise RuntimeError(f"{name} is down")
        return real(*args)

    setattr(store, name, flaky)


@pytest.mark.parametrize("failing", ["delete_service_cr", "apply_policy", "apply_service_policy"])
@pytest.mark.parametrize("op", ["quarantine", "decommission"])
def test_the_retry_of_a_removal_that_failed_part_way_gives_what_a_removal_that_did_not_fail_gives(op, failing):
    catalog, initial = _retry_fixture(op)
    reference = _remove(op, _A2, catalog=catalog, store=FakeStore(initial))
    (expected,) = reference.policy_pushes
    assert [spm.service_id for spm in expected.services] == ["agent-b", "agent-c", _T1]
    assert [_source_roles(spm) for spm in expected.services] == [{_A1: ["r-src-op"]}, {}, {_A1: ["r-src-op"]}]

    store = FakeStore(initial)
    _fail_once(store, failing)
    with pytest.raises(RuntimeError, match=f"{failing} is down"):
        _remove(op, _A2, catalog=catalog, store=store)
    assert _A2 in store.data, "SPM(team2) went before the removal was done, so a retry cannot find its footprint"

    _remove(op, _A2, catalog=catalog, store=store)

    assert store.policy_pushes[-1] == expected
    assert store.data == reference.data


# ---- the lift of a quarantine (D32) ----------------------------------------- #
# The quarantine of team2 re-rendered the callees of the shared role without it, #
# but did not write them: their stored snapshot still names team2. The lift (a   #
# successful re-onboarding, team2 is the focus and still disabled) must give     #
# team2 back to those CRs, also when its batch routes no rule to a callee (an    #
# edge that the callee's own onboarding stored) or only a duplicate rule (the    #
# refreshed SPM is equal to the stored one, so it is not stale).                 #
def _lift_fixture(*, a1_enabled=True, a2_enabled=False, a2_stored=False, snapshot=(_A1, _A2)):
    """The store after the quarantine of team2: the live tool and agent-b keep the edges of the
    shared role, with the snapshot of both holders; a disabled tool and a deleted (absent) tool have
    an edge of it too. ``a2_enabled`` / ``a2_stored`` give the same store for a plain re-onboarding
    of an enabled team2 instead (not a lift). ``snapshot`` is the stored holders on those edges: a
    run that wrote the callees while team2 was quarantined left ``(_A1,)``."""
    TS = _source_read()
    BS = _scope("s-b-inbound", "agent-b.inbound", service_id="agent-b")
    DS = _scope("s-disabled-read", service_id="disabled-tool")
    GS = _scope("s-ghost-read", service_id="ghost-tool")
    both = _shared(*snapshot)
    initial = {
        _T1: _stored_tool(_rule(both, TS)),
        "agent-b": _spm("agent-b", owned_scopes=[BS], inbound=[_rule(both, BS)]),
        "disabled-tool": _spm("disabled-tool", type=ServiceType.TOOL, owned_scopes=[DS], inbound=[_rule(both, DS)]),
        "ghost-tool": _spm("ghost-tool", type=ServiceType.TOOL, owned_scopes=[GS], inbound=[_rule(both, GS)]),
        _A1: _spm(_A1, owned_roles=[_shared(_A1)]),
    }
    if a2_stored:
        initial[_A2] = _spm(_A2, owned_roles=[_shared(_A2)])
    catalog = [
        _agent(_A1, roles=[_shared(_A1)], enabled=a1_enabled),
        _agent(_A2, roles=[_shared(_A2)], enabled=a2_enabled),
        _agent("agent-b", scopes=[BS]),
        _tool(_T1, scopes=[TS]),
        _tool("disabled-tool", scopes=[DS], enabled=False),
    ]
    return catalog, initial


def _lift_store(rules, *, catalog, initial) -> FakeStore:
    return run_engine(rules, catalog=catalog, store_initial=initial, focus_service=_A2)


@pytest.mark.parametrize("rules", [[], [_rule(_shared(_A2), _source_read())]], ids=["no-rule", "duplicate-rule"])
def test_a_lift_redeploys_the_live_callees_of_the_focus_roles_with_the_focus(rules):
    catalog, initial = _lift_fixture()
    store = _lift_store(rules, catalog=catalog, initial=initial)

    (push,) = store.policy_pushes  # one call: the focus, and the live callees of its shared role
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1, _A2]
    assert [_source_roles(spm) for spm in push.services[:2]] == [{_A1: ["r-src-op"], _A2: ["r-src-op"]}] * 2
    # The callees' rules did not change and their snapshot is current: only SPM(focus) is written.
    assert [sid for sid, _ in store.service_writes] == [_A2]
    assert {sid: m for sid, m in store.data.items() if sid != _A2} == initial


def test_a_lift_writes_each_lifted_callee_whose_stored_holders_are_stale():
    # team1's re-onboarding wrote the callees while team2 was quarantined (stale holders, step 3.6),
    # so their snapshot names team1 only. The lift deploys them with team2, and must write them too:
    # else the store says team1 only while the CR names team2, and a later run that touches them
    # cannot see that team2 lost the role (fail open). The disabled and the deleted callees are not
    # lifted, so they are not written. The write does not make them changed: the deploy is the same.
    catalog, initial = _lift_fixture(snapshot=(_A1,))
    store = _lift_store([], catalog=catalog, initial=initial)

    assert sorted(sid for sid, _ in store.service_writes) == sorted(["agent-b", _T1, _A2])
    for sid in ("agent-b", _T1):
        assert [rule.role.actorIds for rule in store.data[sid].inbound_allow_rules] == [[_A1, _A2]], sid
    for sid in ("disabled-tool", "ghost-tool"):
        assert store.data[sid] == initial[sid], sid
    (push,) = store.policy_pushes
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1, _A2]
    assert [_source_roles(spm) for spm in push.services[:2]] == [{_A1: ["r-src-op"], _A2: ["r-src-op"]}] * 2


def test_a_lift_whose_other_holders_are_all_quarantined_gives_the_role_to_the_focus_only():
    catalog, initial = _lift_fixture(a1_enabled=False)
    store = _lift_store([], catalog=catalog, initial=initial)

    (push,) = store.policy_pushes
    assert [spm.service_id for spm in push.services] == ["agent-b", _T1, _A2]
    assert [_source_roles(spm) for spm in push.services[:2]] == [{_A2: ["r-src-op"]}] * 2


@pytest.mark.parametrize("snapshot", [(_A1, _A2), (_A1,)], ids=["current-snapshot", "stale-snapshot"])
def test_a_lift_given_again_gives_the_same_deploy(snapshot):
    # A NATS redelivery before reenable_service: the second run finds SPM(team2) and deploys the same.
    # The first run wrote the stale callees, so the second run writes only SPM(focus).
    catalog, initial = _lift_fixture(snapshot=snapshot)
    store = FakeStore(initial)
    writes = []
    for _ in range(2):
        before = len(store.service_writes)
        with engine_env(catalog, store) as compute:
            compute([_rule(_shared(_A2), _source_read())], focus_service=_A2)
        writes.append(sorted(sid for sid, _ in store.service_writes[before:]))

    first, second = store.policy_pushes
    assert first == second
    assert writes[1] == [_A2]


def test_an_onboarding_of_an_enabled_service_does_not_redeploy_the_callees_of_its_roles():
    # Not a lift: the callees' CRs already name team2, so only what the run touched is deployed: the
    # tool that its (duplicate) rule routes to, and the focus. agent-b is not touched.
    catalog, initial = _lift_fixture(a2_enabled=True, a2_stored=True)
    store = _lift_store([_rule(_shared(_A2), _source_read())], catalog=catalog, initial=initial)

    (push,) = store.policy_pushes
    assert [spm.service_id for spm in push.services] == [_T1, _A2]


@pytest.mark.parametrize("enabled", [False, True], ids=["lift", "onboarding"])
def test_a_lift_of_a_service_that_holds_no_shared_role_deploys_what_an_onboarding_deploys(enabled):
    # The quarantine purged the edges of a role that only X holds, so the lift finds none to redeploy:
    # it deploys what its run changed, as an onboarding of an enabled X does.
    XR = _agent_role("r-x", "x.skill", owner="x-agent")
    TS = _source_read()
    catalog = [_agent("x-agent", roles=[XR], enabled=enabled), _tool(_T1, scopes=[TS])]
    store = run_engine([_rule(XR, TS)], catalog=catalog, store_initial={_T1: _stored_tool()}, focus_service="x-agent")

    (push,) = store.policy_pushes
    assert [spm.service_id for spm in push.services] == [_T1, "x-agent"]
    assert sorted(sid for sid, _ in store.service_writes) == [_T1, "x-agent"]


# ---- on_applied: the re-enable under the PCE lock --------------------------- #
# A render after the lift that read the client as disabled would take the focus  #
# out of the CRs of its roles again. So the caller gives the re-enable as        #
# ``on_applied``, and ``compute_and_apply`` calls it under the PCE lock, after   #
# the run succeeds: no other operation reads the catalog in between.             #
def test_on_applied_runs_under_the_pce_lock_after_the_deploy():
    from aiac.policy.computation import engine

    catalog, initial = _lift_fixture()  # team2 is still disabled in the catalog
    store = FakeStore(initial)
    seen = []

    def on_applied():
        seen.append((engine._pce_lock.locked(), store.apply_policy_count))

    with engine_env(catalog, store) as compute:
        compute([], focus_service=_A2, on_applied=on_applied)

    assert seen == [(True, 1)]


def test_a_render_after_a_lift_whose_on_applied_re_enabled_the_client_keeps_the_lifted_holder():
    catalog, initial = _lift_fixture()
    store = FakeStore(initial)

    def reenable():
        catalog[:] = [svc.model_copy(update={"enabled": True}) if svc.serviceId == _A2 else svc for svc in catalog]

    with engine_env(catalog, store) as compute:
        compute([], focus_service=_A2, on_applied=reenable)
    before = len(store.policy_pushes)
    run_rerender("r-src-op", catalog=catalog, store=store)

    (push,) = store.policy_pushes[before:]
    tool = next(spm for spm in push.services if spm.service_id == _T1)
    assert _source_roles(tool) == {_A1: ["r-src-op"], _A2: ["r-src-op"]}


def test_a_failed_run_does_not_call_on_applied():
    # The client then stays disabled (the failed-service marker), never enabled-with-no-policy.
    catalog, initial = _lift_fixture()
    store = FakeStore(initial)
    on_applied = MagicMock()
    with (
        engine_env(catalog, store) as compute,
        patch("aiac.policy.computation.engine.apply_policy", side_effect=RuntimeError("writer down")),
        pytest.raises(RuntimeError, match="writer down"),
    ):
        compute([], focus_service=_A2, on_applied=on_applied)

    on_applied.assert_not_called()


def test_a_failed_on_applied_propagates_and_releases_the_pce_lock():
    from aiac.policy.computation import engine

    catalog, initial = _lift_fixture()
    store = FakeStore(initial)
    with (
        engine_env(catalog, store) as compute,
        pytest.raises(RuntimeError, match="idp down"),
    ):
        compute([], focus_service=_A2, on_applied=MagicMock(side_effect=RuntimeError("idp down")))

    assert not engine._pce_lock.locked()
