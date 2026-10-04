"""Unit tests for the Policy Computation Engine (``aiac.policy.computation.engine``, SPM-based).

The engine routes each pre-flattened ``PolicyRule`` to the ``ServicePolicyModel`` (SPM) of the
service that *owns* the rule's scope (``scope.serviceId``), persists the changed SPMs, and then
deploys the target-side policy model (``TargetSidePolicyModel``) of the changed live services with
one ``apply_policy`` call (D23). Quarantine and decommission delete the CR of the service
(``delete_service_cr``, D20); ``resync`` replaces every AIAC CR (``replace_policy``, D28);
``policy_model_for`` reads one service's entry (D18); ``bootstrap`` writes the focus tool's first CR.

Tests assert external behaviour — what the engine writes to the Policy Store (SPMs) and pushes to
the PDP (policy models, CR deletes) — not internal merge logic. All downstream dependencies are
mocked at the engine's import boundary via a small in-memory ``FakeStore`` that behaves like the
real Policy Store library (fresh-empty SPM on 404, ``get_service_policies_by_role`` scanning both
inbound lists, ``list_service_policies`` returning every stored SPM):
  - ``Configuration.get_services``                          (IdP catalog: type + own roles/scopes)
  - ``engine.get_service_policy`` / ``get_service_policies_by_role`` / ``list_service_policies`` /
    ``apply_service_policy`` / ``delete_service_policy``    (Policy Store library)
  - ``engine.apply_policy`` / ``replace_policy`` / ``delete_service_cr``  (PDP Policy Writer library)

Agent-side derivation (P0b). In P0 the engine deploys only the target side, so no APM is pushed.
``_derive`` stays (P0b deploys the agent side again), and the tests marked "agent-side derivation"
keep its coverage: ``FakeStore.derived_apm`` runs the real ``engine._derive`` over the SPMs the run
stored, seeded from the catalog as a run seeds them. The expected values stay literals.
"""

import os
import threading
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import pytest

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import Role, RoleKind, Scope, Service, ServiceType
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel, TargetSidePolicyModel


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
        self.catalog = []  # the catalog of the latest ``engine_env`` — seeds ``derived_apm``
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
        """The most recent target-side entry (an SPM) for ``service_id`` across all pushes."""
        for push in reversed(self.policy_pushes):
            for spm in push.services:
                if spm.service_id == service_id:
                    return spm
        return None

    @property
    def pushed_service_ids(self):
        return {spm.service_id for push in self.policy_pushes for spm in push.services}

    def derived_apm(self, agent_id):
        """Agent-side derivation (P0b): the APM that the real ``engine._derive`` builds for
        ``agent_id`` from the SPMs in this store, seeded from the latest catalog as a run seeds
        them. Records no ``get_service_policies_by_role`` call."""
        from aiac.policy.computation import engine

        catalog = {svc.serviceId: svc for svc in self.catalog}
        with (
            patch.object(engine, "get_service_policy", side_effect=self.get_service_policy),
            patch.object(engine, "get_service_policies_by_role", side_effect=self._scan_by_role),
        ):
            spm = engine._spm_cache(catalog)[1]
            return engine._derive(agent_id, spm)


_BOUNDARY = (
    "get_service_policy",
    "get_service_policies_by_role",
    "list_service_policies",
    "apply_service_policy",
    "delete_service_policy",
    "apply_policy",
    "replace_policy",
    "delete_service_cr",
)


@contextmanager
def engine_env(catalog, store):
    """Patch the engine boundary; yield ``compute_and_apply``. Multiple calls share the store."""
    store.catalog = list(catalog)
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"KEYCLOAK_REALM": "test-realm"}))
        stack.enter_context(patch.object(Configuration, "get_services", return_value=list(catalog)))
        for name in _BOUNDARY:
            stack.enter_context(patch(f"aiac.policy.computation.engine.{name}", side_effect=getattr(store, name)))
        from aiac.policy.computation.engine import compute_and_apply

        yield compute_and_apply


def run_engine(rules, *, catalog=None, store_initial=None, override=False, focus_service=None) -> FakeStore:
    store = FakeStore(store_initial)
    with engine_env(catalog or [], store) as compute_and_apply:
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


def _norm(apm):
    """Order-independent view of an APM for equality assertions — every split bucket."""
    return {
        "agent_roles": sorted(r.id for r in apm.agent_roles),
        "agent_scopes": sorted(s.id for s in apm.agent_scopes),
        "inbound_subject_allow": _pairs(apm.inbound_subject_allow_rules),
        "inbound_subject_deny": _pairs(apm.inbound_subject_deny_rules),
        "inbound_source_allow": _pairs(apm.inbound_source_allow_rules),
        "inbound_source_deny": _pairs(apm.inbound_source_deny_rules),
        "outbound_target_allow": _pairs(apm.outbound_target_allow_rules),
        "outbound_target_deny": _pairs(apm.outbound_target_deny_rules),
        "outbound_subject_allow": _pairs(apm.outbound_subject_allow_rules),
        "outbound_subject_deny": _pairs(apm.outbound_subject_deny_rules),
        "source_roles": {k: sorted(r.id for r in v) for k, v in apm.source_roles.items()},
        "subject_roles": {k: sorted(r.id for r in v) for k, v in apm.subject_roles.items()},
        "target_allow_scopes": {k: sorted(s.id for s in v) for k, v in apm.target_allow_scopes.items()},
        "target_deny_scopes": {k: sorted(s.id for s in v) for k, v in apm.target_deny_scopes.items()},
    }


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
# on SPM(A); the stored SPM(A) is pushed as A's target-side entry, once.        #
# --------------------------------------------------------------------------- #
def test_user_role_agent_scope_lands_inbound_and_pushes_once():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS)], catalog=catalog)

    # persisted on SPM(github-agent) — an Allow (user role, agent scope) edge
    assert store.service_writes[0][0] == "github-agent"
    assert _pairs(store.data["github-agent"].inbound_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert store.data["github-agent"].inbound_deny_rules == []
    # deployed as the agent's target-side entry: the stored SPM itself
    assert store.apply_policy_count == 1
    assert isinstance(store.last_push, TargetSidePolicyModel)
    assert store.last_push.services == [store.data["github-agent"]]


def test_derive_user_role_agent_scope_lands_in_inbound_subject_gate():
    # Agent-side derivation (P0b): a User role lands in the inbound SUBJECT allow bucket.
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    assert _pairs(apm.inbound_subject_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert apm.subject_roles == {"dev-user": [UR]}


# --------------------------------------------------------------------------- #
# Cycle 2 — an (agent role, tool scope) rule is stored on SPM(T); A's derived   #
# APM gains outbound_rules + a target_scopes entry for the tool.               #
# --------------------------------------------------------------------------- #
def test_agent_role_tool_scope_derives_outbound_and_target_scopes():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(AR, TS)], catalog=catalog)

    assert _pairs(store.data["github-tool"].inbound_allow_rules) == [("r-agent-src", "s-tool-read")]
    apm = store.derived_apm("github-agent")
    assert _pairs(apm.outbound_target_allow_rules) == [("r-agent-src", "s-tool-read")]
    assert {k: [s.id for s in v] for k, v in apm.target_allow_scopes.items()} == {"github-tool": ["s-tool-read"]}


# --------------------------------------------------------------------------- #
# Cycle 3 — a (user role, tool scope) rule, once an agent targets that tool,    #
# becomes the agent's outbound subject gate.                                    #
# --------------------------------------------------------------------------- #
def test_user_role_tool_scope_becomes_outbound_subject_gate():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(AR, TS), _rule(UR, TS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    assert _pairs(apm.outbound_subject_allow_rules) == [("r-user-dev", "s-tool-read")]
    assert apm.subject_roles == {"dev-user": [UR]}


# --------------------------------------------------------------------------- #
# Cycle 4 — HEADLINE: both onboarding orders converge — the same stored SPM(T)  #
# and the same target-side entry of T; under agent-side derivation (P0b) the    #
# same APM(A).                                                                   #
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


def test_both_orders_yield_identical_target_side_entry_for_the_tool():
    store_at, store_ta = _both_orders()

    assert store_at.data["github-tool"] == store_ta.data["github-tool"]
    assert store_at.pushed_service("github-tool") == store_ta.pushed_service("github-tool")
    assert _pairs(store_at.pushed_service("github-tool").inbound_allow_rules) == [
        ("r-agent-src", "s-tool-read"),
        ("r-user-dev", "s-tool-read"),
    ]


def test_both_orders_yield_identical_agent_policy():
    store_at, store_ta = _both_orders()

    apm_at = store_at.derived_apm("github-agent")
    apm_ta = store_ta.derived_apm("github-agent")
    assert _norm(apm_at) == _norm(apm_ta)

    # and it is the expected policy: inbound {UR->AS}, outbound {AR->TS} + subject gate {UR->TS}
    assert _norm(apm_at)["inbound_subject_allow"] == [("r-user-dev", "s-agent-inbound")]
    assert _norm(apm_at)["outbound_target_allow"] == [("r-agent-src", "s-tool-read")]
    assert _norm(apm_at)["outbound_subject_allow"] == [("r-user-dev", "s-tool-read")]


# --------------------------------------------------------------------------- #
# Cycle 5 — latent sibling bug: after A+T exist, a late (UR2 -> TS) user-role    #
# rule routes to SPM(T); only T's entry is redeployed, with UR2. Under agent-    #
# side derivation (P0b), A's subject gate includes UR2.                          #
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


def test_late_user_role_on_tool_rederives_affected_agent_subject_gate():
    store = _late_user_role_store()

    apm = store.derived_apm("github-agent")
    subject_pairs = _pairs(apm.outbound_subject_allow_rules)
    assert ("r-user-ops", "s-tool-read") in subject_pairs
    assert "ops-user" in apm.subject_roles


# --------------------------------------------------------------------------- #
# Cycle 6 — agent -> agent (AR -> BS): stored on SPM(B); A's APM has it outbound  #
# + target_scopes[B]; B's APM has source_roles[A] += AR.                        #
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


def test_agent_to_agent_edge_projects_into_both_policies():
    store = _agent_to_agent()

    apm_a = store.derived_apm("agent-a")
    assert _pairs(apm_a.outbound_target_allow_rules) == [("r-a-caller", "s-b-inbound")]
    assert {k: [s.id for s in v] for k, v in apm_a.target_allow_scopes.items()} == {"agent-b": ["s-b-inbound"]}

    apm_b = store.derived_apm("agent-b")
    assert {k: [r.id for r in v] for k, v in apm_b.source_roles.items()} == {"agent-a": ["r-a-caller"]}


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
# SPM is its target-side entry. Under agent-side derivation (P0b) the agent's    #
# APM still has the agent -> tool target_allow_scopes edge.                      #
# --------------------------------------------------------------------------- #
def test_tool_gets_its_stored_spm_as_a_target_side_entry():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(AR, TS)], catalog=catalog)

    assert _pairs(store.data["github-tool"].inbound_allow_rules) == [("r-agent-src", "s-tool-read")]
    assert store.last_push.services == [store.data["github-tool"]]
    assert store.last_push.services[0].service_type == ServiceType.TOOL


def test_derive_agent_to_tool_edge_on_the_agent_apm():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(AR, TS)], catalog=catalog)

    assert "github-tool" in store.derived_apm("github-agent").target_allow_scopes


# --------------------------------------------------------------------------- #
# Cycle 12 — P2 identity from owned_*: the derived APM embeds the agent's own     #
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

    apm = store.derived_apm("github-agent")
    assert [r.id for r in apm.agent_roles] == ["r-helper"]  # built-in role dropped
    assert [s.id for s in apm.agent_scopes] == ["s-src"]  # profile scope dropped


def test_p2_identity_empty_when_no_owned_entities():
    agent = _agent("github-agent")  # no catalog roles/scopes
    UR = _user_role("r-user", users=["u"])
    store = run_engine([_rule(UR, _scope("s-x", service_id="github-agent"))], catalog=[agent])

    apm = store.derived_apm("github-agent")
    assert apm.agent_roles == [] and apm.agent_scopes == []


# --------------------------------------------------------------------------- #
# Cycle 13 — directional relevance: a user role shared between an agent scope     #
# and a tool scope does NOT create a false outbound edge from A to the tool.      #
# --------------------------------------------------------------------------- #
def test_shared_user_role_creates_no_false_outbound_edge():
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", service_id="github-tool")
    # A owns NO agent role that maps to TS — only the shared user role touches both scopes.
    catalog = [_agent("github-agent", scopes=[AS]), _tool("github-tool", scopes=[TS])]
    store = run_engine([_rule(UR, AS), _rule(UR, TS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    assert apm.outbound_target_allow_rules == []
    assert apm.outbound_target_deny_rules == []
    assert apm.target_allow_scopes == {}
    assert apm.target_deny_scopes == {}
    assert apm.outbound_subject_allow_rules == []  # A does not target T, so no gate
    assert apm.outbound_subject_deny_rules == []


# --------------------------------------------------------------------------- #
# Cycle 13b — UC-1-shaped multi-role capability match: an agent owning TWO         #
# operator roles reaching four tool scopes, with user edges on a subset, derives   #
# BOTH outbound gates — the full agent->tool outbound_rules + target_scopes, and    #
# the user->tool outbound_subject gate. This is what populates the per-scope AND.   #
# --------------------------------------------------------------------------- #
def test_multi_role_capability_match_populates_both_outbound_gates():
    src_op = _agent_role("r-src-op", "source_operations", owner="github-agent")
    issue_op = _agent_role("r-issue-op", "issue_operations", owner="github-agent")
    developer = _user_role("r-developer", "developer", users=["dev-user"])
    tester = _user_role("r-tester", "tester", users=["test-user"])
    sr = _scope("s-source-read", service_id="github-tool")
    sw = _scope("s-source-write", service_id="github-tool")
    ir = _scope("s-issues-read", service_id="github-tool")
    iw = _scope("s-issues-write", service_id="github-tool")
    catalog = [
        _agent("github-agent", roles=[src_op, issue_op], scopes=[_scope("s-agent-inbound", service_id="github-agent")]),
        _tool("github-tool", scopes=[sr, sw, ir, iw]),
    ]
    rules = [
        # capability gate: each operator role -> its domain's tool scopes (capability-match)
        _rule(src_op, sr),
        _rule(src_op, sw),
        _rule(issue_op, ir),
        _rule(issue_op, iw),
        # subject gate: user roles -> a subset of the tool scopes
        _rule(developer, sr),
        _rule(developer, sw),
        _rule(developer, ir),
        _rule(tester, ir),
        _rule(tester, iw),
    ]
    store = run_engine(rules, catalog=catalog)

    apm = store.derived_apm("github-agent")
    # capability gate: all four agent->tool edges + target_allow_scopes covering all four scopes
    assert _pairs(apm.outbound_target_allow_rules) == sorted(
        [
            ("r-src-op", "s-source-read"),
            ("r-src-op", "s-source-write"),
            ("r-issue-op", "s-issues-read"),
            ("r-issue-op", "s-issues-write"),
        ]
    )
    assert {k: sorted(s.id for s in v) for k, v in apm.target_allow_scopes.items()} == {
        "github-tool": ["s-issues-read", "s-issues-write", "s-source-read", "s-source-write"],
    }
    # subject gate: the user->tool grant set (developer: source rw + issues read; tester: issues rw)
    assert _pairs(apm.outbound_subject_allow_rules) == sorted(
        [
            ("r-developer", "s-source-read"),
            ("r-developer", "s-source-write"),
            ("r-developer", "s-issues-read"),
            ("r-tester", "s-issues-read"),
            ("r-tester", "s-issues-write"),
        ]
    )


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
    assert store.policy_pushes == [TargetSidePolicyModel(services=[expected])]


def test_zero_rule_reonboarding_stores_and_redeploys_the_focus_spm():
    AR, UR, AS, TS, catalog = _repro()
    stored = _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS)])
    store = run_engine([], catalog=catalog, store_initial={"github-tool": stored}, focus_service="github-tool")

    assert store.service_writes == [("github-tool", stored)]  # its rules stay
    assert store.policy_pushes == [TargetSidePolicyModel(services=[stored])]


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
# Reconcile — drift GC (Handoff 10). Keycloak UUIDs churn on delete/recreate,   #
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
    # batch carries the current generation, so the old-generation edge is dropped; the derived APM's
    # subject gate then names only the current role.
    dev_old = _user_role("r-dev-v1", "developer", users=["dev-user"])
    dev_new = _user_role("r-dev-v2", "developer", users=["dev-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    catalog = [_agent("github-agent", scopes=[AS])]
    initial = {
        "github-agent": _spm("github-agent", owned_scopes=[AS], inbound=[_rule(dev_old, AS), _rule(dev_new, AS)])
    }
    store = run_engine([_rule(dev_new, AS)], catalog=catalog, store_initial=initial)

    assert _pairs(_inbound(store.data["github-agent"])) == [("r-dev-v2", "s-agent-inbound")]
    apm = store.derived_apm("github-agent")
    assert apm.subject_roles == {"dev-user": [dev_new]}


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
# get_services()); decommission() is the authoritative teardown: delete SPM(X),  #
# purge X's outbound footprint from other SPMs, delete the CR of X (agent or     #
# tool, D20), and redeploy the live services whose SPM the purge changed.        #
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


def test_derive_after_decommission_of_a_tool_strands_the_agent_outbound():
    # Agent-side derivation (P0b): A's outbound to the tool is stranded (the edge lived on SPM(T));
    # its inbound UR→AS survives.
    store = FakeStore()
    _onboard_repro(store)
    assert _pairs(store.derived_apm("github-agent").outbound_target_allow_rules) == [("r-agent-src", "s-tool-read")]

    run_decommission("github-tool", catalog=[_agent("github-agent", scopes=[])], store=store)

    apm = store.derived_apm("github-agent")
    assert apm.outbound_target_allow_rules == []
    assert apm.target_allow_scopes == {}
    assert apm.outbound_subject_allow_rules == []
    assert _pairs(apm.inbound_subject_allow_rules) == [("r-user-dev", "s-agent-inbound")]


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
    assert store.last_push == TargetSidePolicyModel(services=[store.data["github-tool"]])


def test_decommission_writes_the_store_then_deletes_the_cr_then_redeploys():
    store = FakeStore()
    _onboard_repro(store)
    store.calls.clear()

    run_decommission("github-agent", catalog=[_tool("github-tool", scopes=[])], store=store)

    assert [op for op, _ in store.calls] == ["delete", "write", "delete_service_cr", "apply_policy"]


def test_decommission_of_a_never_onboarded_service_is_a_no_op():
    store = run_decommission("never-seen", catalog=[], store=FakeStore())

    assert store.calls == []  # no store delete, no CR delete, no push


# =========================================================================== #
# Effect (ALLOW / DENY) routing and derivation (#118). Every inbound edge      #
# carries a ``RuleEffect``; the engine files each into the owning SPM's         #
# effect-matching list, and agent-side derivation (P0b) classifies each edge   #
# by role.kind AND effect into the split APM buckets (deny-overrides at request #
# time).                                                                        #
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


def test_decommission_tool_deletes_spm_holding_both_allow_and_deny_inbound():
    # SPM(T) holds an Allow user edge, a Deny user edge, and an agent capability edge on TS.
    # Offboarding T deletes SPM(T) (both lists at once) and its CR; the agent that targeted it
    # derives (P0b) with its outbound stranded.
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    UR = _user_role("r-user-dev", "developer", users=["dev-user"])
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [_agent("github-agent", roles=[AR], scopes=[AS]), _tool("github-tool", scopes=[TS])]
    store = FakeStore()
    with engine_env(catalog, store) as compute:
        compute([_rule(UR, AS), _rule(AR, TS), _rule(UR, TS), _deny(barred, TS)])

    # sanity: both lists on SPM(T) are populated before offboard.
    assert _pairs(store.data["github-tool"].inbound_allow_rules) == sorted(
        [("r-agent-src", "s-tool-read"), ("r-user-dev", "s-tool-read")]
    )
    assert _pairs(store.data["github-tool"].inbound_deny_rules) == [("r-user-ops", "s-tool-read")]

    run_decommission("github-tool", catalog=[_agent("github-agent", roles=[AR], scopes=[AS])], store=store)

    assert "github-tool" in store.service_deletes
    assert "github-tool" not in store.data  # SPM(T) gone — both lists torn down together
    assert store.cr_deletes == ["github-tool"]
    apm = store.derived_apm("github-agent")  # agent-side derivation (P0b): outbound stranded
    assert apm.outbound_target_allow_rules == []
    assert apm.target_allow_scopes == {}
    assert apm.outbound_subject_allow_rules == []


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


def test_derive_classifies_subject_deny_inbound_and_registers_identity():
    # A User-kind DENY edge on SPM(A) derives into inbound_subject_deny_rules; the barred user is
    # still registered into the EFFECT-AGNOSTIC subject_roles map alongside the allowed one.
    AR, UR, AS, TS, catalog = _repro()
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    store = run_engine([_rule(UR, AS), _deny(barred, AS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    assert _pairs(apm.inbound_subject_allow_rules) == [("r-user-dev", "s-agent-inbound")]
    assert _pairs(apm.inbound_subject_deny_rules) == [("r-user-ops", "s-agent-inbound")]
    assert apm.subject_roles == {"dev-user": [UR], "ops-user": [barred]}


def test_derive_registers_deny_only_subject_into_effect_agnostic_map():
    # Correctness invariant: a subject appearing ONLY in a DENY edge (no allow anywhere) must still
    # register in subject_roles, or the generated deny lookup cannot resolve it and the prohibition
    # silently never fires.
    AR, UR, AS, TS, catalog = _repro()
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    store = run_engine([_deny(barred, AS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    assert apm.inbound_subject_allow_rules == []
    assert _pairs(apm.inbound_subject_deny_rules) == [("r-user-ops", "s-agent-inbound")]
    assert apm.subject_roles == {"ops-user": [barred]}  # deny-only, still registered


def test_derive_classifies_source_deny_inbound_and_registers_source_identity():
    # An Agent-kind DENY edge on SPM(B) derives into inbound_source_deny_rules and registers the
    # calling agent into the effect-agnostic source_roles; A's outbound sees the deny target.
    AR = _agent_role("r-a-caller", "a-caller", owner="agent-a")
    BS = _scope("s-b-inbound", "b-inbound", service_id="agent-b")
    catalog = [
        _agent("agent-a", roles=[AR], scopes=[_scope("s-a-inbound", service_id="agent-a")]),
        _agent("agent-b", scopes=[BS]),
    ]
    store = run_engine([_deny(AR, BS)], catalog=catalog)

    apm_b = store.derived_apm("agent-b")
    assert _pairs(apm_b.inbound_source_deny_rules) == [("r-a-caller", "s-b-inbound")]
    assert apm_b.inbound_source_allow_rules == []
    assert {k: [r.id for r in v] for k, v in apm_b.source_roles.items()} == {"agent-a": ["r-a-caller"]}

    apm_a = store.derived_apm("agent-a")
    assert _pairs(apm_a.outbound_target_deny_rules) == [("r-a-caller", "s-b-inbound")]
    assert {k: [s.id for s in v] for k, v in apm_a.target_deny_scopes.items()} == {"agent-b": ["s-b-inbound"]}
    assert apm_a.outbound_target_allow_rules == []
    assert apm_a.target_allow_scopes == {}


def test_derive_agent_deny_target_scope_and_outbound_subject_deny_gate():
    # An agent-role → target-scope DENY edge derives into outbound_target_deny_rules +
    # target_deny_scopes. Per the spec the subject gate is gathered for every target scope (allow OR
    # deny), split by the USER edge's own effect: an allowed user lands in the allow gate, a barred
    # user in the deny gate, and both register into the effect-agnostic subject_roles.
    AR = _agent_role("r-agent-src", "agent-source", owner="github-agent")
    allowed = _user_role("r-user-dev", "developer", users=["dev-user"])
    barred = _user_role("r-user-ops", "ops", users=["ops-user"])
    AS = _scope("s-agent-inbound", "agent-inbound", service_id="github-agent")
    TS = _scope("s-tool-read", "tool-read", service_id="github-tool")
    catalog = [_agent("github-agent", roles=[AR], scopes=[AS]), _tool("github-tool", scopes=[TS])]
    store = run_engine([_deny(AR, TS), _rule(allowed, TS), _deny(barred, TS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    # agent capability deny -> target_deny_scopes + outbound_target_deny_rules
    assert _pairs(apm.outbound_target_deny_rules) == [("r-agent-src", "s-tool-read")]
    assert {k: [s.id for s in v] for k, v in apm.target_deny_scopes.items()} == {"github-tool": ["s-tool-read"]}
    assert apm.outbound_target_allow_rules == []
    assert apm.target_allow_scopes == {}
    # outbound subject gate split by the USER edge's effect
    assert _pairs(apm.outbound_subject_allow_rules) == [("r-user-dev", "s-tool-read")]
    assert _pairs(apm.outbound_subject_deny_rules) == [("r-user-ops", "s-tool-read")]
    assert apm.subject_roles == {"dev-user": [allowed], "ops-user": [barred]}


# --------------------------------------------------------------------------- #
# always DENY — the PCE carries no default effect.                            #
# --------------------------------------------------------------------------- #
def test_compute_and_apply_takes_no_default_effect():
    import inspect

    from aiac.policy.computation import engine

    for fn in (engine.compute_and_apply, engine._run, engine._derive, engine._fresh_apm):
        assert "default_effect" not in inspect.signature(fn).parameters, fn.__name__


def test_derived_apm_carries_no_default_effect():
    AR, UR, AS, TS, catalog = _repro()
    store = run_engine([_rule(UR, AS)], catalog=catalog)

    apm = store.derived_apm("github-agent")
    assert "default_effect" not in apm.model_dump()


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
    assert _pairs(store.derived_apm("github-agent").outbound_target_allow_rules) == [("r-agent-src", "s-tool-read")]


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
# catalog (disabled). Deletes SPM(X), removes X's roles from the other SPMs,    #
# deletes the CR of X — agent or tool (D20: the combiner denies a pod that has  #
# no CR) — and redeploys the live services whose SPM lost X's roles, in one     #
# call.                                                                          #
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


def test_quarantine_writes_the_store_then_deletes_the_cr_then_redeploys():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    assert [op for op, _ in store.calls] == ["delete", "write", "write", "delete_service_cr", "apply_policy"]


def test_derive_after_quarantine_drops_the_quarantined_agent_from_its_callers():
    catalog, initial = _quarantine_fixture()
    store = run_quarantine("github-agent", catalog=catalog, store=FakeStore(initial))

    other = store.derived_apm("other-agent")
    assert "github-agent" not in other.target_allow_scopes  # targeted X: outbound to X dropped
    assert "github-agent" not in other.source_roles  # X's role lost on SPM(other-agent)
    assert _pairs(other.inbound_subject_allow_rules) == [("r-user-dev", "s-b-in")]


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
    # pass-through). Agent-side derivation (P0b) drops the tool from the caller's outbound.
    assert store.apply_policy_count == 0
    assert store.derived_apm("github-agent").target_allow_scopes == {}


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
# disabled one: its rules are dropped, and _run never derives (writes a CR for) #
# an agent that is not in the catalog. The store's 404 placeholder SPM says     #
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
# quarantine and decommission derive only live agents, and keep the grants of   #
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
    assert ("r-shared", "s-tool-read") in _pairs(store.derived_apm("other-agent").outbound_target_allow_rules)


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


def test_resync_replaces_every_cr_with_the_live_stored_spms():
    catalog, initial = _resync_fixture()
    store = run_resync(catalog=catalog, store=FakeStore(initial))

    # one PUT; the disabled and the absent services are not in it (the PUT deletes their CRs)
    assert store.policy_replaces == [
        TargetSidePolicyModel(services=[initial["github-agent"], initial["github-tool"]]),
    ]


def test_resync_quarantines_each_disabled_service_that_has_an_spm():
    catalog, initial = _resync_fixture()
    store = run_resync(catalog=catalog, store=FakeStore(initial))

    assert "failed-agent" not in store.data
    assert store.cr_deletes == ["failed-agent"]
    # its role leaves the tool's SPM, and the tool's CR is redeployed without it
    assert _pairs(_inbound(store.data["github-tool"])) == [("r-agent-src", "s-tool-read")]
    assert store.policy_pushes == [TargetSidePolicyModel(services=[store.data["github-tool"]])]
    # the PUT comes first, then the quarantine
    assert [op for op, _ in store.calls] == [
        "replace_policy",
        "delete",
        "write",
        "delete_service_cr",
        "apply_policy",
    ]


def test_resync_keeps_the_spm_of_a_service_absent_from_the_catalog():
    # Removing a deleted service's SPM is decommission's job; the PUT already removed its CR.
    catalog, initial = _resync_fixture()
    store = run_resync(catalog=catalog, store=FakeStore(initial))

    assert store.data["ghost-agent"] == initial["ghost-agent"]
    assert "ghost-agent" not in store.cr_deletes


def test_resync_with_an_empty_store_replaces_with_an_empty_model():
    store = run_resync(catalog=[_tool("github-tool")], store=FakeStore())

    assert store.policy_replaces == [TargetSidePolicyModel(services=[])]  # the PUT deletes every AIAC CR
    assert [op for op, _ in store.calls] == ["replace_policy"]


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
    assert store.policy_replaces == [TargetSidePolicyModel(services=[zero_rule])]


# --------------------------------------------------------------------------- #
# policy_model_for (D18) — the read model: the target-side policy model with    #
# only the stored SPM of the service, or None if the store has no SPM for it.   #
# Read-only; takes no lock.                                                     #
# --------------------------------------------------------------------------- #
def _read_model(service_id, *, store, catalog=()):
    with engine_env(catalog, store):
        from aiac.policy.computation import policy_model_for

        return policy_model_for(service_id)


def test_policy_model_for_returns_the_stored_spm_as_the_only_entry():
    catalog, initial = _resync_fixture()
    store = FakeStore(initial)

    assert _read_model("github-tool", store=store, catalog=catalog) == TargetSidePolicyModel(
        services=[initial["github-tool"]]
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

    assert _read_model("bare-agent", store=store) == TargetSidePolicyModel(services=[bare])


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
    assert result == [TargetSidePolicyModel(services=[initial["github-agent"]])]


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

    assert store.policy_pushes == [TargetSidePolicyModel(services=[_spm("new-tool", type=ServiceType.TOOL)])]
    assert store.data == {}
    assert [op for op, _ in store.calls] == ["apply_policy"]


def test_bootstrap_seeds_the_zero_rule_spm_from_the_catalog():
    TS = _scope("s-tool-read", "tool-read", service_id="new-tool")
    catalog = [_service("new-tool", type=None, scopes=[TS])]
    store = run_bootstrap("new-tool", ServiceType.TOOL, catalog=catalog, store=FakeStore())

    expected = _spm("new-tool", type=ServiceType.TOOL, owned_scopes=[TS])
    assert store.policy_pushes == [TargetSidePolicyModel(services=[expected])]


def test_bootstrap_of_a_service_absent_from_the_catalog_pushes_a_bare_zero_rule_spm():
    store = run_bootstrap("new-tool", ServiceType.TOOL, catalog=[], store=FakeStore())

    assert store.policy_pushes == [TargetSidePolicyModel(services=[_spm("new-tool", type=ServiceType.TOOL)])]


def test_bootstrap_pushes_the_stored_spm_of_a_managed_tool():
    AR, UR, AS, TS, catalog = _repro()
    stored = _spm("github-tool", type=ServiceType.TOOL, owned_scopes=[TS], inbound=[_rule(AR, TS), _rule(UR, TS)])
    store = run_bootstrap("github-tool", ServiceType.TOOL, catalog=catalog, store=FakeStore({"github-tool": stored}))

    assert store.policy_pushes == [TargetSidePolicyModel(services=[stored])]
    assert store.service_writes == []


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
