"""Shared roles and shared scopes, from onboarding to the rendered CR (handoff 19, D32) — integration lane.

D32: one policy for the whole realm, so services in different namespaces (or an admin, in one
namespace) share a realm role or a client scope by name. Every holder of a shared role must get the
grants of that role, a shared scope is decided one time, and the holders of a role (agents and users)
in a CR are the current holders, not a copy from the onboarding that stored the rule. A shared role can
be mapped onto a scope that one of its holders owns (a self-mapping): D32 allows it (cases 5 and 6).

The real code runs between the seams: the focal-entity resolver, the Service Policy Builder with the
real PRB graphs, the PCE (``compute_and_apply``, ``rerender_role``, ``resync``) and the PDP Policy
Writer app with its Rego render. The fakes (``fakes.py``) stand in for the services behind the
library seams: Keycloak behind the IdP library ``Configuration``, the Policy Model Store, the
Kubernetes API of the writer, and the PRB LLM. The tests assert on the CR content that the writer
renders (the Rego maps ``source_roles`` / ``subject_roles`` and the scope maps).

Where the seams are patched:

- ``Configuration.for_default_realm`` / ``for_realm`` give the ``FakeRealm`` (every caller gets its
  ``Configuration`` through them);
- the store library and PDP library functions, and the PRB ``_structured_call``, are replaced in their
  module and at each ``from ... import`` site in an ``aiac`` module (found by identity — for example
  ``aiac.policy.computation.engine.apply_policy`` and
  ``aiac.agent.uc.onboarding.policy_builder.cross_service.get_service_policy``);
- the writer's Kubernetes client ``aiac.pdp.service.policy.opa.main._api`` is the ``FakeCluster``;
- the library HTTP transports fail the test if a call gets past a fake, so no call reaches a real
  service.

The Provision of a workload is the realm change that ``provision_service`` makes. Each role mapping
(by Provision or by an admin) gives one role-members event: the SPI publishes
``aiac.apply.role-members.{role-id}`` for a ``REALM_ROLE_MAPPING`` create or delete (R5, R9), and the
Controller calls ``rerender_role(role_id)`` for it (R7). ``Stack.deliver_role_events`` does that call
for each event that the realm recorded. ``Stack.drop_role_events`` loses the events, so that the
resync must repair the CRs. Case 7 needs the event of a Provision role mapping: the onboarding of a
new holder of the shared role routes no rule to a callee that has an edge of the role, so only the
event puts the new holder into that callee's CR.

Before D32 (on HEAD ``2069752``), ``rerender_role`` did not exist, so every test stopped with an
``AttributeError``. With a no-op ``rerender_role`` stub, 12 of the 17 tests failed: cases 1 and 2 by
an assertion (an agent that holds the shared role was missing from the tool CR's ``source_roles``),
and cases 3 and 4 too. See ``docs/testing/shared-roles-integration.md`` for the split.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from aiac.agent.policy_rules_builder import graph
from aiac.agent.uc.onboarding.policy_builder.builder import ServicePolicyBuilder
from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ServiceType
from aiac.pdp.policy.library import api as pdp_library
from aiac.pdp.service.policy.opa import main as writer
from aiac.policy import computation
from aiac.policy.model.models import EnforcementSide, PolicyRule
from aiac.policy.model_store.library import api as store_library
from test.integration.policy.computation.fakes import (
    FakeCluster,
    FakeLlm,
    FakePdp,
    FakeRealm,
    FakeStore,
    client_id_of,
)

pytestmark = pytest.mark.integration


@dataclass(frozen=True)
class Workload:
    namespace: str
    name: str
    type: ServiceType
    entries: dict[str, str]  # agent skill id or MCP tool name -> description

    @property
    def client_id(self) -> str:
        return client_id_of(self.namespace, self.name)


AGENT_ROLE = "github-agent.source_operations"  # the shared agent realm role (also the agents' own scope)
SOURCE_READ = "github-tool.source-read"  # a client scope that the two tools share
SOURCE_WRITE = "github-tool.source-write"  # another one
REVIEW_SKILL = "review-agent.code_review"
DEVELOPER = "developer"  # an aiac.managed user realm role

_AGENT_SKILLS = {"source_operations": "Operates on the source repositories of the user."}
_TOOLS = {"source-read": "Read a file of a source repository.", "source-write": "Write a file of a source repository."}

AGENT1 = Workload("team1", "github-agent", ServiceType.AGENT, _AGENT_SKILLS)
AGENT2 = Workload("team2", "github-agent", ServiceType.AGENT, _AGENT_SKILLS)
TOOL1 = Workload("team1", "github-tool", ServiceType.TOOL, _TOOLS)
TOOL2 = Workload("team2", "github-tool", ServiceType.TOOL, _TOOLS)
REVIEWER = Workload("team1", "review-agent", ServiceType.AGENT, {"code_review": "Reviews pull requests."})
TOOLS = (TOOL1, TOOL2)

# The onboarding orders of case 1: the outcome must not depend on them.
ORDERS = {
    "agents-first": (AGENT1, AGENT2, TOOL1, TOOL2),
    "tools-first": (TOOL1, TOOL2, AGENT1, AGENT2),
    "interleaved": (AGENT1, TOOL1, AGENT2, TOOL2),
}

POLICY = """\
Agents that operate on source repositories may read source files and must not write them.
Developers may read source files and may use the agents of the team.
"""

# The decisions of the fake LLM, consistent with POLICY: (focal kind, focal name) -> (grants, denies).
DECISIONS = {
    ("role", AGENT_ROLE): ({SOURCE_READ}, {SOURCE_WRITE}),
    ("scope", SOURCE_READ): ({AGENT_ROLE, DEVELOPER}, set()),
    ("scope", SOURCE_WRITE): (set(), {AGENT_ROLE}),
    ("scope", AGENT_ROLE): ({DEVELOPER}, set()),
    ("scope", REVIEW_SKILL): ({DEVELOPER}, set()),
}


# --------------------------------------------------------------------------- #
# harness                                                                     #
# --------------------------------------------------------------------------- #
class Stack:
    """The real AIAC code between the fakes, driven as the Controller drives it."""

    def __init__(self, realm: FakeRealm, store: FakeStore, cluster: FakeCluster, llm: FakeLlm) -> None:
        self.realm, self.store, self.cluster, self.llm = realm, store, cluster, llm

    def bring_up(self, workload: Workload) -> None:
        """Provision ``workload`` (and deliver the role-members events of its role mappings), then
        onboard it."""
        self.realm.provision(workload.namespace, workload.name, workload.type, workload.entries)
        self.deliver_role_events()
        self.onboard(workload.client_id)

    def onboard(self, client_id: str) -> None:
        """UC-1 after Provision: the Service Policy Builder (with the real resolver and PRB graphs)
        for the service's Keycloak UUID, then one ``compute_and_apply`` with the clientId as
        ``focus_service`` and ``override=False``, as the Controller does with ``onboard_service``."""
        service = self.realm.service(client_id)
        rules = ServicePolicyBuilder.build(service.id, service.type)
        computation.compute_and_apply(rules, override=False, focus_service=client_id)

    def deliver_role_events(self) -> None:
        """Deliver the role-members events that the realm recorded: the Controller calls
        ``rerender_role(role_id)`` for each (R7)."""
        events, self.realm.events = self.realm.events, []
        for role_id in events:
            computation.rerender_role(role_id)

    def drop_role_events(self) -> None:
        """Lose the recorded role-members events (a missed event; the resync must repair it)."""
        self.realm.events.clear()

    def inbound(self, client_id: str) -> str:
        return self._package(client_id, "inbound/request.rego")

    def outbound(self, client_id: str) -> str:
        return self._package(client_id, "outbound/request.rego")

    def _package(self, client_id: str, path: str) -> str:
        policies = self.cluster.policies(client_id)
        assert policies is not None, f"no CR for {client_id}"
        return policies[path]


def _no_network(library: str):
    """A library HTTP call that fails the test: the call got past the fakes."""

    def call(*_args, **_kwargs):
        raise AssertionError(f"the {library} made a real HTTP call: a seam is not faked")

    return call


class _NoRequests:
    """A stand-in for the ``requests`` module of a library: every call fails the test."""

    def __init__(self, library: str) -> None:
        self._library = library

    def __getattr__(self, name: str):
        return _no_network(f"{self._library} (requests.{name})")


def _patch_bound(monkeypatch: pytest.MonkeyPatch, module, name: str, fake) -> None:
    """Replace ``module.<name>`` and each ``from module import name`` binding of it in a loaded
    ``aiac`` module — the import sites that the real code uses, found by identity."""
    original = getattr(module, name)
    for module_name, loaded in list(sys.modules.items()):
        if module_name.startswith("aiac.") and getattr(loaded, name, None) is original:
            monkeypatch.setattr(loaded, name, fake)


@pytest.fixture
def stack(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Stack:
    """The fakes behind the seams, under target side (the default). Before AIAC runs, the realm has
    the user role ``developer`` held by alice and bob, and the user carol."""
    for name in ("AIAC_ENFORCEMENT_SIDE", "PLATFORM_SOURCE_CLIENTS", "POLICY_WRITER_DUMP_REGO"):
        monkeypatch.delenv(name, raising=False)
    policy_file = tmp_path / "policy.md"
    policy_file.write_text(POLICY, encoding="utf-8")
    monkeypatch.setenv("AIAC_POLICY_FILE", str(policy_file))

    realm, store, cluster, pdp, llm = FakeRealm(), FakeStore(), FakeCluster(), FakePdp(), FakeLlm(DECISIONS)
    monkeypatch.setattr(Configuration, "for_default_realm", staticmethod(lambda: realm))
    monkeypatch.setattr(Configuration, "for_realm", staticmethod(lambda _name: realm))
    monkeypatch.setattr(Configuration, "_request", _no_network("IdP library"))
    for name in (
        "get_service_policy",
        "list_service_policies",
        "get_service_policies_by_role",
        "apply_service_policy",
        "delete_service_policy",
    ):
        _patch_bound(monkeypatch, store_library, name, getattr(store, name))
    for name in ("apply_policy", "replace_policy", "delete_service_cr"):
        _patch_bound(monkeypatch, pdp_library, name, getattr(pdp, name))
    _patch_bound(monkeypatch, graph, "_structured_call", llm)
    monkeypatch.setattr(store_library, "requests", _NoRequests("Policy Store library"))
    monkeypatch.setattr(pdp_library, "requests", _NoRequests("PDP library"))
    monkeypatch.setattr(writer, "_api", cluster)

    realm.ensure_role(DEVELOPER, "Developers of the team.")
    for user in ("alice", "bob", "carol"):
        realm.add_user(user)
    for user in ("alice", "bob"):
        realm.grant(user, DEVELOPER)
    realm.events.clear()  # the realm before AIAC: no rule uses a role yet
    return Stack(realm, store, cluster, llm)


# --------------------------------------------------------------------------- #
# assertion helpers — read the CR content that the writer rendered            #
# --------------------------------------------------------------------------- #
def _rego_map(rego: str, var: str) -> dict[str, list[str]]:
    """The Rego map ``var`` of a rendered package (``var := { "key": ["a", ...], ... }``), as a dict."""
    lines = rego.splitlines()
    if f"{var} := {{}}" in lines:
        return {}
    assert f"{var} := {{" in lines, f"no map {var} in the package:\n{rego}"
    out: dict[str, list[str]] = {}
    for line in lines[lines.index(f"{var} := {{") + 1 :]:
        if line == "}":
            return out
        key, values = line.strip().removesuffix(",").split(": [", 1)
        out[json.loads(key)] = json.loads(f"[{values}")
    raise AssertionError(f"map {var} is not closed in the package:\n{rego}")


def _holders(stack: Stack, workload: Workload, role: str = AGENT_ROLE) -> set[str]:
    """The callers (clientIds) that the inbound CR's ``source_roles`` gives ``role``."""
    source_roles = _rego_map(stack.inbound(workload.client_id), "source_roles")
    return {caller for caller, roles in source_roles.items() if role in roles}


def _users(stack: Stack, workload: Workload, role: str = DEVELOPER) -> set[str]:
    """The users that the CR's ``subject_roles`` gives ``role``."""
    subject_roles = _rego_map(stack.inbound(workload.client_id), "subject_roles")
    return {user for user, roles in subject_roles.items() if role in roles}


def _edges(rules: list[PolicyRule]) -> set[tuple[str, str, str]]:
    return {(rule.role.name, rule.scope.name, rule.scope.serviceId) for rule in rules}


def _assert_tool_gates(stack: Stack, tool: Workload) -> None:
    """The tool CR allows the shared role ``source-read`` and denies it ``source-write``."""
    rego = stack.inbound(tool.client_id)
    assert _rego_map(rego, "source_role_allow_scopes") == {AGENT_ROLE: ["source-read"]}
    assert _rego_map(rego, "source_role_deny_scopes") == {AGENT_ROLE: ["source-write"]}


# --------------------------------------------------------------------------- #
# case 1 — across namespaces                                                  #
# --------------------------------------------------------------------------- #
class TestAcrossNamespaces:
    """team1/github-agent and team2/github-agent share the realm role ``github-agent.source_operations``;
    team1/github-tool and team2/github-tool share the client scopes ``github-tool.source-read`` and
    ``github-tool.source-write``."""

    @pytest.mark.parametrize("order", list(ORDERS))
    def test_every_holder_of_the_shared_role_is_a_source_of_each_tool_cr(self, stack: Stack, order: str) -> None:
        for workload in ORDERS[order]:
            stack.bring_up(workload)

        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT1.client_id, AGENT2.client_id}, (
                f"{tool.client_id}: the holders of {AGENT_ROLE} in source_roles"
            )
            _assert_tool_gates(stack, tool)

    @pytest.mark.parametrize("order", list(ORDERS))
    def test_each_owner_spm_gets_the_rule_for_its_own_copy(self, stack: Stack, order: str) -> None:
        for workload in ORDERS[order]:
            stack.bring_up(workload)

        for tool in TOOLS:
            spm = stack.store.spm(tool.client_id)
            assert spm is not None
            assert _edges(spm.inbound_allow_rules) == {
                (AGENT_ROLE, SOURCE_READ, tool.client_id),
                (DEVELOPER, SOURCE_READ, tool.client_id),
            }
            assert _edges(spm.inbound_deny_rules) == {(AGENT_ROLE, SOURCE_WRITE, tool.client_id)}

    def test_the_prb_prompt_lists_a_shared_scope_once(self, stack: Stack) -> None:
        # Tools first: at each agent's onboarding both tools' copies of each scope are candidates of
        # the role-focal pass of the shared role. Count the candidate line (``scope name=<name>:``), not
        # the bare name: the auditor prompt also gives the proposed names.
        for workload in ORDERS["tools-first"]:
            stack.bring_up(workload)

        prompts = stack.llm.prompts_for("role", AGENT_ROLE)
        for scope in (SOURCE_READ, SOURCE_WRITE):
            listing = [prompt for prompt in prompts if f"scope name={scope}:" in prompt]
            assert listing, f"no role-focal prompt of {AGENT_ROLE} lists {scope}"
            assert [prompt.count(f"scope name={scope}:") for prompt in listing] == [1] * len(listing), (
                f"the role-focal prompts of {AGENT_ROLE} list {scope} more than once"
            )

    def test_the_prb_prompt_lists_a_shared_role_once(self, stack: Stack) -> None:
        # Agents first: at each tool's onboarding both agents' copies of the role are candidates of
        # the scope-focal passes.
        for workload in ORDERS["agents-first"]:
            stack.bring_up(workload)

        for scope in (SOURCE_READ, SOURCE_WRITE):
            prompts = stack.llm.prompts_for("scope", scope)
            assert prompts, f"no scope-focal prompt of {scope}"
            assert [prompt.count(f"role name={AGENT_ROLE}:") for prompt in prompts] == [1] * len(prompts)

    @pytest.mark.parametrize("order", list(ORDERS))
    def test_agent_side_every_holder_gets_the_outbound_gates(
        self, stack: Stack, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        for workload in ORDERS[order]:
            stack.bring_up(workload)

        for agent in (AGENT1, AGENT2):
            rego = stack.outbound(agent.client_id)
            assert _rego_map(rego, "target_allow_scopes") == {tool.client_id: ["source-read"] for tool in TOOLS}, (
                f"{agent.client_id}: the outbound allow"
            )
            assert _rego_map(rego, "target_deny_scopes") == {tool.client_id: ["source-write"] for tool in TOOLS}, (
                f"{agent.client_id}: the outbound deny"
            )


# --------------------------------------------------------------------------- #
# case 2 — in one namespace                                                   #
# --------------------------------------------------------------------------- #
class TestInOneNamespace:
    """team1/github-agent and team1/review-agent hold ``github-agent.source_operations``: Provision
    gives it to github-agent, and an admin assigns it to review-agent's service account in Keycloak."""

    @pytest.mark.parametrize("tool_first", [False, True], ids=["tool-last", "tool-first"])
    def test_both_holders_are_sources_of_the_tool_cr(self, stack: Stack, tool_first: bool) -> None:
        if tool_first:
            stack.bring_up(TOOL1)
        stack.bring_up(AGENT1)
        stack.bring_up(REVIEWER)
        stack.realm.grant(REVIEWER.client_id, AGENT_ROLE)  # the admin's role mapping
        stack.deliver_role_events()
        if not tool_first:
            stack.bring_up(TOOL1)

        assert _holders(stack, TOOL1) == {AGENT1.client_id, REVIEWER.client_id}, (
            f"{TOOL1.client_id}: the holders of {AGENT_ROLE} in source_roles"
        )
        _assert_tool_gates(stack, TOOL1)


# --------------------------------------------------------------------------- #
# case 3 — the members of a user role change (Bug 4)                          #
# --------------------------------------------------------------------------- #
class TestUserRoleMembers:
    """After the rules are stored, carol gets ``developer`` and bob loses it. The event path
    (``rerender_role``) and the resync (a missed event) render the current members, with no PRB run."""

    @pytest.mark.parametrize("repair", ["event", "resync"])
    def test_a_new_member_gets_access_and_a_removed_member_loses_it(self, stack: Stack, repair: str) -> None:
        stack.bring_up(TOOL1)
        stack.bring_up(AGENT1)
        for workload in (TOOL1, AGENT1):
            assert _users(stack, workload) == {"alice", "bob"}, f"{workload.client_id}: before the change"
        prompts_before, writes_before = len(stack.llm.prompts), len(stack.store.writes)

        stack.realm.grant("carol", DEVELOPER)
        stack.realm.revoke("bob", DEVELOPER)
        if repair == "event":
            stack.deliver_role_events()
        else:
            stack.drop_role_events()
            computation.resync()

        for workload in (TOOL1, AGENT1):
            assert _users(stack, workload) == {"alice", "carol"}, f"{workload.client_id}: the members of {DEVELOPER}"
        assert stack.llm.prompts[prompts_before:] == [], "a PRB call happened"
        if repair == "event":
            assert stack.store.writes[writes_before:] == [], "the event path wrote an SPM"


# --------------------------------------------------------------------------- #
# case 4 — a later holder and a removed holder of the shared agent role (Bug 1) #
# --------------------------------------------------------------------------- #
class TestLaterAndRemovedHolder:
    """After the rules are stored, an admin assigns the shared role to team1/review-agent and removes
    it from team1/github-agent. The event path and the resync render the current holders, with no PRB
    run."""

    @pytest.mark.parametrize("repair", ["event", "resync"])
    def test_a_later_holder_appears_and_a_removed_holder_goes(self, stack: Stack, repair: str) -> None:
        for workload in (*ORDERS["agents-first"], REVIEWER):
            stack.bring_up(workload)
        for tool in TOOLS:
            assert AGENT1.client_id in _holders(stack, tool), f"{tool.client_id}: before the change"
        prompts_before, writes_before = len(stack.llm.prompts), len(stack.store.writes)

        stack.realm.grant(REVIEWER.client_id, AGENT_ROLE)  # a later holder
        stack.realm.revoke(AGENT1.client_id, AGENT_ROLE)  # a removed holder
        if repair == "event":
            stack.deliver_role_events()
        else:
            stack.drop_role_events()
            computation.resync()

        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT2.client_id, REVIEWER.client_id}, (
                f"{tool.client_id}: the holders of {AGENT_ROLE} in source_roles"
            )
            _assert_tool_gates(stack, tool)
        assert stack.llm.prompts[prompts_before:] == [], "a PRB call happened"
        if repair == "event":
            assert stack.store.writes[writes_before:] == [], "the event path wrote an SPM"


# --------------------------------------------------------------------------- #
# case 5 — a shared role on a scope that one of its holders owns (self-mapping) #
# --------------------------------------------------------------------------- #
# The decisions of a policy that also lets the agents that operate on source repositories call one
# another (the fake LLM decides from this table, not from the policy text): both passes grant the
# shared role on the agents' shared scope, which has the same name.
PEER_DECISIONS = {
    **DECISIONS,
    ("role", AGENT_ROLE): ({SOURCE_READ, AGENT_ROLE}, {SOURCE_WRITE}),
    ("scope", AGENT_ROLE): ({DEVELOPER, AGENT_ROLE}, set()),
}
AGENT_ORDERS = {"team1-first": (AGENT1, AGENT2), "team2-first": (AGENT2, AGENT1)}


class TestSelfMapping:
    """team1/github-agent and team2/github-agent hold the shared role ``github-agent.source_operations``
    and each owns a copy of the shared scope of the same name. D32 allows a self-mapping. The candidates
    come from the other services by owner service, so at the second agent's onboarding the shared role
    is a candidate of the scope-focal pass of the focus's own copy (through the other holder), and the
    other agent's copy is a candidate of the role-focal pass of the shared role. No filter removes the
    pair, and the PCE renders the current holders, so a grant on it lets each holder call each copy,
    its own copy included."""

    @pytest.mark.parametrize("order", list(AGENT_ORDERS))
    def test_the_shared_pair_reaches_the_prb_prompt_of_both_passes(self, stack: Stack, order: str) -> None:
        first, second = AGENT_ORDERS[order]
        stack.llm.decisions = PEER_DECISIONS
        stack.bring_up(first)
        # One holder and one owner: no other service brings the role or a copy of the scope in. The
        # focal line of a pass has the other prefix, so these strings match only a candidate line.
        assert all(f"role name={AGENT_ROLE}:" not in p for p in stack.llm.prompts_for("scope", AGENT_ROLE))
        assert all(f"scope name={AGENT_ROLE}:" not in p for p in stack.llm.prompts_for("role", AGENT_ROLE))
        seen = {kind: len(stack.llm.prompts_for(kind, AGENT_ROLE)) for kind in ("scope", "role")}

        stack.bring_up(second)

        scope_pass = stack.llm.prompts_for("scope", AGENT_ROLE)[seen["scope"] :]
        role_pass = stack.llm.prompts_for("role", AGENT_ROLE)[seen["role"] :]
        assert scope_pass, f"no scope-focal prompt of {AGENT_ROLE} at the second onboarding"
        assert all(f"role name={AGENT_ROLE}:" in p for p in scope_pass), "the shared role is not a candidate"
        assert role_pass, f"no role-focal prompt of {AGENT_ROLE} at the second onboarding"
        assert all(f"scope name={AGENT_ROLE}:" in p for p in role_pass), "the other copy is not a candidate"

    @pytest.mark.parametrize("order", list(AGENT_ORDERS))
    def test_target_side_the_cr_of_each_copy_gives_every_holder_the_grant(self, stack: Stack, order: str) -> None:
        stack.llm.decisions = PEER_DECISIONS
        for workload in AGENT_ORDERS[order]:
            stack.bring_up(workload)

        holders = {AGENT1.client_id, AGENT2.client_id}
        for owner in (AGENT1, AGENT2):
            spm = stack.store.spm(owner.client_id)
            assert spm is not None
            assert _edges(spm.inbound_allow_rules) == {
                (AGENT_ROLE, AGENT_ROLE, owner.client_id),
                (DEVELOPER, AGENT_ROLE, owner.client_id),
            }
            assert _holders(stack, owner) == holders, f"{owner.client_id}: the owner is a holder too"
            rego = stack.inbound(owner.client_id)
            assert _rego_map(rego, "source_role_allow_scopes") == {AGENT_ROLE: [AGENT_ROLE]}
            assert _rego_map(rego, "source_role_deny_scopes") == {}

    @pytest.mark.parametrize("order", list(AGENT_ORDERS))
    def test_agent_side_each_holder_outbound_allows_every_copy(
        self, stack: Stack, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        stack.llm.decisions = PEER_DECISIONS
        for workload in AGENT_ORDERS[order]:
            stack.bring_up(workload)

        owners = {AGENT1.client_id: ["source_operations"], AGENT2.client_id: ["source_operations"]}
        for holder in (AGENT1, AGENT2):
            rego = stack.outbound(holder.client_id)
            assert _rego_map(rego, "target_allow_scopes") == owners, f"{holder.client_id}: its own copy too"
            assert _rego_map(rego, "target_deny_scopes") == {}
            # The inbound gates are the same on both sides (D18b).
            assert _holders(stack, holder) == set(owners), f"{holder.client_id}: the inbound source_roles"


# --------------------------------------------------------------------------- #
# case 6 — an admin-assigned shared role on a re-onboarding (self-mapping)     #
# --------------------------------------------------------------------------- #
# The decisions of the re-onboarding. They grant the shared role on review-agent's skill (a scope
# with a different name, which the holder by the admin's assignment owns) and on github-agent's skill
# (the scope with the same name as the role, which the holder by Provision owns).
ADMIN_DECISIONS = {
    **PEER_DECISIONS,
    ("scope", REVIEW_SKILL): ({DEVELOPER, AGENT_ROLE}, set()),
}


class TestAdminAssignedSelfMapping:
    """An admin assigns github-agent's role to team1/review-agent, then review-agent is onboarded
    again. The role now has two holders in one namespace, so each pass of the re-onboarding gets a
    self-mapping pair: the scope-focal pass of review-agent's own skill gets the shared role (through
    github-agent, its other holder), and the role-focal pass of the shared role gets github-agent's
    skill (a scope that the other holder owns). D32 allows both pairs. No filter removes them, and the
    PCE renders the current holders, so each holder can call both skills, its own skill included."""

    @staticmethod
    def _reonboard(stack: Stack) -> tuple[list[str], list[str]]:
        """Bring up github-agent and review-agent with ``DECISIONS``, assign the shared role to
        review-agent (and deliver its event), then onboard review-agent again with
        ``ADMIN_DECISIONS``. Returns the scope-focal prompts of review-agent's skill and the
        role-focal prompts of the shared role, of the re-onboarding only."""
        stack.bring_up(AGENT1)
        stack.bring_up(REVIEWER)
        # Before the assignment, review-agent does not hold the shared role: no role-focal pass of the
        # role gets github-agent's skill, and no rule grants the role on a skill.
        assert all(f"scope name={AGENT_ROLE}:" not in p for p in stack.llm.prompts_for("role", AGENT_ROLE))
        for owner in (AGENT1, REVIEWER):
            spm = stack.store.spm(owner.client_id)
            assert spm is not None
            assert all(rule.role.name != AGENT_ROLE for rule in spm.inbound_allow_rules), owner.client_id
        stack.realm.grant(REVIEWER.client_id, AGENT_ROLE)  # the admin's role mapping
        stack.deliver_role_events()
        scope_seen = len(stack.llm.prompts_for("scope", REVIEW_SKILL))
        role_seen = len(stack.llm.prompts_for("role", AGENT_ROLE))
        stack.llm.decisions = ADMIN_DECISIONS

        stack.onboard(REVIEWER.client_id)

        return (
            stack.llm.prompts_for("scope", REVIEW_SKILL)[scope_seen:],
            stack.llm.prompts_for("role", AGENT_ROLE)[role_seen:],
        )

    def test_both_self_pairs_reach_the_prb_prompt(self, stack: Stack) -> None:
        scope_pass, role_pass = self._reonboard(stack)

        assert scope_pass, f"no scope-focal prompt of {REVIEW_SKILL} at the re-onboarding"
        assert all(f"role name={AGENT_ROLE}:" in p for p in scope_pass), (
            f"the shared role is not a candidate of {REVIEW_SKILL} (a self-mapping of review-agent)"
        )
        assert role_pass, f"no role-focal prompt of {AGENT_ROLE} at the re-onboarding"
        assert all(f"scope name={AGENT_ROLE}:" in p for p in role_pass), (
            f"github-agent's {AGENT_ROLE} is not a candidate of the shared role (a self-mapping of github-agent)"
        )

    def test_target_side_both_spms_keep_the_grant_and_each_cr_gives_every_holder(self, stack: Stack) -> None:
        self._reonboard(stack)

        holders = {AGENT1.client_id, REVIEWER.client_id}
        for owner, skill in ((AGENT1, AGENT_ROLE), (REVIEWER, REVIEW_SKILL)):
            spm = stack.store.spm(owner.client_id)
            assert spm is not None
            assert _edges(spm.inbound_allow_rules) == {
                (AGENT_ROLE, skill, owner.client_id),
                (DEVELOPER, skill, owner.client_id),
            }, f"{owner.client_id}: the allow edges"
            assert _holders(stack, owner) == holders, f"{owner.client_id}: the owner is a holder too"
            rego = stack.inbound(owner.client_id)
            assert _rego_map(rego, "source_role_allow_scopes") == {AGENT_ROLE: [skill]}
            assert _rego_map(rego, "source_role_deny_scopes") == {}

    def test_agent_side_each_holder_outbound_allows_both_skills(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        self._reonboard(stack)

        targets = {AGENT1.client_id: ["source_operations"], REVIEWER.client_id: ["code_review"]}
        for holder in (AGENT1, REVIEWER):
            rego = stack.outbound(holder.client_id)
            assert _rego_map(rego, "target_allow_scopes") == targets, f"{holder.client_id}: its own skill too"
            assert _rego_map(rego, "target_deny_scopes") == {}
            # The inbound gates are the same on both sides (D18b).
            assert _holders(stack, holder) == set(targets), f"{holder.client_id}: the inbound source_roles"


# --------------------------------------------------------------------------- #
# case 7 — a new holder's Provision event re-renders a callee with no new rule  #
# --------------------------------------------------------------------------- #
# The decisions of a policy that also lets the agents that operate on source repositories call
# review-agent. The scope-focal pass of review-agent's skill grants the shared role; the role-focal
# pass of the shared role decides only the tool scopes (``DECISIONS``), not review-agent's skill.
REVIEWER_CALLED = {**DECISIONS, ("scope", REVIEW_SKILL): ({DEVELOPER, AGENT_ROLE}, set())}


class TestProvisionEventOfANewHolder:
    """team1/review-agent's SPM has an edge of the shared role (its skill allows it). Then
    team2/github-agent is provisioned and gets the shared role. Its onboarding routes no rule to
    review-agent (the role-focal pass does not grant the skill), so no ``compute_and_apply`` deploys
    review-agent again: only the role-members event of the Provision role mapping (R5, R7) puts the
    new holder into review-agent's CR. The event can come before or after the onboarding."""

    @pytest.mark.parametrize("event_first", [True, False], ids=["event-first", "onboarding-first"])
    def test_the_provision_event_adds_the_new_holder_to_the_callee_cr(self, stack: Stack, event_first: bool) -> None:
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (AGENT1, TOOL1, REVIEWER):
            stack.bring_up(workload)
        assert _holders(stack, REVIEWER) == {AGENT1.client_id}, "before the new holder"
        writes_before = len(stack.store.writes)

        if event_first:
            stack.bring_up(AGENT2)  # Provision, the events of its role mappings, then the onboarding
        else:
            stack.realm.provision(AGENT2.namespace, AGENT2.name, AGENT2.type, AGENT2.entries)
            events, stack.realm.events = stack.realm.events, []
            assert events, "the Provision role mapping gave no role-members event"
            stack.onboard(AGENT2.client_id)
            assert _holders(stack, REVIEWER) == {AGENT1.client_id}, "the onboarding deployed review-agent again"
            stack.realm.events = events
            stack.deliver_role_events()

        assert ("apply", REVIEWER.client_id) not in stack.store.writes[writes_before:], "a rule was routed to it"
        assert _holders(stack, REVIEWER) == {AGENT1.client_id, AGENT2.client_id}, (
            f"{REVIEWER.client_id}: the holders of {AGENT_ROLE} in source_roles"
        )
        rego = stack.inbound(REVIEWER.client_id)
        assert _rego_map(rego, "source_role_allow_scopes") == {AGENT_ROLE: [REVIEW_SKILL]}


# --------------------------------------------------------------------------- #
# case 8 — the copies of a shared scope get different user rules              #
# --------------------------------------------------------------------------- #
# Each owner's onboarding is its own scope-focal PRB pass on its own copy of a shared scope, so the
# copies can get different user rules. Here one tool's pass grants ``developer`` on its copy of
# ``github-tool.source-read`` (``DECISIONS``), and the other tool's pass gives ``developer`` no rule on
# its copy (``OTHER_COPY_DECISIONS``). The agent role is granted on both copies, so the agent may call
# both. Each copy must decide from the user rules of its own SPM, under both sides. (A deny on the other
# copy does not get this far: the PRB of the second onboarding finds the grant of the first copy and
# raises a policy conflict for the pair.)
OTHER_COPY_DECISIONS = {**DECISIONS, ("scope", SOURCE_READ): ({AGENT_ROLE}, set())}
_CALL_SOURCE_READ = {"method": "tools/call", "params": {"name": "source-read"}}


def _rego_nested_map(rego: str, var: str) -> dict[str, dict[str, list[str]]]:
    """The two-level Rego map ``var`` of a rendered package (``var := { "key": { "inner": ["a", ...],
    ... }, ... }``), as a dict."""
    lines = rego.splitlines()
    if f"{var} := {{}}" in lines:
        return {}
    assert f"{var} := {{" in lines, f"no map {var} in the package:\n{rego}"
    out: dict[str, dict[str, list[str]]] = {}
    inner: dict[str, list[str]] = {}
    for line in lines[lines.index(f"{var} := {{") + 1 :]:
        if line == "}":
            return out
        entry = line.strip()
        if entry == "},":
            continue
        if entry.endswith(": {"):
            inner = out.setdefault(json.loads(entry.removesuffix(": {")), {})
            continue
        key, values = entry.removesuffix(",").split(": [", 1)
        inner[json.loads(key)] = json.loads(f"[{values}")
    raise AssertionError(f"map {var} is not closed in the package:\n{rego}")


def _opa_allow(rego: str, tier: str, input_doc: dict) -> bool:
    """The ``allow`` of the rendered package of ``tier`` for ``input_doc``, from ``opa eval``. Skips the
    test cleanly when the ``opa`` binary is not on the PATH."""
    opa = shutil.which("opa")
    if opa is None:
        pytest.skip("opa binary not on PATH")
    query = f"data.authbridge.client.{tier}.request.allow"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego, encoding="utf-8")
        out = subprocess.run(
            [opa, "eval", "-f", "json", "-d", str(path), "--stdin-input", query],
            input=json.dumps(input_doc),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    return json.loads(out)["result"][0]["expressions"][0]["value"]


class TestDivergentCopiesOfASharedScope:
    """team1/github-tool and team2/github-tool share ``github-tool.source-read``. ``granted`` is the tool
    whose copy grants ``developer`` (alice and bob); the other tool's copy has no user rule. team1/
    github-agent may call both copies. A user rule decides only on the copy whose SPM has it: under
    agent side, a grant on one copy must not admit alice on the other copy (that is fail-open)."""

    @staticmethod
    def _bring_up(stack: Stack, granted: Workload) -> Workload:
        """Bring up the two tools (team1 first), each with the decisions of its own copy, then the
        agent. Returns the other tool."""
        for tool in TOOLS:
            stack.llm.decisions = DECISIONS if tool is granted else OTHER_COPY_DECISIONS
            stack.bring_up(tool)
        stack.llm.decisions = DECISIONS
        stack.bring_up(AGENT1)
        return TOOL2 if granted is TOOL1 else TOOL1

    @pytest.mark.parametrize("granted", TOOLS, ids=["team1-copy", "team2-copy"])
    def test_target_side_each_copy_cr_has_only_its_own_user_rules(self, stack: Stack, granted: Workload) -> None:
        other = self._bring_up(stack, granted)

        granted_spm, other_spm = stack.store.spm(granted.client_id), stack.store.spm(other.client_id)
        assert granted_spm is not None and other_spm is not None
        assert (DEVELOPER, SOURCE_READ, granted.client_id) in _edges(granted_spm.inbound_allow_rules)
        assert all(rule.role.name != DEVELOPER for rule in other_spm.inbound_allow_rules), other.client_id
        assert all(rule.role.name != DEVELOPER for rule in other_spm.inbound_deny_rules), other.client_id

        assert _rego_map(stack.inbound(granted.client_id), "subject_role_allow_scopes") == {DEVELOPER: ["source-read"]}
        assert _rego_map(stack.inbound(other.client_id), "subject_role_allow_scopes") == {}

    @pytest.mark.parametrize("granted", TOOLS, ids=["team1-copy", "team2-copy"])
    def test_agent_side_a_copy_with_no_grant_has_no_subject_entry(
        self, stack: Stack, granted: Workload, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        other = self._bring_up(stack, granted)

        rego = stack.outbound(AGENT1.client_id)
        assert _rego_map(rego, "target_allow_scopes") == {tool.client_id: ["source-read"] for tool in TOOLS}, (
            "the agent may call both copies"
        )
        assert _rego_nested_map(rego, "subject_role_allow_scopes") == {
            DEVELOPER: {granted.client_id: ["source-read"]}
        }, f"{other.client_id}: a copy with no grant has no subject entry"
        assert _rego_nested_map(rego, "subject_role_deny_scopes") == {}

    @pytest.mark.parametrize("side", [EnforcementSide.TARGET_SIDE, EnforcementSide.AGENT_SIDE], ids=lambda s: s.value)
    @pytest.mark.parametrize("granted", TOOLS, ids=["team1-copy", "team2-copy"])
    def test_alice_reaches_only_the_copy_that_grants_her(
        self, stack: Stack, granted: Workload, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The decision of the rendered CRs for alice (through team1/github-agent) on each copy: both
        sides allow her on the copy that grants her and deny her on the other copy."""
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        other = self._bring_up(stack, granted)

        for tool, expected in ((granted, True), (other, False)):
            if side is EnforcementSide.AGENT_SIDE:
                rego, tier = stack.outbound(AGENT1.client_id), "outbound"
                identity = {"subject": "alice", "service_id": tool.client_id}
            else:
                rego, tier = stack.inbound(tool.client_id), "inbound"
                identity = {"subject": "alice", "client_id": AGENT1.client_id}
            allowed = _opa_allow(rego, tier, {"identity": identity, "mcp": _CALL_SOURCE_READ})
            assert allowed is expected, f"{side.value}: alice -> {tool.client_id} source-read"

    def test_agent_side_copies_that_agree_each_get_their_own_rule(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The control case: both copies grant ``developer`` (case 1), so the APM keeps the grant of
        each copy (the PCE keeps one outbound subject rule for each copy), each copy gets its own
        subject entry, and alice reaches both copies through the agent."""
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        for workload in (TOOL1, TOOL2, AGENT1):
            stack.bring_up(workload)

        rego = stack.outbound(AGENT1.client_id)
        assert _rego_nested_map(rego, "subject_role_allow_scopes") == {
            DEVELOPER: {tool.client_id: ["source-read"] for tool in TOOLS}
        }
        for tool in TOOLS:
            identity = {"subject": "alice", "service_id": tool.client_id}
            allowed = _opa_allow(rego, "outbound", {"identity": identity, "mcp": _CALL_SOURCE_READ})
            assert allowed is True, f"alice -> {tool.client_id} source-read"


# --------------------------------------------------------------------------- #
# case 9 — a deny on the copies of a shared scope                             #
# --------------------------------------------------------------------------- #
# The PCE keeps one outbound subject rule for each copy (role, scope id, copy owner, effect), and the
# writer keys each rule only by the copy that it names, as under target side. So when the SPMs of both
# copies deny ``developer``, the APM has the deny of each copy, and the agent side denies alice on both
# copies (with the deny of one copy only, she would reach the other copy through her ``tester`` grant
# there: fail-open). When one copy denies ``developer`` and the other copy has no rule for it, the agent
# side denies alice on the first copy only, and allows her on the other copy, as the target side does.
TESTER = "tester"
DENY_COPY1 = {**DECISIONS, ("scope", SOURCE_READ): ({AGENT_ROLE}, {DEVELOPER})}
DENY_COPY2_GRANT_TESTER = {**DECISIONS, ("scope", SOURCE_READ): ({AGENT_ROLE, TESTER}, {DEVELOPER})}
NO_DENY_COPY2_GRANT_TESTER = {**DECISIONS, ("scope", SOURCE_READ): ({AGENT_ROLE, TESTER}, set())}
# The scenario -> the decisions of the copy of TOOL1 and of TOOL2.
DENY_SCENARIOS = {
    "deny-on-both-copies": (DENY_COPY1, DENY_COPY2_GRANT_TESTER),
    "deny-on-team1-copy-only": (DENY_COPY1, NO_DENY_COPY2_GRANT_TESTER),
}
# The onboarding order of the tools is the order in which the PCE reads their SPMs.
TOOL_ORDERS = {"team1-first": (TOOL1, TOOL2), "team2-first": (TOOL2, TOOL1)}
SIDES = [EnforcementSide.TARGET_SIDE, EnforcementSide.AGENT_SIDE]


class TestDenyOnCopiesOfASharedScope:
    """team1/github-tool and team2/github-tool share ``github-tool.source-read``, and team1/github-agent
    may call both copies. The copy of team1 denies ``developer``. The copy of team2 grants ``tester``,
    and denies ``developer`` too or has no rule for it. alice holds ``developer`` and ``tester``; carol
    holds ``tester`` only."""

    @staticmethod
    def _bring_up(stack: Stack, scenario: str, order: str, side: EnforcementSide, monkeypatch) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.realm.ensure_role(TESTER, "Testers of the team.")
        for user in ("alice", "carol"):
            stack.realm.grant(user, TESTER)
        stack.realm.events.clear()
        decisions = {tool.client_id: copy for tool, copy in zip(TOOLS, DENY_SCENARIOS[scenario], strict=True)}
        for tool in TOOL_ORDERS[order]:
            stack.llm.decisions = decisions[tool.client_id]
            stack.bring_up(tool)
        stack.llm.decisions = DECISIONS
        stack.bring_up(AGENT1)

    @staticmethod
    def _verdicts(stack: Stack, side: EnforcementSide) -> dict[tuple[str, str], bool]:
        """The ``allow`` of the rendered CRs for (user, copy owner) through team1/github-agent."""
        verdicts = {}
        for user in ("alice", "carol"):
            for tool in TOOLS:
                if side is EnforcementSide.AGENT_SIDE:
                    rego, tier = stack.outbound(AGENT1.client_id), "outbound"
                    identity = {"subject": user, "service_id": tool.client_id}
                else:
                    rego, tier = stack.inbound(tool.client_id), "inbound"
                    identity = {"subject": user, "client_id": AGENT1.client_id}
                verdicts[user, tool.client_id] = _opa_allow(
                    rego, tier, {"identity": identity, "mcp": _CALL_SOURCE_READ}
                )
        return verdicts

    @pytest.mark.parametrize("order", list(TOOL_ORDERS))
    @pytest.mark.parametrize("side", SIDES, ids=lambda s: s.value)
    def test_a_deny_on_both_copies_blocks_the_user_on_both_copies(
        self, stack: Stack, side: EnforcementSide, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._bring_up(stack, "deny-on-both-copies", order, side, monkeypatch)

        for tool in TOOLS:
            spm = stack.store.spm(tool.client_id)
            assert spm is not None
            assert (DEVELOPER, SOURCE_READ, tool.client_id) in _edges(spm.inbound_deny_rules), tool.client_id
        assert self._verdicts(stack, side) == {
            ("alice", TOOL1.client_id): False,
            ("alice", TOOL2.client_id): False,  # the team2 SPM denies developer (alice holds it)
            ("carol", TOOL1.client_id): False,
            ("carol", TOOL2.client_id): True,  # tester, granted on the team2 copy
        }

    @pytest.mark.parametrize("order", list(TOOL_ORDERS))
    def test_agent_side_the_deny_map_has_the_deny_on_both_copies(
        self, stack: Stack, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The deny-agree control: the APM keeps the deny of each copy, and the writer keys each deny on
        its own copy, so both copies have it (with the deny of one copy only, the other copy would admit
        alice through her tester grant: fail-open)."""
        self._bring_up(stack, "deny-on-both-copies", order, EnforcementSide.AGENT_SIDE, monkeypatch)

        rego = stack.outbound(AGENT1.client_id)
        assert _rego_nested_map(rego, "subject_role_deny_scopes") == {
            DEVELOPER: {tool.client_id: ["source-read"] for tool in TOOLS}
        }
        assert _rego_nested_map(rego, "subject_role_allow_scopes") == {TESTER: {TOOL2.client_id: ["source-read"]}}

    @pytest.mark.parametrize("order", list(TOOL_ORDERS))
    def test_agent_side_the_deny_map_has_a_deny_of_one_copy_on_that_copy_only(
        self, stack: Stack, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the team1 copy denies ``developer``: the deny is keyed only on that copy, and the team2
        copy, whose SPM has no deny, gets no deny entry (no over-deny)."""
        self._bring_up(stack, "deny-on-team1-copy-only", order, EnforcementSide.AGENT_SIDE, monkeypatch)

        rego = stack.outbound(AGENT1.client_id)
        assert _rego_nested_map(rego, "subject_role_deny_scopes") == {DEVELOPER: {TOOL1.client_id: ["source-read"]}}
        assert _rego_nested_map(rego, "subject_role_allow_scopes") == {TESTER: {TOOL2.client_id: ["source-read"]}}

    def _verdicts_on_both_sides(self, stack: Stack, scenario: str, order: str, monkeypatch) -> dict:
        """Bring up under target side, then change to agent side as an operator does (the side in the
        ConfigMap, then the resync at the Controller start). The verdicts of each side, by side."""
        self._bring_up(stack, scenario, order, EnforcementSide.TARGET_SIDE, monkeypatch)
        verdicts = {EnforcementSide.TARGET_SIDE: self._verdicts(stack, EnforcementSide.TARGET_SIDE)}
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        computation.resync()
        verdicts[EnforcementSide.AGENT_SIDE] = self._verdicts(stack, EnforcementSide.AGENT_SIDE)
        return verdicts

    @pytest.mark.parametrize("order", list(TOOL_ORDERS))
    @pytest.mark.parametrize("scenario", list(DENY_SCENARIOS))
    def test_agent_side_is_never_more_permissive_than_target_side(
        self, stack: Stack, scenario: str, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """For each user and copy, the agent outbound allows only what the CR of that copy allows."""
        verdicts = self._verdicts_on_both_sides(stack, scenario, order, monkeypatch)
        opened = sorted(
            key
            for key, allowed in verdicts[EnforcementSide.AGENT_SIDE].items()
            if allowed and not verdicts[EnforcementSide.TARGET_SIDE][key]
        )
        assert opened == [], f"agent side allows where target side denies: {opened}"

    @pytest.mark.parametrize("order", list(TOOL_ORDERS))
    def test_a_deny_on_one_copy_gives_the_same_verdicts_on_both_sides(
        self, stack: Stack, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """alice is denied on the team1 copy only: both sides allow her on the team2 copy (her tester
        grant there), and every other verdict is the same too."""
        verdicts = self._verdicts_on_both_sides(stack, "deny-on-team1-copy-only", order, monkeypatch)
        assert verdicts[EnforcementSide.TARGET_SIDE][("alice", TOOL2.client_id)] is True, "the precondition"
        assert verdicts[EnforcementSide.AGENT_SIDE] == verdicts[EnforcementSide.TARGET_SIDE]
