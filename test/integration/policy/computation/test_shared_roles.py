"""Shared roles and shared scopes, from onboarding to the rendered CR (handoff 19, D32) — integration lane.

D32: one policy for the whole realm, so services in different namespaces (or an admin, in one
namespace) share a realm role or a client scope by name. Every holder of a shared role must get the
grants of that role, a shared scope is decided one time, and the holders of a role (agents and users)
in a CR are the current holders, not a copy from the onboarding that stored the rule.

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
resync must repair the CRs.

Before D32 (on HEAD ``2069752``), cases 1 and 2 failed by an assertion: an agent that holds the shared
role was missing from the tool CR's ``source_roles``.
"""

import json
import sys
from dataclasses import dataclass

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


def _holders(stack: Stack, tool: Workload, role: str = AGENT_ROLE) -> set[str]:
    """The callers (clientIds) that the tool CR's ``source_roles`` gives ``role``."""
    source_roles = _rego_map(stack.inbound(tool.client_id), "source_roles")
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
