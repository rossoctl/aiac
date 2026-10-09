"""The lift of a quarantine puts the service back in the CRs of its shared roles (D32) — integration lane.

A failed onboarding of a service X quarantines it (UC-1 Failure & Rollback): the rollback disables
the client, and ``quarantine`` deletes ``SPM(X)`` and the CR of X. A role that X shares with another
service (Provision reuses it by name, so it is not in the created-manifest) stays mapped to X, and its
edges stay on the SPMs of its callees. X is disabled, so it is not a holder: the quarantine renders
those CRs again without X. It does not write those SPMs (their rules did not change), so their stored
``actorIds`` still name X. The edges stay also when the other holder is quarantined (disabled) too:
a disabled client keeps its role mappings, so it still holds the role, and its lift gives the edges
back to it.

Only a successful re-onboarding lifts the quarantine. Its ``compute_and_apply`` runs with X as the
focus service (X counts as live, its client is still disabled), so the callees get X as a holder
again. Before the fix, their refreshed SPM was equal to the stored one (not stale), and a callee that
the lift's batch does not route a new rule to was not touched at all: no CR got X back until a
role-members event or the resync. Provision's re-map of the kept shared role sends a role-members
event too: Keycloak (26.5.2) sends ``REALM_ROLE_MAPPING`` CREATE also for a mapping that is already
there. That event would repair the CRs, so each test drops it, to show that the lift alone repairs
them. The lift also writes each lifted SPM whose stored holders are stale, so its snapshot names the
holders that its CR names.

The caller re-enables the client after ``compute_and_apply`` returns, outside the PCE lock. So the
lift counts X as waiting for its re-enable, and the PCE counts a waiting service as live until the
caller calls ``lift_done`` (after ``reenable_service``, also when it fails). A render in that window
(for example the role-members event of the re-map) then keeps X in the CRs of its roles.

The harness is the one of ``test_shared_roles.py`` (the real resolver, PRB graphs, PCE and writer
between the fakes).
"""

import copy

import pytest

from aiac.policy import computation
from aiac.policy.computation import engine
from aiac.policy.model.models import EnforcementSide
from test.integration.policy.computation import test_shared_roles
from test.integration.policy.computation.test_shared_roles import (
    AGENT1,
    AGENT2,
    AGENT_ROLE,
    DECISIONS,
    DEVELOPER,
    ORDERS,
    REVIEW_SKILL,
    REVIEWER,
    SOURCE_READ,
    SOURCE_WRITE,
    TOOL1,
    TOOLS,
    Stack,
    Workload,
    _assert_tool_gates,
    _holders,
)

pytestmark = pytest.mark.integration

# The harness of test_shared_roles.py: the real code between the fakes, under target side.
stack = test_shared_roles.stack

# The shared role may also call review-agent: the scope-focal pass of its skill grants it, at the
# onboarding of review-agent. The role-focal pass of the shared role does not grant it, so the
# onboarding of a github-agent routes no rule to SPM(review-agent).
REVIEWER_CALLED = {**DECISIONS, ("scope", REVIEW_SKILL): ({DEVELOPER, AGENT_ROLE}, set())}


def _set_enabled(stack: Stack, workload: Workload, enabled: bool) -> None:
    """The client's ``enabled`` flag: the rollback's disable, or ``reenable_service``."""
    stack.realm._clients[workload.client_id]["enabled"] = enabled


def _fail_onboarding(stack: Stack, workload: Workload) -> None:
    """A failed onboarding of ``workload``: Provision (create-or-get), the build fails, the rollback
    disables the client, and the Orchestrator calls ``quarantine``. The shared role was reused, so
    it is not in the created-manifest: there are no deleted roles. The role-members events of
    Provision come after the onboarding (one message at a time)."""
    stack.realm.provision(workload.namespace, workload.name, workload.type, workload.entries)
    _set_enabled(stack, workload, False)
    computation.quarantine(workload.client_id, [])
    stack.deliver_role_events()


def _lift(stack: Stack, workload: Workload) -> None:
    """A successful re-onboarding of the quarantined ``workload``: Provision again (create-or-get),
    the build and ``compute_and_apply`` with the client still disabled (the focus service), then
    ``reenable_service`` and ``lift_done``, as the Controller does. Provision maps the kept shared role
    again, and Keycloak sends a role-members event also for a mapping that is already there; the test
    drops it, so only the lift can repair the CRs."""
    stack.realm.provision(workload.namespace, workload.name, workload.type, workload.entries)
    stack.drop_role_events()
    stack.onboard(workload.client_id)
    _set_enabled(stack, workload, True)
    computation.lift_done(workload.client_id)


@pytest.fixture(autouse=True)
def _no_service_waits_for_its_re_enable():
    """No test leaves a service in the PCE's in-process set of services that wait for their re-enable
    (a test that fails before its ``lift_done`` would leave it for the next test)."""
    yield
    engine._awaiting_reenable.clear()


class TestTheLiftPutsTheHolderBack:
    """team1/github-agent and team2/github-agent share ``github-agent.source_operations``; the two
    tools grant it ``source-read`` and deny it ``source-write``. team2's onboarding fails, then a
    re-onboarding of team2 succeeds."""

    @pytest.mark.parametrize("before", ["onboarded", "never-onboarded"])
    def test_each_tool_cr_names_the_lifted_holder_again(self, stack: Stack, before: str) -> None:
        # "onboarded": a re-onboarding of team2 fails (its SPM and the tools' snapshots name it).
        # "never-onboarded": the first onboarding of team2 fails.
        workloads = ORDERS["agents-first"] if before == "onboarded" else (AGENT1, *TOOLS)
        for workload in workloads:
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT2)
        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT1.client_id}, f"{tool.client_id}: after the quarantine"

        _lift(stack, AGENT2)

        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT1.client_id, AGENT2.client_id}, (
                f"{tool.client_id}: the holders of {AGENT_ROLE} right after the lift"
            )
            _assert_tool_gates(stack, tool)

    @pytest.mark.parametrize("side", list(EnforcementSide), ids=lambda side: side.value)
    def test_a_callee_that_the_lift_routes_no_rule_to_names_the_lifted_holder_again(
        self, stack: Stack, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # review-agent's inbound names the holders of the shared role (its source_roles), under both
        # sides. Its edge comes from its own onboarding, so team2's lift does not touch its SPM.
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (AGENT1, AGENT2, TOOL1, REVIEWER):
            stack.bring_up(workload)
        assert _holders(stack, REVIEWER) == {AGENT1.client_id, AGENT2.client_id}, "before the failure"
        _fail_onboarding(stack, AGENT2)
        assert _holders(stack, REVIEWER) == {AGENT1.client_id}, "after the quarantine"
        writes_before = len(stack.store.writes)

        _lift(stack, AGENT2)

        assert ("apply", REVIEWER.client_id) not in stack.store.writes[writes_before:], "the lift routed to it"
        assert _holders(stack, REVIEWER) == {AGENT1.client_id, AGENT2.client_id}, (
            f"{REVIEWER.client_id}: the holders of {AGENT_ROLE} right after the lift"
        )

    def test_a_shared_role_whose_other_holders_are_all_quarantined(self, stack: Stack) -> None:
        # Both holders fail. Each lift gives the role back to the lifted holder only: a holder that is
        # still quarantined stays out of the CRs.
        for workload in ORDERS["agents-first"]:
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT1)
        _fail_onboarding(stack, AGENT2)
        for tool in TOOLS:
            assert _holders(stack, tool) == set(), f"{tool.client_id}: after both quarantines"

        _lift(stack, AGENT2)
        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT2.client_id}, f"{tool.client_id}: after the lift of team2"
            _assert_tool_gates(stack, tool)

        _lift(stack, AGENT1)
        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT1.client_id, AGENT2.client_id}, (
                f"{tool.client_id}: after the lift of team1"
            )

    @pytest.mark.parametrize("side", list(EnforcementSide), ids=lambda side: side.value)
    def test_a_callee_that_no_lift_routes_a_rule_to_keeps_the_role_while_every_holder_is_quarantined(
        self, stack: Stack, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # review-agent's edge of the shared role comes from its own onboarding, so no lift routes a rule
        # to it: only the stored edge can give a lifted holder the grant back. team1 fails first, then
        # team2. team1 is disabled, but its client keeps the mapping of the role, so it still holds it:
        # the quarantine of team2 does not purge the edge, which is the grant of team1 too.
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (AGENT1, AGENT2, TOOL1, REVIEWER):
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT1)
        _fail_onboarding(stack, AGENT2)
        assert _holders(stack, REVIEWER) == set(), "after both quarantines"
        assert _stored_holders(stack, REVIEWER), "the quarantine of team2 purged the edge of the shared role"

        _lift(stack, AGENT1)

        assert _holders(stack, REVIEWER) == {AGENT1.client_id}, f"{REVIEWER.client_id}: after the lift of team1"

    @pytest.mark.parametrize("side", list(EnforcementSide), ids=lambda side: side.value)
    def test_the_resync_after_a_lift_gives_the_same_crs(
        self, stack: Stack, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (*ORDERS["agents-first"], REVIEWER):
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT2)
        _lift(stack, AGENT2)
        after_lift = copy.deepcopy(stack.cluster.crs)

        computation.resync()

        assert stack.cluster.crs == after_lift


class TestTheWindowBeforeTheReEnable:
    """A render between the lift (``compute_and_apply``) and ``reenable_service`` reads the client of
    team2 as disabled. Here it is the role-members event of Provision's re-map of the shared role. The
    NATS consumer can run it in that window when the onboarding came on the HTTP route
    ``POST /apply/service/{service_id}`` (the consumer is then free), and so can the route
    ``POST /apply/role-members/{role_id}``."""

    @pytest.mark.parametrize("side", list(EnforcementSide), ids=lambda side: side.value)
    def test_a_role_members_event_before_the_re_enable_keeps_the_lifted_holder(
        self, stack: Stack, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (AGENT1, AGENT2, TOOL1, REVIEWER):
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT2)
        # Under agent side the tool CR is a pass-through: review-agent's inbound names the holders.
        callees = (TOOL1, REVIEWER) if side == EnforcementSide.TARGET_SIDE else (REVIEWER,)
        stack.realm.provision(AGENT2.namespace, AGENT2.name, AGENT2.type, AGENT2.entries)
        assert stack.realm.events, "Provision's re-map of the shared role sends a role-members event"
        stack.onboard(AGENT2.client_id)  # the lift

        stack.deliver_role_events()  # before reenable_service
        for callee in callees:
            assert _holders(stack, callee) == {AGENT1.client_id, AGENT2.client_id}, f"{callee.client_id}: in the window"

        _set_enabled(stack, AGENT2, True)  # reenable_service
        computation.lift_done(AGENT2.client_id)
        stack.onboard(AGENT1.client_id)  # a later run that touches the callees
        for callee in callees:
            assert _holders(stack, callee) == {AGENT1.client_id, AGENT2.client_id}, f"{callee.client_id}: after it"

    def test_after_a_failed_re_enable_the_next_render_takes_the_holder_out(self, stack: Stack) -> None:
        # reenable_service failed: the client of team2 stays disabled, and lift_done ends the wait.
        for workload in ORDERS["agents-first"]:
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT2)
        stack.realm.provision(AGENT2.namespace, AGENT2.name, AGENT2.type, AGENT2.entries)
        stack.onboard(AGENT2.client_id)  # the lift
        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT1.client_id, AGENT2.client_id}, f"{tool.client_id}: the lift"

        computation.lift_done(AGENT2.client_id)
        stack.deliver_role_events()

        for tool in TOOLS:
            assert _holders(stack, tool) == {AGENT1.client_id}, f"{tool.client_id}: team2 is still disabled"


class TestTheStoreAfterALift:
    """The CR and the stored snapshot of a lifted callee name the same holders, so a later stale
    check sees a later change of the holders."""

    def test_a_holder_that_loses_the_role_after_the_lift_leaves_a_callee_cr(self, stack: Stack) -> None:
        # review-agent's edge of the shared role comes from its own onboarding (scope-focal), so the
        # lift of team2 routes no rule to it. While team2 is quarantined, review-agent re-onboards:
        # its holders are stale, so that run writes its snapshot with team1 only. The lift deploys it
        # with team2 again, and must also write that snapshot. Later team2 loses the shared role and
        # the event is lost (the live SPI image has no role-members listener). Then team1's
        # re-onboarding judges the pair in the role-focal pass too (a judge decision can differ
        # between runs): a duplicate rule on SPM(review-agent). Only a snapshot that names team2
        # makes it stale, so its CR loses team2; else the CR keeps allowing team2 until the resync.
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (AGENT1, AGENT2, TOOL1, REVIEWER):
            stack.bring_up(workload)
        _fail_onboarding(stack, AGENT2)
        stack.onboard(REVIEWER.client_id)
        assert _stored_holders(stack, REVIEWER) == [[AGENT1.client_id]], "during the quarantine"
        writes_before = len(stack.store.writes)

        _lift(stack, AGENT2)
        assert ("apply", REVIEWER.client_id) in stack.store.writes[writes_before:], "the lift did not write it"
        assert _holders(stack, REVIEWER) == {AGENT1.client_id, AGENT2.client_id}, "the CR after the lift"
        assert _stored_holders(stack, REVIEWER) == [[AGENT1.client_id, AGENT2.client_id]], "the snapshot after the lift"

        stack.realm.revoke(AGENT2.client_id, AGENT_ROLE)
        stack.drop_role_events()
        stack.llm.decisions = {**REVIEWER_CALLED, ("role", AGENT_ROLE): ({SOURCE_READ, REVIEW_SKILL}, {SOURCE_WRITE})}
        stack.onboard(AGENT1.client_id)

        assert _holders(stack, REVIEWER) == {AGENT1.client_id}, f"after team2 lost {AGENT_ROLE}"


def _stored_holders(stack: Stack, tool: Workload) -> list[list[str]]:
    """The distinct stored ``actorIds`` (the snapshot) on the edges of the shared role on the tool's
    SPM, allow and deny."""
    spm = stack.store.spm(tool.client_id)
    assert spm is not None, f"no SPM for {tool.client_id}"
    edges = spm.inbound_allow_rules + spm.inbound_deny_rules
    return [list(ids) for ids in sorted({tuple(rule.role.actorIds) for rule in edges if rule.role.name == AGENT_ROLE})]


class TestNoExtraDeploy:
    """A lift deploys the callees of a shared role only. A service that holds no shared role gets the
    same deploys as before the fix."""

    def test_the_lift_of_a_service_that_holds_no_shared_role_deploys_only_what_its_run_changed(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # review-agent holds only its own role, which no rule uses. Its run changes only SPM(review-agent).
        for workload in (*ORDERS["agents-first"], REVIEWER):
            stack.bring_up(workload)
        _fail_onboarding(stack, REVIEWER)
        deployed: list[list[str]] = []
        apply_policy = engine.apply_policy

        def recording(model):
            deployed.append([entry.service_id for entry in model.services])
            return apply_policy(model)

        monkeypatch.setattr(engine, "apply_policy", recording)

        _lift(stack, REVIEWER)

        assert deployed == [[REVIEWER.client_id]]
