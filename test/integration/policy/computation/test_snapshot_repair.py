"""A later run repairs a CR whose snapshot does not name its holders (D32) — integration lane.

The PCE keeps the holders of a role at render time (``RoleHolders``), not in the store: a stored edge
keeps a copy of the holders (a snapshot) from the run that wrote it. A run writes an SPM whose stored
holders are not the current ones (it is stale), so its snapshot names the holders of its CR. A render
that writes no SPM (``rerender_role``, the resync) does not: after it, a CR can name a holder that the
snapshot does not name. If that holder then loses the role and the role-members event is lost (for
example while the Keycloak SPI publishes nothing), the SPM is not stale. So before the fix, a later
run that routed only a duplicate rule to it did not deploy it, and the CR kept the grant of the
removed holder until the resync (fail open). Now every SPM that a run touches is deployed.

Under agent side the CR that keeps the grant is the outbound of the removed holder itself. A run that
finds a stale SPM re-derives its former holders too (the stored holders that do not hold the role
now): they are not holders any more, so the current holders do not find them.

The resync (at every Controller start) is the repair of a missed role-members event: it renders every
CR with the current holders, not with the snapshots. Under agent side it derives each APM so, as a
deploy does: the inbound of a callee agent then names the current holders of a role and the current
members of a user role, and the outbound subject gate of each caller names the current members of a
user role (so a user who lost the role does not get past the caller's outbound).

The harness is the one of ``test_shared_roles.py`` (the real resolver, PRB graphs, PCE and writer
between the fakes).
"""

import pytest

from aiac.policy import computation
from aiac.policy.model.models import EnforcementSide
from test.integration.policy.computation import test_shared_roles
from test.integration.policy.computation.test_shared_roles import (
    AGENT1,
    AGENT2,
    AGENT_ROLE,
    DECISIONS,
    DEVELOPER,
    REVIEW_SKILL,
    REVIEWER,
    TOOL1,
    TOOLS,
    Stack,
    _holders,
    _opa_allow,
    _rego_map,
    _rego_nested_map,
    _users,
)

pytestmark = pytest.mark.integration

# The harness of test_shared_roles.py: the real code between the fakes, under target side.
stack = test_shared_roles.stack


def _stored_holders(stack: Stack, client_id: str) -> set[tuple[str, ...]]:
    """The distinct stored ``actorIds`` (the snapshot) on the edges of the shared role on an SPM."""
    spm = stack.store.spm(client_id)
    assert spm is not None, f"no SPM for {client_id}"
    edges = spm.inbound_allow_rules + spm.inbound_deny_rules
    return {tuple(rule.role.actorIds) for rule in edges if rule.role.name == AGENT_ROLE}


def _outbound_users(stack: Stack, client_id: str, role: str = DEVELOPER) -> set[str]:
    """The users that the outbound CR of an agent gives ``role`` (its ``subject_roles``): the outbound
    subject gate admits only these users through the agent."""
    subject_roles = _rego_map(stack.outbound(client_id), "subject_roles")
    return {user for user, roles in subject_roles.items() if role in roles}


class TestADuplicateRuleRepairsTheCr:
    """team1/github-agent holds ``github-agent.source_operations``, which the tool grants
    ``source-read`` and denies ``source-write``. An admin assigns the role to team1/review-agent, and
    the role-members event puts it in the tool CR (no SPM write). Later the admin removes it again,
    and that event is lost. Then team1/github-agent re-onboards: its rules on the tool are duplicates."""

    def test_the_tool_cr_loses_the_holder_that_lost_the_role(self, stack: Stack) -> None:
        for workload in (AGENT1, TOOL1, REVIEWER):
            stack.bring_up(workload)
        stack.realm.grant(REVIEWER.client_id, AGENT_ROLE)
        stack.deliver_role_events()
        assert _holders(stack, TOOL1) == {AGENT1.client_id, REVIEWER.client_id}, "after the assignment"
        assert _stored_holders(stack, TOOL1.client_id) == {(AGENT1.client_id,)}, "the event wrote the SPM"

        stack.realm.revoke(REVIEWER.client_id, AGENT_ROLE)
        stack.drop_role_events()
        stack.onboard(AGENT1.client_id)

        assert _holders(stack, TOOL1) == {AGENT1.client_id}, f"after review-agent lost {AGENT_ROLE}"


class TestAgentSideAFormerHolderIsDerivedAgain:
    """Under agent side. team1/github-agent and team2/github-agent share the role, and the tools'
    snapshots name both. team2 loses the role, and the event is lost. Then team1/github-agent
    re-onboards: the tools are stale (their snapshot names team2), so the run writes them, and team2 is
    a former holder of them."""

    def test_the_outbound_of_the_former_holder_loses_the_tools(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        for workload in (AGENT1, AGENT2, *TOOLS):
            stack.bring_up(workload)
        targets = {tool.client_id: ["source-read"] for tool in TOOLS}
        assert _rego_map(stack.outbound(AGENT2.client_id), "target_allow_scopes") == targets, "before"

        stack.realm.revoke(AGENT2.client_id, AGENT_ROLE)
        stack.drop_role_events()
        stack.onboard(AGENT1.client_id)

        for tool in TOOLS:
            assert _stored_holders(stack, tool.client_id) == {(AGENT1.client_id,)}, f"{tool.client_id}: not written"
        assert _rego_map(stack.outbound(AGENT2.client_id), "target_allow_scopes") == {}, (
            f"{AGENT2.client_id}: the outbound after it lost {AGENT_ROLE}"
        )
        assert _rego_map(stack.outbound(AGENT1.client_id), "target_allow_scopes") == targets


# The scope-focal pass of review-agent's skill also grants the shared role, so the inbound of
# review-agent names the holders of the role, under both sides.
REVIEWER_CALLED = {**DECISIONS, ("scope", REVIEW_SKILL): ({DEVELOPER, AGENT_ROLE}, set())}


class TestAgentSideTheResyncRepairsAMissedEvent:
    """Under agent side. team1/github-agent and team2/github-agent share the role, which may call
    review-agent, and alice and bob are developers. Then team2 loses the role, carol becomes a
    developer and bob stops being one, and every role-members event is lost. The Controller restarts.

    The resync derives every APM with the current holders: the inbound of the callee and the
    outbound of each caller. The outbound subject gate of team1 (the remaining holder) decides which
    users reach review-agent through team1."""

    @staticmethod
    def _restart_after_missed_events(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> int:
        """Bring up the agents, the tool and review-agent, change the holders with every event lost,
        then run the resync. Returns the number of store writes before the resync."""
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
        stack.llm.decisions = REVIEWER_CALLED
        for workload in (AGENT1, AGENT2, TOOL1, REVIEWER):
            stack.bring_up(workload)
        assert _holders(stack, REVIEWER) == {AGENT1.client_id, AGENT2.client_id}, "before"
        assert _users(stack, REVIEWER) == {"alice", "bob"}, "before"
        assert _outbound_users(stack, AGENT1.client_id) == {"alice", "bob"}, "before"
        writes_before = len(stack.store.writes)

        stack.realm.revoke(AGENT2.client_id, AGENT_ROLE)
        stack.realm.grant("carol", DEVELOPER)
        stack.realm.revoke("bob", DEVELOPER)
        stack.drop_role_events()
        computation.resync()
        return writes_before

    def test_the_apm_of_the_callee_names_the_current_holders(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        writes_before = self._restart_after_missed_events(stack, monkeypatch)

        assert _holders(stack, REVIEWER) == {AGENT1.client_id}, f"{REVIEWER.client_id}: the holders of {AGENT_ROLE}"
        assert _users(stack, REVIEWER) == {"alice", "carol"}, f"{REVIEWER.client_id}: the members of {DEVELOPER}"
        assert _rego_map(stack.outbound(AGENT2.client_id), "target_allow_scopes") == {}, (
            f"{AGENT2.client_id}: the outbound after it lost {AGENT_ROLE}"
        )
        assert stack.store.writes[writes_before:] == [], "the resync wrote an SPM"

    def test_the_outbound_of_the_remaining_holder_names_the_current_members(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._restart_after_missed_events(stack, monkeypatch)

        rego = stack.outbound(AGENT1.client_id)
        assert _rego_map(rego, "target_allow_scopes")[REVIEWER.client_id] == ["code_review"], (
            f"{AGENT1.client_id}: the outbound edge to {REVIEWER.client_id}"
        )
        assert _rego_nested_map(rego, "subject_role_allow_scopes")[DEVELOPER][REVIEWER.client_id] == ["code_review"]
        assert _outbound_users(stack, AGENT1.client_id) == {"alice", "carol"}, (
            f"{AGENT1.client_id}: the outbound subject gate names the current members of {DEVELOPER}"
        )

    @pytest.mark.parametrize(("user", "expected"), [("alice", True), ("carol", True), ("bob", False)])
    def test_the_outbound_of_the_remaining_holder_decides_with_the_current_members(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch, user: str, expected: bool
    ) -> None:
        """The decision of team1's rendered outbound for a ``code_review`` call to review-agent."""
        self._restart_after_missed_events(stack, monkeypatch)

        identity = {"subject": user, "service_id": REVIEWER.client_id}
        call = {"method": "tools/call", "params": {"name": "code_review"}}
        allowed = _opa_allow(stack.outbound(AGENT1.client_id), "outbound", {"identity": identity, "mcp": call})
        assert allowed is expected, f"{user} -> {REVIEWER.client_id} code_review through {AGENT1.client_id}"
