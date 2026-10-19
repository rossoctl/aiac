"""A later run repairs a CR whose snapshot does not name its holders (D32) — integration lane.

The PCE keeps the holders of a role at render time (``RoleHolders``), not in the store: a stored edge
keeps a copy of the holders (a snapshot) from the run that wrote it. A run writes an SPM whose stored
holders are not the current ones (it is stale), so its snapshot names the holders of its CR. A render
that writes no SPM (``rerender_role``, the resync) does not: after it, a CR can name a holder that the
snapshot does not name. If that holder then loses the role and the role-members event is lost (for
example while the Keycloak SPI publishes nothing), the SPM is not stale. So before the fix, a later
run that routed only a duplicate rule to it did not deploy it, and the CR kept the grant of the
removed holder until the resync (fail open). Now every SPM that a run touches is deployed.

The resync (at every Controller start) is the repair of a missed role-members event: it renders every
CR with the current holders, not with the snapshots.

The harness is the one of ``test_shared_roles.py`` (the real resolver, PRB graphs, PCE and writer
between the fakes).
"""

import pytest

from test.integration.policy.computation import test_shared_roles
from test.integration.policy.computation.test_shared_roles import (
    AGENT1,
    AGENT_ROLE,
    REVIEWER,
    TOOL1,
    Stack,
    _holders,
)

pytestmark = pytest.mark.integration

# The harness of test_shared_roles.py: the real code between the fakes.
stack = test_shared_roles.stack


def _stored_holders(stack: Stack, client_id: str) -> set[tuple[str, ...]]:
    """The distinct stored ``actorIds`` (the snapshot) on the edges of the shared role on an SPM."""
    spm = stack.store.spm(client_id)
    assert spm is not None, f"no SPM for {client_id}"
    edges = spm.inbound_allow_rules + spm.inbound_deny_rules
    return {tuple(rule.role.actorIds) for rule in edges if rule.role.name == AGENT_ROLE}


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
