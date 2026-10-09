"""A decommission takes the service out of the CRs of every role that it held (D32) — integration lane.

A shared role (D32) keeps its edges when one of its holders is removed: they are the grants of the
other holders too. So a decommission of service X renders the callees of each such role again,
without X, and does not write their SPMs. X is gone from the IdP (its client was deleted), so the
PCE cannot read the roles of X from the catalog any more. ``SPM(X).owned_roles`` has the roles of X
from the last run that wrote ``SPM(X)``. An admin can map a role to the service account of X after
that run: the role-members event (``rerender_role``) then puts X in the CRs of the role, and it
writes no SPM. So neither ``SPM(X)`` nor the stored ``actorIds`` of the callees name X, and before
the fix X stayed in those CRs until the resync (fail open). A client delete gives no role-members
event.

The harness is the one of ``test_shared_roles.py`` (the real resolver, PRB graphs, PCE and writer
between the fakes). The decisions let the holders of the shared role call each other
(``PEER_DECISIONS``), so the inbound of each github-agent names the holders of the role under both
sides, and the tools' inbound does under target side.
"""

import pytest

from aiac.policy import computation
from aiac.policy.model.models import EnforcementSide
from test.integration.policy.computation import test_shared_roles
from test.integration.policy.computation.fakes import SERVICE_ACCOUNT_PREFIX
from test.integration.policy.computation.test_shared_roles import (
    AGENT1,
    AGENT2,
    AGENT_ROLE,
    PEER_DECISIONS,
    REVIEWER,
    TOOLS,
    Stack,
    Workload,
    _holders,
)

pytestmark = pytest.mark.integration

# The harness of test_shared_roles.py: the real code between the fakes, under target side.
stack = test_shared_roles.stack


def _delete_client(stack: Stack, workload: Workload) -> None:
    """The Keycloak client delete: the client and its service-account user go, so the role mappings
    of the service account go too. It gives no role-members event."""
    realm, client_id = stack.realm, workload.client_id
    del realm._clients[client_id]
    del realm._client_scopes[client_id]
    account = f"{SERVICE_ACCOUNT_PREFIX}{client_id}"
    for role_id, members in realm._members.items():
        realm._members[role_id] = [member for member in members if member != account]
    realm.events.clear()


class TestALaterHolderIsDecommissioned:
    """team1/github-agent and team2/github-agent share ``github-agent.source_operations``. After
    review-agent is onboarded, an admin assigns the role to it, and the role-members event puts it in
    the CRs of the role. Then its client is deleted and the operator offboards it."""

    @pytest.mark.parametrize("side", list(EnforcementSide), ids=lambda side: side.value)
    def test_every_cr_of_the_role_loses_the_decommissioned_holder_at_once(
        self, stack: Stack, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.llm.decisions = PEER_DECISIONS
        for workload in (AGENT1, AGENT2, *TOOLS, REVIEWER):
            stack.bring_up(workload)
        stack.realm.grant(REVIEWER.client_id, AGENT_ROLE)  # the admin's role mapping
        stack.deliver_role_events()
        # The inbound gates of an agent are the same on both sides (D18b); a tool has them only
        # under target side (under agent side its CR is a pass-through, D24).
        callees = (AGENT1, AGENT2, *TOOLS) if side == EnforcementSide.TARGET_SIDE else (AGENT1, AGENT2)
        everyone = {AGENT1.client_id, AGENT2.client_id, REVIEWER.client_id}
        for callee in callees:
            assert _holders(stack, callee) == everyone, f"{callee.client_id}: after the admin's assignment"
        stored = stack.store.spm(REVIEWER.client_id)
        assert stored is not None
        assert AGENT_ROLE not in [role.name for role in stored.owned_roles], "the event wrote SPM(review-agent)"
        writes_before = len(stack.store.writes)

        _delete_client(stack, REVIEWER)
        computation.decommission(REVIEWER.client_id)

        for callee in callees:
            assert _holders(stack, callee) == {AGENT1.client_id, AGENT2.client_id}, (
                f"{callee.client_id}: the holders of {AGENT_ROLE} right after the decommission"
            )
        # The rules of the callees did not change: only SPM(review-agent) goes from the store.
        assert stack.store.writes[writes_before:] == [("delete", REVIEWER.client_id)]
        assert stack.cluster.policies(REVIEWER.client_id) is None


class TestARetriedDecommission:
    """The same assignment, then the client delete. The first decommission fails at the redeploy (the
    Kubernetes API is down for one CR patch), and the operator offboards review-agent again."""

    @pytest.mark.parametrize("side", list(EnforcementSide), ids=lambda side: side.value)
    def test_the_retry_takes_the_holder_out_of_every_cr_of_the_role(
        self, stack: Stack, side: EnforcementSide, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", side.value)
        stack.llm.decisions = PEER_DECISIONS
        for workload in (AGENT1, AGENT2, *TOOLS, REVIEWER):
            stack.bring_up(workload)
        stack.realm.grant(REVIEWER.client_id, AGENT_ROLE)
        stack.deliver_role_events()
        callees = (AGENT1, AGENT2, *TOOLS) if side == EnforcementSide.TARGET_SIDE else (AGENT1, AGENT2)
        _delete_client(stack, REVIEWER)

        patch, failed = stack.cluster.patch_namespaced_custom_object, []

        def down_once(**kwargs: object) -> None:
            if not failed:
                failed.append(kwargs["name"])
                raise RuntimeError("the Kubernetes API is down")
            patch(**kwargs)

        monkeypatch.setattr(stack.cluster, "patch_namespaced_custom_object", down_once)
        with pytest.raises(RuntimeError, match="the Kubernetes API is down"):
            computation.decommission(REVIEWER.client_id)
        assert failed, "the decommission patched no CR"
        assert stack.store.spm(REVIEWER.client_id) is not None, "the failed decommission deleted SPM(review-agent)"

        computation.decommission(REVIEWER.client_id)

        for callee in callees:
            assert _holders(stack, callee) == {AGENT1.client_id, AGENT2.client_id}, (
                f"{callee.client_id}: the holders of {AGENT_ROLE} after the retry"
            )
        assert stack.store.spm(REVIEWER.client_id) is None
        assert stack.cluster.policies(REVIEWER.client_id) is None
