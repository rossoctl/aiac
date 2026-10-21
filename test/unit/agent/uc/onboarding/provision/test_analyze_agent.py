"""Unit tests for the Service Provision `analyze_agent` node (UC1, issue 4.3).

Kubernetes access (AgentCard CRs) is mocked via the `_custom_objects` seam.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from aiac.agent.uc.onboarding.provision import kube, nodes
from aiac.agent.uc.onboarding.provision.nodes import AgentCardNotReadyError
from aiac.agent.uc.onboarding.provision.state import OnboardingProvisionState, Trigger

NS = "team-a"
WORKLOAD = "weather"
SYNCED = {"type": "Synced", "status": "True", "reason": "SyncSucceeded", "message": "Successfully fetched"}


def _state():
    return OnboardingProvisionState(trigger=Trigger(entity_id="svc-123"), namespace=NS, workload_name=WORKLOAD)


def _card(name=WORKLOAD, skills=None, synced=SYNCED):
    """An AgentCard CR as the operator syncs it: the fetched A2A card lives under ``status.card``,
    and each skill carries a machine ``id`` (a stable identifier) plus a display ``name``. The
    operator writes the card and its ``Synced`` condition in one status update; ``synced=None``
    gives a card with no ``Synced`` condition yet."""
    status = {"card": {"skills": skills or []}}
    if synced is not None:
        status["conditions"] = [synced]
    return {"metadata": {"name": name}, "status": status}


def _not_synced(reason, message="not yet"):
    return {"type": "Synced", "status": "False", "reason": reason, "message": message}


@pytest.fixture(autouse=True)
def _fast_card_wait(monkeypatch):
    # Keep the deploy->onboard card-sync wait instant in unit tests: a single look, no sleep.
    # Tests that exercise the RETRY path override ONBOARD_CARD_WAIT_ATTEMPTS themselves.
    monkeypatch.setenv("ONBOARD_CARD_WAIT_ATTEMPTS", "1")
    monkeypatch.setenv("ONBOARD_CARD_WAIT_BACKOFF", "0")


def _run(items=None, list_exc=None):
    with patch.object(kube, "_custom_objects") as co:
        client = MagicMock()
        if list_exc is not None:
            client.list_namespaced_custom_object.side_effect = list_exc
        else:
            client.list_namespaced_custom_object.return_value = {"items": items or []}
        co.return_value = client
        return nodes.analyze_agent(_state())


class TestAnalyzeAgentFound:
    def test_one_operator_role_and_one_scope_per_skill(self):
        # Scope names come from each skill's machine ``id`` — not its display ``name`` (which may
        # contain spaces) — so they are stable identifiers usable as Keycloak scope names. Each skill
        # also yields a per-skill operator role mirroring the scope (same name + description); the
        # role's description drives the PRB capability-match. No generic ``{workload}.agent`` role.
        skills = [
            {"id": "forecast", "name": "Weather forecast operations", "description": "Get forecast"},
            {"id": "history", "name": "Historical data operations", "description": "Historical data"},
        ]
        provision = _run(items=[_card(skills=skills)])["service_provision"]

        assert [r.name for r in provision.roles] == [f"{WORKLOAD}.forecast", f"{WORKLOAD}.history"]
        assert provision.roles[0].description == "Get forecast"
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.forecast", f"{WORKLOAD}.history"]
        assert provision.scopes[0].description == "Get forecast"
        # role name == scope name per skill (distinct Keycloak objects: realm role vs client scope)
        assert [r.name for r in provision.roles] == [s.name for s in provision.scopes]
        assert f"{WORKLOAD}.agent" not in [r.name for r in provision.roles]
        assert "derived from AgentCard: 2 skills" == provision.reasoning

    def test_agentcard_matched_by_targetref_not_metadata_name(self):
        # The operator names the card after the Deployment (e.g. "<workload>-deployment-card") and
        # points spec.targetRef at the workload; provision must link the card by targetRef, not by
        # metadata.name == workload.
        card = {
            "metadata": {"name": f"{WORKLOAD}-deployment-card"},
            "spec": {"targetRef": {"kind": "Deployment", "name": WORKLOAD}},
            "status": {
                "card": {"skills": [{"id": "forecast", "name": "F", "description": "d"}]},
                "conditions": [SYNCED],
            },
        }
        provision = _run(items=[card])["service_provision"]

        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.forecast"]
        assert "derived from AgentCard: 1 skills" == provision.reasoning


class TestAnalyzeAgentNoSkillsFallback:
    def test_synced_card_with_no_skills_yields_default_access_scope_and_partial_reasoning(self):
        # The operator fetched the card (Synced=True) and it has no skills: a real "no skills", so a
        # default operator role mirrors the default access scope.
        provision = _run(items=[_card(skills=[])])["service_provision"]

        assert [r.name for r in provision.roles] == [f"{WORKLOAD}.access"]
        assert provision.roles[0].description == "Default access scope"
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.access"]
        assert provision.scopes[0].description == "Default access scope"
        assert provision.reasoning == "partial: AgentCard has no synced skills, default scope assigned"

    def test_synced_card_with_no_skills_key_is_the_same_fallback(self):
        # ``status.card.skills`` is omitempty in the CRD, so a card with no skills can have no key.
        card = {"metadata": {"name": WORKLOAD}, "status": {"card": {}, "conditions": [SYNCED]}}
        provision = _run(items=[card])["service_provision"]
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.access"]
        assert "no synced skills" in provision.reasoning


class TestAnalyzeAgentNotReady:
    """A card that is not ``Synced=True`` after the budget is not ready: ``AgentCardNotReadyError``
    (a retryable ``502``), never a default role. Skills alone are not proof of a sync."""

    def _raises(self, items):
        with pytest.raises(AgentCardNotReadyError) as ei:
            _run(items=items)
        assert ei.value.status_code == 502
        assert repr(WORKLOAD) in ei.value.detail and repr(NS) in ei.value.detail
        return ei.value.detail

    def test_no_agentcard_is_not_ready(self):
        detail = self._raises([])
        assert "no AgentCard targets the workload" in detail

    def test_agentcard_of_another_workload_is_no_agentcard(self):
        detail = self._raises([_card(name="other-agent", skills=[{"id": "x", "name": "X", "description": "y"}])])
        assert "no AgentCard targets the workload" in detail

    def test_card_with_skills_but_no_synced_condition_is_not_ready(self):
        detail = self._raises([_card(skills=[{"id": "x", "name": "X", "description": "y"}], synced=None)])
        assert "no Synced condition" in detail

    def test_card_with_skills_and_synced_false_is_not_ready(self):
        # The operator writes the card, then Synced=False, on a failed signature check: the skills are
        # there, but they are not a sync.
        card = _card(
            skills=[{"id": "x", "name": "X", "description": "y"}], synced=_not_synced("SignatureInvalid", "bad sig")
        )
        detail = self._raises([card])
        assert "Synced=False (SignatureInvalid): bad sig" in detail


class TestAnalyzeAgentCardSyncRace:
    """The operator syncs the fetched A2A card onto ``status.card`` (with ``Synced=True``) only AFTER
    the workload is Available and a fetch succeeds — later than the Keycloak-registration event that
    triggers onboarding — so this node can run before the card is synced. A card that is not
    ``Synced=True`` yet is re-polled a bounded number of times; after the budget it is not ready
    (``AgentCardNotReadyError``), never a default access scope."""

    def _run_with_client(self, monkeypatch, *, attempts, side_effect=None, return_value=None):
        # monkeypatch.setattr (not a with-block) so the seam stays patched through the test body,
        # where analyze_agent is actually invoked.
        monkeypatch.setenv("ONBOARD_CARD_WAIT_ATTEMPTS", str(attempts))
        monkeypatch.setenv("ONBOARD_CARD_WAIT_BACKOFF", "0")
        client = MagicMock()
        if side_effect is not None:
            client.list_namespaced_custom_object.side_effect = side_effect
        else:
            client.list_namespaced_custom_object.return_value = return_value
        monkeypatch.setattr(kube, "_custom_objects", MagicMock(return_value=client))
        return client

    def test_card_synced_late_is_retried_then_succeeds(self, monkeypatch):
        client = self._run_with_client(
            monkeypatch,
            attempts=4,
            side_effect=[
                {"items": [_card(synced=_not_synced("WorkloadNotReady"))]},  # the workload is not Available yet
                {"items": [_card(synced=_not_synced("FetchFailed", "connection reset by peer"))]},  # port not up
                {"items": [_card(skills=[{"id": "forecast", "name": "F", "description": "Get forecast"}])]},  # synced
            ],
        )
        provision = nodes.analyze_agent(_state())["service_provision"]
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.forecast"]
        assert "derived from AgentCard: 1 skills" == provision.reasoning
        assert client.list_namespaced_custom_object.call_count == 3  # re-polled twice, then succeeded

    def test_never_synced_is_not_ready_after_exhausting_the_attempt_budget(self, monkeypatch):
        client = self._run_with_client(
            monkeypatch,
            attempts=3,
            side_effect=[
                {"items": [_card(synced=_not_synced("WorkloadNotReady"))]},
                {"items": [_card(synced=_not_synced("WorkloadNotReady"))]},
                {"items": [_card(synced=_not_synced("FetchFailed", "connection reset by peer"))]},
            ],
        )
        with pytest.raises(AgentCardNotReadyError) as ei:
            nodes.analyze_agent(_state())
        # The detail names the state of the LAST look, not an earlier one.
        assert "Synced=False (FetchFailed): connection reset by peer" in ei.value.detail
        assert "ONBOARD_CARD_WAIT_ATTEMPTS" in ei.value.detail
        assert client.list_namespaced_custom_object.call_count == 3  # polled the full budget, then gave up


class TestAnalyzeAgent502:
    def test_k8s_agentcards_list_failure_is_502(self, monkeypatch):
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")
        with pytest.raises(HTTPException) as ei:
            _run(list_exc=RuntimeError("apiserver down"))
        assert ei.value.status_code == 502
        # A real failure, not a race: a plain 502, which the NATS consumer does not nak.
        assert not isinstance(ei.value, AgentCardNotReadyError)
