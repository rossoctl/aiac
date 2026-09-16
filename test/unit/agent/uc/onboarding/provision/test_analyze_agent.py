"""Unit tests for the Service Provision `analyze_agent` node (UC1, issue 4.3).

Kubernetes access (AgentCard CRs) is mocked via the `_custom_objects` seam.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from aiac.agent.uc.onboarding.provision import kube, nodes
from aiac.agent.uc.onboarding.provision.state import OnboardingProvisionState, Trigger

NS = "team-a"
WORKLOAD = "weather"


def _state():
    return OnboardingProvisionState(trigger=Trigger(entity_id="svc-123"), namespace=NS, workload_name=WORKLOAD)


def _card(name=WORKLOAD, skills=None):
    """An AgentCard CR as the operator syncs it: the fetched A2A card lives under ``status.card``,
    and each skill carries a machine ``id`` (a stable identifier) plus a display ``name``."""
    return {"metadata": {"name": name}, "status": {"card": {"skills": skills or []}}}


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
            "status": {"card": {"skills": [{"id": "forecast", "name": "F", "description": "d"}]}},
        }
        provision = _run(items=[card])["service_provision"]

        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.forecast"]
        assert "derived from AgentCard: 1 skills" == provision.reasoning


class TestAnalyzeAgentLegacyFallback:
    def test_no_agentcard_yields_default_access_scope_and_partial_reasoning(self):
        provision = _run(items=[])["service_provision"]

        # No-skills fallback: a default operator role mirrors the default access scope.
        assert [r.name for r in provision.roles] == [f"{WORKLOAD}.access"]
        assert provision.roles[0].description == "Default access scope"
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.access"]
        assert provision.scopes[0].description == "Default access scope"
        assert "partial: no AgentCard found" in provision.reasoning

    def test_agentcard_present_but_no_name_match_is_legacy_fallback(self):
        provision = _run(items=[_card(name="other-agent", skills=[{"id": "x", "name": "X", "description": "y"}])])[
            "service_provision"
        ]
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.access"]
        assert "partial: no AgentCard found" in provision.reasoning

    def test_agentcard_present_but_no_synced_skills_is_fallback(self):
        # The CR exists but its ``status.card`` has not synced any skills yet (e.g. the operator has
        # not fetched the A2A card): fall back to a default access scope rather than provision none.
        provision = _run(items=[_card(skills=[])])["service_provision"]
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.access"]
        assert "no synced skills" in provision.reasoning


class TestAnalyzeAgentCardSyncRace:
    """The operator syncs the fetched A2A card onto ``status.card.skills`` only AFTER the agent pod is
    Ready — later than the Keycloak-registration event that triggers onboarding — so this node can run
    while the skills are still empty. A briefly-empty skill list is a transient race, re-polled a
    bounded number of times before falling back to a default access scope (unlike a genuinely
    card-less legacy deployment, which converges on the fallback only after the budget is spent)."""

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

    def test_skills_synced_late_are_retried_then_succeed(self, monkeypatch):
        client = self._run_with_client(
            monkeypatch,
            attempts=3,
            side_effect=[
                {"items": [_card(skills=[])]},  # operator has not synced the A2A card onto status yet
                {"items": [_card(skills=[{"id": "forecast", "name": "F", "description": "Get forecast"}])]},  # synced
            ],
        )
        provision = nodes.analyze_agent(_state())["service_provision"]
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.forecast"]
        assert "derived from AgentCard: 1 skills" == provision.reasoning
        assert client.list_namespaced_custom_object.call_count == 2  # re-polled once, then succeeded

    def test_never_synced_falls_back_after_exhausting_the_attempt_budget(self, monkeypatch):
        client = self._run_with_client(monkeypatch, attempts=3, return_value={"items": [_card(skills=[])]})
        provision = nodes.analyze_agent(_state())["service_provision"]
        assert [s.name for s in provision.scopes] == [f"{WORKLOAD}.access"]
        assert "no synced skills" in provision.reasoning
        assert client.list_namespaced_custom_object.call_count == 3  # polled the full budget, then gave up


class TestAnalyzeAgent502:
    def test_k8s_agentcards_list_failure_is_502(self, monkeypatch):
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")
        with pytest.raises(HTTPException) as ei:
            _run(list_exc=RuntimeError("apiserver down"))
        assert ei.value.status_code == 502
