"""Unit tests for ``correctness_e2e_helpers.py`` (spec: ``docs/evaluation/
policy-eval-correctness-e2e.md``).

Pure-logic, unmarked — runs in the default fast pass (``testpaths`` already includes ``eval/``),
mirroring ``test_correctness_scorer.py``'s status as a separate, unmarked file. No LLM, no
Keycloak, no ``opa``, no fixtures beyond plain dicts/sets — the module-level
``pytestmark = pytest.mark.eval`` in ``test_policy_pipeline_correctness_e2e.py`` would otherwise
wrongly sweep these up and exclude them from the default pass.
"""

from __future__ import annotations

import pytest

from eval.correctness_e2e_helpers import (
    _accumulate_service_gates,
    _pairs_from_map,
    _user_role_rows,
)
from eval.correctness_scorer import score_scenario

# The target scopes of these tests: the tool scopes and the agent delegation scopes.
TARGET_SCOPES = {"tool-scope-repo-read", "tool-scope-repo-write", "agent-scope-broker"}

# The owner (serviceId) of each scope in these tests, as ``_scope_owner`` gives it for a scenario.
SCOPE_OWNERS = {
    "tool-scope-repo-read": "repo-tool",
    "tool-scope-repo-write": "repo-tool",
    "tool-scope-issue-read": "tracker-tool",
    "agent-scope-broker": "broker-agent",
    "agent-scope-repo-access": "repo-agent",
    "agent-scope-tracker-access": "tracker-agent",
}


def test_pairs_from_map_flattens_role_scope_map() -> None:
    got = _pairs_from_map({"role-a": ["scope-x", "scope-y"], "role-b": ["scope-x"]})
    assert got == {("role-a", "scope-x"), ("role-a", "scope-y"), ("role-b", "scope-x")}


def test_pairs_from_map_empty_map_yields_no_pairs() -> None:
    assert _pairs_from_map({}) == set()


def test_pairs_from_map_rejects_a_map_keyed_by_target() -> None:
    """A flat-map reader that gets a map keyed by target must fail, not score ``(role, target)``."""
    with pytest.raises(TypeError, match="role-a"):
        _pairs_from_map({"role-a": {"repo-tool": ["scope-x"]}})


def test_user_role_rows_drops_agent_role_rows() -> None:
    rows = {
        "user-role-inventory-manager": ["tool-scope-inventory-check"],
        "agent-role-inventory-operations": ["tool-scope-inventory-check"],
    }
    got = _user_role_rows(rows, user_roles={"user-role-inventory-manager"})
    assert got == {"user-role-inventory-manager": ["tool-scope-inventory-check"]}


def test_user_role_rows_empty_map_yields_empty_map() -> None:
    assert _user_role_rows({}, user_roles={"user-role-x"}) == {}


def _accumulate(granted: dict, denied: dict, *, service_id: str, is_agent: bool, **maps: dict) -> None:
    _accumulate_service_gates(
        granted,
        denied,
        service_id=service_id,
        is_agent=is_agent,
        subject_allow=maps.get("subject_allow", {}),
        subject_deny=maps.get("subject_deny", {}),
        source_allow=maps.get("source_allow", {}),
        source_deny=maps.get("source_deny", {}),
        target_scopes=TARGET_SCOPES,
        scope_owners=SCOPE_OWNERS,
    )


def test_a_tool_inbound_gives_the_two_outbound_gates() -> None:
    """A tool inbound has the user gate (``outbound_subject``) and the calling-agent gate
    (``outbound_target``), each with an allow side and a deny side. A tool gives no ``inbound`` pair."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate(
        granted,
        denied,
        service_id="repo-tool",
        is_agent=False,
        subject_allow={"user-role-developer": ["tool-scope-repo-read"]},
        subject_deny={"user-role-tester": ["tool-scope-repo-write"]},
        source_allow={"agent-role-repo-operations": ["tool-scope-repo-read"]},
        source_deny={"agent-role-restricted": ["tool-scope-repo-write"]},
    )

    assert granted == {
        "outbound_subject": {("user-role-developer", "tool-scope-repo-read")},
        "outbound_target": {("agent-role-repo-operations", "tool-scope-repo-read")},
    }
    assert denied == {
        "outbound_subject": {("user-role-tester", "tool-scope-repo-write")},
        "outbound_target": {("agent-role-restricted", "tool-scope-repo-write")},
    }


def test_an_agent_inbound_gives_the_inbound_gate() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate(
        granted,
        denied,
        service_id="repo-agent",
        is_agent=True,
        subject_allow={"user-role-developer": ["agent-scope-repo-access"]},
        subject_deny={"user-role-devops": ["agent-scope-repo-access"]},
    )

    assert granted["inbound"] == {("user-role-developer", "agent-scope-repo-access")}
    assert denied["inbound"] == {("user-role-devops", "agent-scope-repo-access")}
    assert granted["outbound_subject"] == set()
    assert granted["outbound_target"] == set()


def test_a_delegation_scope_of_an_agent_gives_the_inbound_and_the_outbound_gates() -> None:
    """A delegation scope is a scope of the agent that owns it: its user rows are in the agent's own
    inbound, and they are the user gate of a call to that agent through another agent."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate(
        granted,
        denied,
        service_id="broker-agent",
        is_agent=True,
        subject_allow={"user-role-shipment-coordinator": ["agent-scope-broker"]},
        source_allow={"agent-role-dispatcher": ["agent-scope-broker"]},
    )

    assert granted == {
        "inbound": {("user-role-shipment-coordinator", "agent-scope-broker")},
        "outbound_subject": {("user-role-shipment-coordinator", "agent-scope-broker")},
        "outbound_target": {("agent-role-dispatcher", "agent-scope-broker")},
    }


def test_a_source_row_on_an_agent_inbound_scope_is_not_an_outbound_target_pair() -> None:
    """``outbound_target`` pairs an agent role with a target scope only, as ``grant_sets`` does."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate(
        granted,
        denied,
        service_id="repo-agent",
        is_agent=True,
        source_allow={"agent-role-dispatcher": ["agent-scope-repo-access"]},
    )

    assert granted["outbound_target"] == set()


def test_the_gates_union_across_services() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    repo_access = {"user-role-developer": ["agent-scope-repo-access"]}
    tracker_access = {"user-role-tester": ["agent-scope-tracker-access"]}
    _accumulate(granted, denied, service_id="repo-agent", is_agent=True, subject_allow=repo_access)
    _accumulate(granted, denied, service_id="tracker-agent", is_agent=True, subject_allow=tracker_access)
    repo_read = {"agent-role-a": ["tool-scope-repo-read"]}
    repo_write = {"agent-role-b": ["tool-scope-repo-write"]}
    _accumulate(granted, denied, service_id="repo-tool", is_agent=False, source_allow=repo_read)
    _accumulate(granted, denied, service_id="repo-tool", is_agent=False, source_allow=repo_write)

    assert granted["inbound"] == {
        ("user-role-developer", "agent-scope-repo-access"),
        ("user-role-tester", "agent-scope-tracker-access"),
    }
    assert granted["outbound_target"] == {
        ("agent-role-a", "tool-scope-repo-read"),
        ("agent-role-b", "tool-scope-repo-write"),
    }


def test_a_map_keyed_by_target_is_rejected() -> None:
    with pytest.raises(TypeError, match="user-role-developer"):
        _accumulate(
            {},
            {},
            service_id="repo-tool",
            is_agent=False,
            subject_allow={"user-role-developer": {"team1/repo-tool": ["tool-scope-repo-read"]}},
        )


def test_a_grant_in_the_inbound_of_a_service_that_does_not_own_the_scope_is_an_over_grant() -> None:
    """A writer or PCE regression that puts a grant in the inbound of the wrong service grants the
    scope there and not on its owner. The scorer must fail the zero-tolerance gate, not score it as
    correct."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    _accumulate(
        granted,
        denied,
        service_id="tracker-tool",
        is_agent=False,
        subject_allow={"user-role-developer": ["tool-scope-repo-read"]},
    )

    score = score_scenario(
        "wrong-service",
        granted,
        denied,
        expected={"outbound_subject": {("user-role-developer", "tool-scope-repo-read")}},
    )

    assert score.passed is False
    assert score.over_grants == {"outbound_subject": {("user-role-developer", "tool-scope-repo-read@tracker-tool")}}
    assert score.under_grants == {"outbound_subject": {("user-role-developer", "tool-scope-repo-read")}}


def test_a_deny_in_the_inbound_of_a_service_that_does_not_own_the_scope_is_not_scored_as_the_owner_deny() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    _accumulate(
        granted,
        denied,
        service_id="tracker-tool",
        is_agent=False,
        subject_deny={"user-role-devops": ["tool-scope-repo-write"]},
        source_deny={"agent-role-restricted": ["tool-scope-repo-write"]},
    )

    assert denied["outbound_subject"] == {("user-role-devops", "tool-scope-repo-write@tracker-tool")}
    assert denied["outbound_target"] == {("agent-role-restricted", "tool-scope-repo-write@tracker-tool")}


def test_a_scope_with_no_owner_names_the_service() -> None:
    """A row on a scope that no service of the scenario owns is not dropped: it names the service."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    _accumulate(
        granted,
        denied,
        service_id="repo-tool",
        is_agent=False,
        subject_allow={"user-role-developer": ["tool-scope-unknown"]},
        source_allow={"agent-role-a": ["tool-scope-unknown"]},
    )

    assert granted["outbound_subject"] == {("user-role-developer", "tool-scope-unknown@repo-tool")}
    assert granted["outbound_target"] == {("agent-role-a", "tool-scope-unknown@repo-tool")}


def test_an_agent_scope_in_the_inbound_of_another_agent_is_an_inbound_over_grant() -> None:
    """The ``inbound`` bucket checks the owner too: an agent scope in the inbound of another agent
    names that agent, in ``inbound`` and (because the scope is not owned there) in
    ``outbound_subject``."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    _accumulate(
        granted,
        denied,
        service_id="tracker-agent",
        is_agent=True,
        subject_allow={"user-role-developer": ["agent-scope-repo-access"]},
    )

    assert granted["inbound"] == {("user-role-developer", "agent-scope-repo-access@tracker-agent")}
    assert granted["outbound_subject"] == {("user-role-developer", "agent-scope-repo-access@tracker-agent")}
