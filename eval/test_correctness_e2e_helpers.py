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
    _accumulate_agent_gates,
    _pairs_from_map,
    _pairs_from_target_map,
    _user_role_rows,
)
from eval.correctness_scorer import score_scenario

# The owner (serviceId) of each scope in these tests, as ``_scope_owner`` gives it for a scenario.
SCOPE_OWNERS = {
    "scope-x": "repo-tool",
    "scope-y": "repo-tool",
    "scope-z": "tracker-tool",
    "tool-scope-repo-read": "repo-tool",
    "tool-scope-repo-write": "repo-tool",
    "tool-scope-issue-read": "tracker-tool",
}


def test_pairs_from_map_flattens_role_scope_map() -> None:
    got = _pairs_from_map({"role-a": ["scope-x", "scope-y"], "role-b": ["scope-x"]})
    assert got == {("role-a", "scope-x"), ("role-a", "scope-y"), ("role-b", "scope-x")}


def test_pairs_from_map_empty_map_yields_no_pairs() -> None:
    assert _pairs_from_map({}) == set()


def test_pairs_from_map_rejects_a_map_keyed_by_target() -> None:
    """A flat-map reader that gets the per-target shape must fail, not score ``(role, target)``."""
    with pytest.raises(TypeError, match="role-a"):
        _pairs_from_map({"role-a": {"repo-tool": ["scope-x"]}})


# The agent outbound subject maps are keyed by role and then by the full target service id (LIM-02):
# ``{role: {target: [tool, ...]}}``. ``_pairs_from_target_map`` flattens the target level first, and
# checks that each tool is keyed by the target that owns it.


def test_pairs_from_target_map_flattens_the_target_level() -> None:
    got = _pairs_from_target_map(
        {
            "role-a": {"repo-tool": ["scope-x", "scope-y"], "tracker-tool": ["scope-z"]},
            "role-b": {"repo-tool": ["scope-x"]},
        },
        SCOPE_OWNERS,
    )
    assert got == {("role-a", "scope-x"), ("role-a", "scope-y"), ("role-a", "scope-z"), ("role-b", "scope-x")}


def test_pairs_from_target_map_empty_map_yields_no_pairs() -> None:
    assert _pairs_from_target_map({}, SCOPE_OWNERS) == set()
    assert _pairs_from_target_map({"role-a": {}}, SCOPE_OWNERS) == set()


def test_pairs_from_target_map_rejects_the_flat_shape() -> None:
    """A rendered outbound subject map without the target level (the old shape) must fail."""
    with pytest.raises(TypeError, match="role-a"):
        _pairs_from_target_map({"role-a": ["scope-x"]}, SCOPE_OWNERS)


def test_pairs_from_target_map_names_the_target_of_a_tool_that_it_does_not_own() -> None:
    """A tool keyed under another target decides there, not on its owner: the pair names that
    target, so it can never match the ``(role, scope)`` pair of the truth table."""
    got = _pairs_from_target_map({"role-a": {"tracker-tool": ["scope-x"]}}, SCOPE_OWNERS)
    assert got == {("role-a", "scope-x@tracker-tool")}


def test_pairs_from_target_map_names_the_target_of_a_tool_with_no_owner() -> None:
    got = _pairs_from_target_map({"role-a": {"repo-tool": ["scope-unknown"]}}, SCOPE_OWNERS)
    assert got == {("role-a", "scope-unknown@repo-tool")}


def test_user_role_rows_drops_agent_role_rows() -> None:
    rows = {
        "user-role-inventory-manager": ["tool-scope-inventory-check"],
        "agent-role-inventory-operations": ["tool-scope-inventory-check"],
    }
    got = _user_role_rows(rows, user_roles={"user-role-inventory-manager"})
    assert got == {"user-role-inventory-manager": ["tool-scope-inventory-check"]}


def test_user_role_rows_empty_map_yields_empty_map() -> None:
    assert _user_role_rows({}, user_roles={"user-role-x"}) == {}


def test_user_role_rows_keeps_the_target_level_of_a_user_row() -> None:
    rows = {
        "user-role-developer": {"repo-tool": ["tool-scope-repo-read"]},
        "agent-role-repo-operations": {"repo-tool": ["tool-scope-repo-read"]},
    }
    got = _user_role_rows(rows, user_roles={"user-role-developer"})
    assert got == {"user-role-developer": {"repo-tool": ["tool-scope-repo-read"]}}


def test_accumulate_agent_gates_classifies_into_three_buckets() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate_agent_gates(
        granted,
        denied,
        inbound_allow={"user-role-developer": ["agent-scope-repo-access"]},
        inbound_deny={"user-role-devops": ["agent-scope-repo-access"]},
        outbound_subject_allow={"user-role-developer": {"repo-tool": ["tool-scope-repo-read"]}},
        outbound_subject_deny={"user-role-tester": {"repo-tool": ["tool-scope-repo-write"]}},
        outbound_target_allow={"agent-role-repo-operations": ["tool-scope-repo-read"]},
        scope_owners=SCOPE_OWNERS,
    )

    assert granted == {
        "inbound": {("user-role-developer", "agent-scope-repo-access")},
        "outbound_subject": {("user-role-developer", "tool-scope-repo-read")},
        "outbound_target": {("agent-role-repo-operations", "tool-scope-repo-read")},
    }
    assert denied == {
        "inbound": {("user-role-devops", "agent-scope-repo-access")},
        "outbound_subject": {("user-role-tester", "tool-scope-repo-write")},
    }
    assert "outbound_target" not in denied  # never rendered — see module docstring


def test_accumulate_agent_gates_unions_across_multiple_agents() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate_agent_gates(
        granted,
        denied,
        inbound_allow={"user-role-developer": ["agent-scope-repo-access"]},
        inbound_deny={},
        outbound_subject_allow={},
        outbound_subject_deny={},
        outbound_target_allow={},
        scope_owners=SCOPE_OWNERS,
    )
    _accumulate_agent_gates(
        granted,
        denied,
        inbound_allow={"user-role-tester": ["agent-scope-tracker-access"]},
        inbound_deny={},
        outbound_subject_allow={},
        outbound_subject_deny={},
        outbound_target_allow={},
        scope_owners=SCOPE_OWNERS,
    )

    assert granted["inbound"] == {
        ("user-role-developer", "agent-scope-repo-access"),
        ("user-role-tester", "agent-scope-tracker-access"),
    }


def test_accumulate_agent_gates_scores_the_outbound_subject_tools_of_every_target() -> None:
    """Each target's tools give ``(role, tool)`` pairs; a target id is never scored as a scope."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}

    _accumulate_agent_gates(
        granted,
        denied,
        inbound_allow={},
        inbound_deny={},
        outbound_subject_allow={
            "user-role-developer": {"repo-tool": ["tool-scope-repo-read"], "tracker-tool": ["tool-scope-issue-read"]},
        },
        outbound_subject_deny={"user-role-devops": {"repo-tool": ["tool-scope-repo-read"]}},
        outbound_target_allow={},
        scope_owners=SCOPE_OWNERS,
    )

    assert granted["outbound_subject"] == {
        ("user-role-developer", "tool-scope-repo-read"),
        ("user-role-developer", "tool-scope-issue-read"),
    }
    assert denied["outbound_subject"] == {("user-role-devops", "tool-scope-repo-read")}


def test_accumulate_agent_gates_rejects_a_flat_outbound_subject_map() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    with pytest.raises(TypeError, match="not keyed by target"):
        _accumulate_agent_gates(
            granted,
            denied,
            inbound_allow={},
            inbound_deny={},
            outbound_subject_allow={"user-role-developer": ["tool-scope-repo-read"]},
            outbound_subject_deny={},
            outbound_target_allow={},
            scope_owners=SCOPE_OWNERS,
        )


def test_a_grant_on_a_target_that_does_not_own_the_tool_is_an_over_grant() -> None:
    """A writer or PCE regression that keys a grant under the wrong target id grants the tool there
    and not on its owner. The scorer must fail the zero-tolerance gate, not score it as correct."""
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    _accumulate_agent_gates(
        granted,
        denied,
        inbound_allow={},
        inbound_deny={},
        outbound_subject_allow={"user-role-developer": {"tracker-tool": ["tool-scope-repo-read"]}},
        outbound_subject_deny={},
        outbound_target_allow={},
        scope_owners=SCOPE_OWNERS,
    )

    score = score_scenario(
        "wrong-target",
        granted,
        denied,
        expected={"outbound_subject": {("user-role-developer", "tool-scope-repo-read")}},
    )

    assert score.passed is False
    assert score.over_grants == {"outbound_subject": {("user-role-developer", "tool-scope-repo-read@tracker-tool")}}
    assert score.under_grants == {"outbound_subject": {("user-role-developer", "tool-scope-repo-read")}}


def test_a_deny_on_a_target_that_does_not_own_the_tool_is_not_scored_as_the_owner_deny() -> None:
    granted: dict[str, set[tuple[str, str]]] = {}
    denied: dict[str, set[tuple[str, str]]] = {}
    _accumulate_agent_gates(
        granted,
        denied,
        inbound_allow={},
        inbound_deny={},
        outbound_subject_allow={},
        outbound_subject_deny={"user-role-devops": {"tracker-tool": ["tool-scope-repo-write"]}},
        outbound_target_allow={},
        scope_owners=SCOPE_OWNERS,
    )
    assert denied["outbound_subject"] == {("user-role-devops", "tool-scope-repo-write@tracker-tool")}
