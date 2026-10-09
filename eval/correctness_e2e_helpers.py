"""Pure-logic helpers for ``test_policy_pipeline_correctness_e2e.py`` — no LLM, no Keycloak, no
``opa``, no I/O. Mirrors ``correctness_scorer.py``'s split from its own test module
(``test_correctness_scorer.py``): logic lives here (no ``test_`` prefix, not collected by
pytest), unit tests live in ``test_correctness_e2e_helpers.py`` (unmarked, runs in the default
fast pass).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

Pair = tuple[str, str]
Row = TypeVar("Row")


def _pairs_from_map(role_to_scopes: dict[str, list[str]]) -> set[Pair]:
    """Flatten a rendered Rego ``{role_name: [scope_name, ...]}`` map (e.g. the inbound
    ``subject_role_allow_scopes``, ``agent_role_scopes``) into a set of ``(role, scope)`` pairs.

    Raises ``TypeError`` when a row is not a list (e.g. the per-target outbound subject maps, which
    ``_pairs_from_target_map`` reads): a flat reader on that shape would score ``(role, target)``
    pairs with no error."""
    for role, scopes in role_to_scopes.items():
        if not isinstance(scopes, list):
            raise TypeError(f"row {role!r} is {type(scopes).__name__}, not a list of scopes: {scopes!r}")
    return {(role, scope) for role, scopes in role_to_scopes.items() for scope in scopes}


def _pairs_from_target_map(
    role_to_targets: dict[str, dict[str, list[str]]], scope_owners: Mapping[str, str]
) -> set[Pair]:
    """Flatten a rendered agent outbound subject map (``subject_role_allow_scopes`` /
    ``subject_role_deny_scopes``) into a set of ``(role, tool)`` pairs.

    These two maps are keyed by role and then by the full target service id (LIM-02):
    ``{role: {target: [tool, ...]}}``. A rule decides only on the target that it is keyed by. The
    truth tables pair a role with a scope name, and in every scenario a scope name has one owner
    (``scope_owners``: scope name -> owner serviceId, as ``_scope_owner`` gives it), so a tool that is
    keyed by its owner gives the ``(role, tool)`` pair.

    A tool that is keyed by any other target (a writer or PCE regression, or a tool with no owner)
    gives ``(role, "<tool>@<target>")``. No truth table has that pair, so a grant there is scored as
    an over-grant, and the owner's ``(role, tool)`` pair, which the deployment does not grant, is
    scored as an under-grant.

    Raises ``TypeError`` when a row is not keyed by target (the old flat shape)."""
    for role, by_target in role_to_targets.items():
        if not isinstance(by_target, dict):
            raise TypeError(f"row {role!r} is {type(by_target).__name__}, not keyed by target: {by_target!r}")
    return {
        (role, tool if scope_owners.get(tool) == target else f"{tool}@{target}")
        for role, by_target in role_to_targets.items()
        for target, tools in by_target.items()
        for tool in tools
    }


def _user_role_rows(role_to_scopes: dict[str, Row], user_roles: set[str]) -> dict[str, Row]:
    """Keep only the rows of a rendered ``subject_role_*_scopes`` map whose role is a genuine user
    role of the scenario. That map's "subject" isn't exclusively human — an agent calling another
    agent (outbound-target, ``agent_role_scopes``) is rendered into the *same*
    ``subject_role_allow_scopes`` document as real user-role grants, since the outbound Rego's
    ``subject_role`` doesn't distinguish the caller's role by human-vs-agent, only by role name.
    Without this filter, every agent-role row double-counts as an ``outbound_subject`` over-grant
    even though it's already correctly counted under ``outbound_target`` — confirmed empirically:
    a real run's every over-grant was exactly its scenario's ``outbound_target`` true positives,
    reappearing here. Mirrors the ``role.name in user_role_names`` discrimination
    ``eval.test_policy_pipeline_eval.grant_sets`` already applies to the PRB's raw rules.

    Also applied to the inbound maps (``subject_role_allow/deny_scopes`` from the *inbound* Rego)
    for the same reason, though it's a no-op there in practice: the inbound Rego has no
    agent-calling-agent concept to begin with, so its ``subject_role`` rows are user roles only —
    nothing gets filtered out. Applying the same call uniformly to both directions, rather than
    conditionally skipping it for inbound, avoids two different call shapes for what is
    conceptually the same "keep user rows only" step.

    The row is kept as it is: a list of scopes (inbound) or a map keyed by target (outbound)."""
    return {role: scopes for role, scopes in role_to_scopes.items() if role in user_roles}


def _accumulate_agent_gates(
    granted: dict[str, set[Pair]],
    denied: dict[str, set[Pair]],
    *,
    inbound_allow: dict[str, list[str]],
    inbound_deny: dict[str, list[str]],
    outbound_subject_allow: dict[str, dict[str, list[str]]],
    outbound_subject_deny: dict[str, dict[str, list[str]]],
    outbound_target_allow: dict[str, list[str]],
    scope_owners: Mapping[str, str],
) -> None:
    """Union one agent's rendered Rego maps into the three top-level gate buckets
    (``inbound``/``outbound_subject``/``outbound_target``), in place. The two outbound subject maps
    are keyed by role and then by target (``_pairs_from_target_map``, which checks each target
    against ``scope_owners``); the other maps are flat. No ``outbound_target_deny`` parameter — the
    outbound Rego generator never renders that map (see
    ``test_policy_pipeline_correctness_e2e.py``'s module docstring)."""
    granted.setdefault("inbound", set()).update(_pairs_from_map(inbound_allow))
    denied.setdefault("inbound", set()).update(_pairs_from_map(inbound_deny))
    granted.setdefault("outbound_subject", set()).update(_pairs_from_target_map(outbound_subject_allow, scope_owners))
    denied.setdefault("outbound_subject", set()).update(_pairs_from_target_map(outbound_subject_deny, scope_owners))
    granted.setdefault("outbound_target", set()).update(_pairs_from_map(outbound_target_allow))
