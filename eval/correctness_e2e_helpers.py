"""Pure-logic helpers for ``test_policy_pipeline_correctness_e2e.py`` — no LLM, no Keycloak, no
``opa``, no I/O. Mirrors ``correctness_scorer.py``'s split from its own test module
(``test_correctness_scorer.py``): logic lives here (no ``test_`` prefix, not collected by
pytest), unit tests live in ``test_correctness_e2e_helpers.py`` (unmarked, runs in the default
fast pass).
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from typing import TypeVar

Pair = tuple[str, str]
Row = TypeVar("Row")


def _pairs_from_map(role_to_scopes: dict[str, list[str]]) -> set[Pair]:
    """Flatten a rendered Rego ``{role_name: [scope_name, ...]}`` map (e.g. the inbound
    ``subject_role_allow_scopes``, ``source_role_allow_scopes``) into a set of ``(role, scope)``
    pairs.

    Raises ``TypeError`` when a row is not a list (for example a map keyed by role and then by
    target): a flat reader on that shape would score ``(role, target)`` pairs with no error."""
    for role, scopes in role_to_scopes.items():
        if not isinstance(scopes, list):
            raise TypeError(f"row {role!r} is {type(scopes).__name__}, not a list of scopes: {scopes!r}")
    return {(role, scope) for role, scopes in role_to_scopes.items() for scope in scopes}


def _user_role_rows(role_to_scopes: dict[str, Row], user_roles: set[str]) -> dict[str, Row]:
    """Keep only the rows of a rendered ``subject_role_*_scopes`` map whose role is a genuine user
    role of the scenario. Mirrors the ``role.name in user_role_names`` discrimination
    ``eval.test_policy_pipeline_eval.grant_sets`` already applies to the PRB's raw rules.

    The inbound projection puts only user roles in the subject maps (an agent role goes to the
    ``source_role_*_scopes`` maps), so this filter is a guard: it removes nothing from a correct
    render. Without it, a render that puts an agent-role row in a subject map would score that row
    as an ``outbound_subject`` over-grant. The row is kept as it is."""
    return {role: scopes for role, scopes in role_to_scopes.items() if role in user_roles}


def _owned_pairs(pairs: set[Pair], *, service_id: str, scope_owners: Mapping[str, str]) -> set[Pair]:
    """Name the service in each pair of ``pairs`` whose scope ``service_id`` does not own.

    A row on a scope of ``service_id`` (``scope_owners`` maps the scope to ``service_id``) gives the
    ``(role, scope)`` pair. A row on a scope of another service, or on a scope with no owner (a
    writer or PCE regression that puts the rule in the wrong inbound), gives
    ``(role, "<scope>@<service_id>")``. No truth table has that pair, so a grant there is scored as
    an over-grant, and the owner's ``(role, scope)`` pair, which the deployment does not grant, is
    scored as an under-grant."""
    return {
        (role, scope if scope_owners.get(scope) == service_id else f"{scope}@{service_id}") for role, scope in pairs
    }


def _on_target_scopes(
    pairs: set[Pair], *, service_id: str, scope_owners: Mapping[str, str], target_scopes: Set[str]
) -> set[Pair]:
    """The pairs of ``pairs`` that ``outbound_subject`` scores: a pair on a target scope, and every
    pair on a scope that ``service_id`` does not own (named by ``_owned_pairs``, so it is never
    dropped). A user row on an ordinary agent inbound scope is an ``inbound`` pair, so this bucket
    drops it."""
    return _owned_pairs(
        {(role, scope) for role, scope in pairs if scope in target_scopes or scope_owners.get(scope) != service_id},
        service_id=service_id,
        scope_owners=scope_owners,
    )


def _accumulate_service_gates(
    granted: dict[str, set[Pair]],
    denied: dict[str, set[Pair]],
    *,
    service_id: str,
    is_agent: bool,
    subject_allow: dict[str, list[str]],
    subject_deny: dict[str, list[str]],
    source_allow: dict[str, list[str]],
    source_deny: dict[str, list[str]],
    target_scopes: Set[str],
    scope_owners: Mapping[str, str],
) -> None:
    """Union the rendered inbound Rego maps of one service (``service_id``, agent or tool) into the
    three top-level gate buckets (``inbound``/``outbound_subject``/``outbound_target``), in place.
    Each map is flat: the callee's own CR is the key, so a map is keyed by role only.

    * ``inbound`` — every row of the subject maps of an agent's inbound.
    * ``outbound_subject`` — the rows of the subject maps on a target scope (``target_scopes``: the
      tool scopes and the agent delegation scopes).
    * ``outbound_target`` — every row of the source maps. The truth tables pair an agent role with a
      target scope only, so a source row on an ordinary agent inbound scope is an over-grant: the
      agent inbound is agent-level (D26a), so that row lets the calling agent call the agent. The
      inbound renders both ``source_role_allow_scopes`` and ``source_role_deny_scopes``, so this
      gate has a deny side.

    Each row is checked against the owner of its scope (``scope_owners``, as ``_scope_owner`` gives
    it). A row on a scope that ``service_id`` does not own gives ``(role, "<scope>@<service_id>")``
    in each bucket that it goes to (``_owned_pairs``), and an outbound bucket keeps it whatever its
    scope is.

    A delegation scope is a scope of an agent, so its subject rows go to ``inbound`` and to
    ``outbound_subject``."""
    owners = {"service_id": service_id, "scope_owners": scope_owners}
    outbound = {**owners, "target_scopes": target_scopes}
    subject_allow_pairs = _pairs_from_map(subject_allow)
    subject_deny_pairs = _pairs_from_map(subject_deny)
    if is_agent:
        granted.setdefault("inbound", set()).update(_owned_pairs(subject_allow_pairs, **owners))
        denied.setdefault("inbound", set()).update(_owned_pairs(subject_deny_pairs, **owners))
    granted.setdefault("outbound_subject", set()).update(_on_target_scopes(subject_allow_pairs, **outbound))
    denied.setdefault("outbound_subject", set()).update(_on_target_scopes(subject_deny_pairs, **outbound))
    granted.setdefault("outbound_target", set()).update(_owned_pairs(_pairs_from_map(source_allow), **owners))
    denied.setdefault("outbound_target", set()).update(_owned_pairs(_pairs_from_map(source_deny), **owners))
