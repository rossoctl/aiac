"""Pure-logic helper for ``test_policy_pipeline_eval.py``'s ``_invoke_graph`` — no LLM, no
Keycloak, no ``opa``, no I/O. Mirrors ``correctness_e2e_helpers.py``'s split from its own test
module: logic lives here (no ``test_`` prefix, not collected by pytest), unit tests live in
``test_best_effort_rules.py`` (unmarked, runs in the default fast pass).
"""

from __future__ import annotations

from typing import Any

from aiac.agent.policy_rules_builder.graph import _assemble_rules
from aiac.policy.model.models import PolicyRule


def _best_effort_rules(entity: dict[str, Any], state: dict[str, Any]) -> list[PolicyRule]:
    """Build a best-effort rule set for a proposal the auditor never approved, using the SAME
    assembly the real graph does — ``graph._assemble_rules`` (ALLOW from granted names, then DENY
    from explicit prohibitions, each in candidate order). Reusing the shared helper means this
    replica cannot silently diverge from ``build_role_graph``/``build_scope_graph`` (whose build
    closures are nested and so not directly importable); only the role-focal vs scope-focal
    ``make_rule`` direction is chosen here from ``entity``'s shape.

    Only ever called from ``eval.test_policy_pipeline_eval._invoke_graph`` after catching a
    rejection; the caller is responsible for flagging the result as best-effort (not a real,
    auditor-approved decision) — see ``orchestrate_prb``'s ``best_effort_notes``.
    """
    selected = state.get("selected_names", [])
    denied = state.get("denied_names", [])
    if "role" in entity:  # ROLE_GRAPH shape: role-focal
        role = entity["role"]
        return _assemble_rules(
            entity["scopes"], selected, denied, lambda sc, effect: PolicyRule(role=role, scope=sc, effect=effect)
        )
    # SCOPE_GRAPH shape: scope-focal
    scope = entity["scope"]
    return _assemble_rules(
        entity["roles"], selected, denied, lambda r, effect: PolicyRule(role=r, scope=scope, effect=effect)
    )
