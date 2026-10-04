"""Unit tests for ``eval.scale_generator`` (spec: ``docs/evaluation/policy-eval-scale.md``).

Pure logic, no LLM, no I/O -- unmarked so it runs in the default fast pass, same convention as
``test_correctness_scorer.py``/``test_best_effort_rules.py``.
"""

from __future__ import annotations

import pytest

from eval.scale_generator import (
    FOCAL_ROLE_NAME,
    FOCAL_SCOPE_NAME,
    generate_per_decision,
    generate_total_corpus,
)


def _inbound_scope_names(corpus) -> set[str]:
    return {n for agent in corpus.AGENTS.values() for n in agent["inbound_scopes"]}


def _target_scope_names(corpus) -> set[str]:
    return {n for tool in corpus.TOOLS.values() for n in tool["scopes"]}


def _agent_role_names(corpus) -> set[str]:
    return {n for agent in corpus.AGENTS.values() for n in agent["roles"]}


class TestGenerateTotalCorpus:
    def test_deterministic_for_same_seed(self) -> None:
        a = generate_total_corpus(n_services=20, n_roles=4, seed=7)
        b = generate_total_corpus(n_services=20, n_roles=4, seed=7)
        assert a == b

    def test_different_seed_yields_different_pairs(self) -> None:
        a = generate_total_corpus(n_services=20, n_roles=4, seed=1)
        b = generate_total_corpus(n_services=20, n_roles=4, seed=2)
        assert a.INBOUND_PAIRS != b.INBOUND_PAIRS or a.OUTBOUND_PAIRS != b.OUTBOUND_PAIRS

    def test_service_and_role_counts(self) -> None:
        corpus = generate_total_corpus(n_services=100, n_roles=10, seed=0)
        assert len(corpus.AGENTS) + len(corpus.TOOLS) == 100
        assert len(corpus.USER_ROLES) == 10
        # Every agent/tool has exactly one scope, one agent role per agent -- "modest" per-decision
        # candidate lists is a property of *this* dimension, unlike generate_per_decision.
        assert all(len(a["inbound_scopes"]) == 1 and len(a["roles"]) == 1 for a in corpus.AGENTS.values())
        assert all(len(t["scopes"]) == 1 for t in corpus.TOOLS.values())

    def test_every_pair_references_a_real_name(self) -> None:
        corpus = generate_total_corpus(n_services=30, n_roles=6, seed=3)
        user_roles = set(corpus.USER_ROLES)
        agent_roles = _agent_role_names(corpus)
        inbound_scopes = _inbound_scope_names(corpus)
        target_scopes = _target_scope_names(corpus)

        for role, scope in corpus.INBOUND_PAIRS:
            assert role in user_roles
            assert scope in inbound_scopes
        for role, scope in corpus.OUTBOUND_SUBJECT_PAIRS:
            assert role in user_roles
            assert scope in target_scopes
        for role, scope in corpus.OUTBOUND_PAIRS:
            assert role in agent_roles
            assert scope in target_scopes

    def test_every_scope_has_exactly_one_owner(self) -> None:
        corpus = generate_total_corpus(n_services=30, n_roles=6, seed=3)
        owners: dict[str, int] = {}
        for agent in corpus.AGENTS.values():
            for name in agent["inbound_scopes"]:
                owners[name] = owners.get(name, 0) + 1
        for tool in corpus.TOOLS.values():
            for name in tool["scopes"]:
                owners[name] = owners.get(name, 0) + 1
        assert set(owners.values()) == {1}, "every generated scope must have exactly one owner"

    def test_policy_text_has_one_grant_line_per_pair(self) -> None:
        corpus = generate_total_corpus(n_services=20, n_roles=4, seed=9)
        total_pairs = len(corpus.INBOUND_PAIRS) + len(corpus.OUTBOUND_SUBJECT_PAIRS) + len(corpus.OUTBOUND_PAIRS)
        grant_lines = [line for line in corpus.policy_text.splitlines() if line.startswith("Role '")]
        assert len(grant_lines) == total_pairs

    def test_as_namespace_exposes_every_field(self) -> None:
        corpus = generate_total_corpus(n_services=10, n_roles=2, seed=0)
        ns = corpus.as_namespace()
        for field_name in ("AGENTS", "TOOLS", "USER_ROLES", "USERS", "USER_PASSWORD", "REALM_DEFAULT"):
            assert hasattr(ns, field_name)

    def test_raises_clearly_on_zero_roles_instead_of_crashing_in_the_repair_pass(self) -> None:
        with pytest.raises(ValueError, match="n_roles"):
            generate_total_corpus(n_services=10, n_roles=0, seed=0)

    def test_raises_clearly_on_fewer_than_two_services_instead_of_crashing_in_the_repair_pass(self) -> None:
        # n_services=1 -> n_agents = 1 // 2 = 0 -> no agent role for the repair pass to pick from.
        with pytest.raises(ValueError, match="n_services"):
            generate_total_corpus(n_services=1, n_roles=2, seed=0)


class TestGeneratePerDecision:
    def test_deterministic_for_same_seed(self) -> None:
        a = generate_per_decision(n_candidates=50, seed=5)
        b = generate_per_decision(n_candidates=50, seed=5)
        assert a == b

    def test_candidate_counts(self) -> None:
        corpus = generate_per_decision(n_candidates=100, seed=0)
        assert len(corpus.scope_candidate_roles) == 100
        assert len(corpus.role_candidate_scopes) == 100
        assert len(set(corpus.scope_candidate_roles)) == 100  # no duplicate candidate names
        assert len(set(corpus.role_candidate_scopes)) == 100

    def test_granted_is_a_subset_of_candidates(self) -> None:
        corpus = generate_per_decision(n_candidates=100, seed=0)
        assert corpus.scope_granted_roles <= set(corpus.scope_candidate_roles)
        assert corpus.role_granted_scopes <= set(corpus.role_candidate_scopes)

    def test_granted_is_neither_empty_nor_everything(self) -> None:
        # A degenerate all-or-nothing grant set would make the correctness check vacuous.
        corpus = generate_per_decision(n_candidates=100, seed=0)
        assert 0 < len(corpus.scope_granted_roles) < 100
        assert 0 < len(corpus.role_granted_scopes) < 100

    def test_granted_is_never_empty_even_at_small_sizes(self) -> None:
        # At small n_candidates, independent per-candidate density sampling can legitimately draw
        # zero grants by chance -- the repair pass must prevent that across many seeds, not just
        # the default size/seed above.
        for seed in range(20):
            corpus = generate_per_decision(n_candidates=10, seed=seed)
            assert corpus.scope_granted_roles, f"seed={seed}"
            assert corpus.role_granted_scopes, f"seed={seed}"

    def test_policy_text_names_the_focal_entity_and_one_line_per_grant(self) -> None:
        corpus = generate_per_decision(n_candidates=40, seed=2)
        assert FOCAL_SCOPE_NAME in corpus.scope_policy_text
        assert FOCAL_ROLE_NAME in corpus.role_policy_text
        scope_grant_lines = [line for line in corpus.scope_policy_text.splitlines() if line.startswith("Role '")]
        role_grant_lines = [line for line in corpus.role_policy_text.splitlines() if line.startswith("Role '")]
        assert len(scope_grant_lines) == len(corpus.scope_granted_roles)
        assert len(role_grant_lines) == len(corpus.role_granted_scopes)
        # Every granted line names the fixed focal scope (subject side varies) ...
        assert all(line.endswith(f"Scope '{FOCAL_SCOPE_NAME}'.") for line in scope_grant_lines)
        # ... and every granted line for the role direction starts from the fixed focal role.
        assert all(line.startswith(f"Role '{FOCAL_ROLE_NAME}'") for line in role_grant_lines)

    def test_raises_clearly_on_zero_candidates_instead_of_crashing_in_the_repair_pass(self) -> None:
        with pytest.raises(ValueError, match="n_candidates"):
            generate_per_decision(n_candidates=0, seed=0)
