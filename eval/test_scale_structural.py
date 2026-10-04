"""Unit tests for ``eval.scale_structural`` (spec: ``docs/evaluation/policy-eval-scale.md``).

Pure logic, no LLM, no I/O -- unmarked so it runs in the default fast pass.
"""

from __future__ import annotations

from types import SimpleNamespace

from aiac.idp.configuration.models import Role, RoleKind, Scope
from aiac.policy.model.models import PolicyRule, RuleEffect
from eval.scale_generator import generate_total_corpus
from eval.scale_structural import (
    CostSummary,
    duplicate_rego_entries,
    duplicate_rule_triples,
    invalid_selected_names,
    missing_decisions,
    missing_rego,
    orphaned_scope_names,
    summarize_usage,
)


def _role(name: str) -> Role:
    return Role(id=f"role-{name}", name=name, description="", composite=False, kind=RoleKind.USER)


def _scope(name: str) -> Scope:
    return Scope(id=f"scope-{name}", name=name, description="", serviceId="svc")


class TestInvalidSelectedNames:
    def test_none_invalid_when_every_name_is_a_real_candidate(self) -> None:
        assert invalid_selected_names(["a", "b", "c"], selected=["a"], denied=["b"]) == []

    def test_names_the_exact_hallucinated_name(self) -> None:
        assert invalid_selected_names(["a", "b"], selected=["a", "zzz"], denied=[]) == ["zzz"]

    def test_a_non_granted_non_denied_candidate_is_not_flagged(self) -> None:
        # Production's own schema carries only explicit grants/prohibitions -- a candidate in
        # neither list is an ordinary implicit deny, not an incomplete response.
        assert invalid_selected_names(["a", "b", "c"], selected=["a"], denied=[]) == []


class TestMissingDecisions:
    def test_none_missing_when_every_decision_ran(self) -> None:
        corpus = generate_total_corpus(n_services=6, n_roles=3, seed=0)
        ns = corpus.as_namespace()
        scope_names = [n for a in ns.AGENTS.values() for n in a["inbound_scopes"]]
        scope_names += [n for t in ns.TOOLS.values() for n in t["scopes"]]
        role_names = [n for a in ns.AGENTS.values() for n in a["roles"]]
        reasoning_by_scope = {n: "..." for n in scope_names}
        reasoning_by_role = {n: "..." for n in role_names}
        assert missing_decisions(ns, reasoning_by_scope, reasoning_by_role) == []

    def test_names_the_exact_missing_decision(self) -> None:
        corpus = generate_total_corpus(n_services=6, n_roles=3, seed=0)
        ns = corpus.as_namespace()
        scope_names = [n for a in ns.AGENTS.values() for n in a["inbound_scopes"]]
        scope_names += [n for t in ns.TOOLS.values() for n in t["scopes"]]
        role_names = [n for a in ns.AGENTS.values() for n in a["roles"]]
        reasoning_by_scope = {n: "..." for n in scope_names[1:]}  # drop the first one
        reasoning_by_role = {n: "..." for n in role_names}
        missing = missing_decisions(ns, reasoning_by_scope, reasoning_by_role)
        assert missing == [scope_names[0]]


class TestMissingRego:
    def test_none_missing_when_every_path_exists(self, tmp_path) -> None:
        p = tmp_path / "a.rego"
        p.write_text("package x")
        assert missing_rego([("agent-a/inbound", p)]) == []

    def test_names_the_exact_missing_label(self, tmp_path) -> None:
        exists = tmp_path / "a.rego"
        exists.write_text("package x")
        missing = tmp_path / "b.rego"
        assert missing_rego([("agent-a/inbound", exists), ("agent-b/outbound", missing)]) == ["agent-b/outbound"]


class TestDuplicateRuleTriples:
    def test_no_duplicates(self) -> None:
        rules = [PolicyRule(role=_role("r1"), scope=_scope("s1"), effect=RuleEffect.ALLOW)]
        assert duplicate_rule_triples(rules) == []

    def test_names_the_exact_duplicated_triple(self) -> None:
        rules = [
            PolicyRule(role=_role("r1"), scope=_scope("s1"), effect=RuleEffect.ALLOW),
            PolicyRule(role=_role("r1"), scope=_scope("s1"), effect=RuleEffect.ALLOW),
        ]
        assert duplicate_rule_triples(rules) == [("r1", "s1", "Allow")]

    def test_same_pair_different_effect_is_not_a_duplicate(self) -> None:
        rules = [
            PolicyRule(role=_role("r1"), scope=_scope("s1"), effect=RuleEffect.ALLOW),
            PolicyRule(role=_role("r1"), scope=_scope("s1"), effect=RuleEffect.DENY),
        ]
        assert duplicate_rule_triples(rules) == []


class TestDuplicateRegoEntries:
    def test_no_duplicates(self) -> None:
        assert duplicate_rego_entries({"role-a": ["scope-1", "scope-2"]}) == []

    def test_names_the_exact_key_and_repeated_candidate(self) -> None:
        assert duplicate_rego_entries({"role-a": ["scope-1", "scope-1"]}) == [("role-a", "scope-1")]

    def test_only_the_repeated_entry_is_flagged_not_the_whole_key(self) -> None:
        assert duplicate_rego_entries({"role-a": ["scope-1", "scope-1", "scope-2"]}) == [("role-a", "scope-1")]

    def test_different_keys_are_independent(self) -> None:
        assert duplicate_rego_entries({"role-a": ["scope-1"], "role-b": ["scope-1"]}) == []

    def test_empty_map_has_no_duplicates(self) -> None:
        assert duplicate_rego_entries({}) == []


class TestOrphanedScopeNames:
    def test_generated_corpus_has_no_orphans_across_many_seeds(self) -> None:
        # The generator's repair pass must hold even where independent-density sampling would
        # otherwise leave a scope with zero grants by chance -- check several seeds/sizes, not
        # just one, since the failure mode is inherently probabilistic without the repair pass.
        # This invariant is a pure property of the *generator's* output (never of what an LLM
        # did), so it's exercised directly here, offline, every ``pytest`` run -- the live-LLM
        # Scale suite's own structural tests do not re-check it (see this function's own
        # docstring for why that would always pass for free).
        for n_services, n_roles in [(30, 4), (2, 1), (37, 3)]:
            for seed in range(10):
                corpus = generate_total_corpus(n_services=n_services, n_roles=n_roles, seed=seed)
                assert orphaned_scope_names(corpus.as_namespace()) == [], f"n_services={n_services} seed={seed}"

    def test_names_the_exact_orphaned_scope(self) -> None:
        ns = SimpleNamespace(
            AGENTS={"a1": {"inbound_scopes": {"orphan-scope": "d"}, "delegation_scopes": {}, "roles": {}}},
            TOOLS={},
            INBOUND_PAIRS=[],
            OUTBOUND_PAIRS=[],
            OUTBOUND_SUBJECT_PAIRS=[],
        )
        assert orphaned_scope_names(ns) == ["orphan-scope"]

    def test_a_reachable_scope_is_not_flagged(self) -> None:
        ns = SimpleNamespace(
            AGENTS={"a1": {"inbound_scopes": {"reachable-scope": "d"}, "delegation_scopes": {}, "roles": {}}},
            TOOLS={},
            INBOUND_PAIRS=[("some-role", "reachable-scope")],
            OUTBOUND_PAIRS=[],
            OUTBOUND_SUBJECT_PAIRS=[],
        )
        assert orphaned_scope_names(ns) == []


class TestSummarizeUsage:
    def test_sums_total_tokens_across_calls(self) -> None:
        usage_by_name = {
            "a": {"model-x": {"total_tokens": 100}},
            "b": {"model-x": {"total_tokens": 50}},
        }
        summary = summarize_usage(usage_by_name)
        assert summary == CostSummary(total_tokens=150, calls_with_usage=2, total_calls=2)
        assert summary.coverage == 1.0

    def test_a_call_with_no_usage_lowers_coverage_without_being_silently_zero(self) -> None:
        usage_by_name = {"a": {"model-x": {"total_tokens": 100}}, "b": {}}
        summary = summarize_usage(usage_by_name)
        assert summary.total_tokens == 100
        assert summary.calls_with_usage == 1
        assert summary.total_calls == 2
        assert summary.coverage == 0.5

    def test_empty_input(self) -> None:
        summary = summarize_usage({})
        assert summary == CostSummary(total_tokens=0, calls_with_usage=0, total_calls=0)
        assert summary.coverage == 1.0
