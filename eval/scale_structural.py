"""Structural-check helpers for the Scale suite (spec: ``docs/evaluation/policy-eval-scale.md``).

Pure logic, no LLM, no I/O of its own -- every function here takes data the suite already has in
hand (a flat ``list[PolicyRule]``, a generated corpus, a usage-metadata dict) and
returns the **concrete offending entities**, never a bare boolean, so a report reader is never left
inferring a failure's cause from a crash message alone (per the spec's no-opaque-failures
discipline -- same convention ``eval/correctness_scorer.py``'s over-/under-grant pair sets and the
consistency suite's ``mismatches`` list already establish). Everything a check produces here is
meant to be handed straight to ``record_property`` and rendered unconditionally, pass or fail.

Four structural properties, per ``docs/evaluation/eval-framework.md`` §5:
    - completeness       -- ``missing_decisions`` (total-corpus PRB-level: every decision ran),
      ``missing_rego`` (e2e). Per-decision fidelity (no hallucinated candidate name) needs no
      helper here: the suite reads the names ``eval.scale_prb.capture_precheck_drops`` recovers
      from production's own ``_precheck`` step, which are hallucinations by definition.
    - no duplication     -- ``duplicate_rule_triples``, over two different inputs depending on
      level (PRB: the raw pre-merge PRB output; e2e: the real persisted post-merge
      ``ServicePolicyModel``, **not** the rendered Rego -- see its own docstring for why).
    - no orphans         -- ``orphaned_scope_names`` is a pure invariant of the **generator's**
      output (never the LLM's), so it is exercised directly, parametrized across several
      ``(size, seed)`` combinations, in ``eval/test_scale_generator.py`` (offline, every ``pytest``
      run) rather than re-checked once per expensive live-LLM Scale run, where it would always
      pass for free (the corpus it would check never changes between generation and the PRB call).
    - latency / cost     -- ``CostSummary``/``summarize_usage``; latency is plain
      ``time.perf_counter()`` wall-clock, timed by the suite itself around whichever call it is
      measuring (no wrapper needed for a single ``start = time.perf_counter(); ...; elapsed =
      time.perf_counter() - start`` pattern).

Completeness/no-duplication are objectively pass/fail, so the suite gates on them (no-orphans gates
too, just offline in ``test_scale_generator.py`` instead of here). Latency/cost have no defined SLA
anywhere in the spec or issue (same as the Correctness suite's still-TBD under-grant threshold) --
they are reported and trended only, never gated.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from aiac.policy.model.models import PolicyRule


def missing_decisions(
    scenario: SimpleNamespace, reasoning_by_scope: dict[str, str], reasoning_by_agent_role: dict[str, str]
) -> list[str]:
    """Total-corpus, PRB-level completeness: every generated agent-inbound-scope, tool/agent-target
    scope, and agent-role decision the corpus defines must actually have run (``best_effort=True``
    guarantees a rejected decision still contributes an entry, so a name missing here means the
    call never happened at all -- an eval-harness bug, not an LLM finding). Returns the exact
    missing decision names, not a count."""
    expected_scopes = {n for agent in scenario.AGENTS.values() for n in agent["inbound_scopes"]}
    expected_scopes |= {n for tool in scenario.TOOLS.values() for n in tool["scopes"]}
    expected_scopes |= {n for agent in scenario.AGENTS.values() for n in agent.get("delegation_scopes", {})}
    expected_roles = {n for agent in scenario.AGENTS.values() for n in agent["roles"]}
    missing_scopes = expected_scopes - set(reasoning_by_scope)
    missing_roles = expected_roles - set(reasoning_by_agent_role)
    return sorted(missing_scopes | missing_roles)


def missing_rego(rego_paths: list[tuple[str, Path]]) -> list[str]:
    """E2e completeness: given a list of ``(label, path)`` pairs (label naming the agent+direction,
    e.g. ``"scale-agent-003/inbound"``), returns the labels whose ``path`` never landed on disk.
    Generalizes ``eval.test_policy_pipeline_eval._provision_scenario``'s existing per-scenario
    missing-rego assertion to an arbitrary label/path list rather than a fixed 8-scenario dict."""
    return sorted(label for label, path in rego_paths if not path.is_file())


def duplicate_rule_triples(rules: list[PolicyRule]) -> list[tuple[str, str, str]]:
    """No-duplication: every ``(role_name, scope_name, effect)`` triple should appear at most once
    in ``rules``. Used two ways by the Scale suite, over two different inputs:

    - **PRB level**, over the raw pre-merge PRB output. Not a merge-engine check -- no merge has
      happened yet, and ``aiac.agent.policy_rules_builder.graph._assemble_rules`` already builds
      each call's rules from a ``set`` of granted/denied names iterated over a fixed, unique
      candidate list, so a single PRB call cannot itself emit a triple twice, and this suite's own
      disjoint user-role/agent-role and inbound-scope/target-scope naming (``eval.scale_generator``)
      makes two *different* calls coincidentally producing the same triple impossible too. What it
      still catches: a bug in *this test's own* candidate-list construction
      (``eval.scale_prb.orchestrate_prb_concurrent``'s ``inbound_scopes``/``target_scopes``/
      ``agent_roles`` lists, or the per-decision fixtures' candidate lists) accidentally listing the
      same scope/role twice, which ``_assemble_rules`` would then faithfully restate twice.
    - **e2e level**, over the real persisted post-``compute_and_apply`` ``ServicePolicyModel``
      rules (``eval.test_policy_pipeline_scale._merged_rules_for``, read in one request via
      ``aiac.policy.model_store.library.api.list_service_policies`` while the Policy Model Store is
      still running) -- the one place a real merge-engine dedup-by-``role.id``+``scope.id``+
      ``effect`` bug could actually show up. **Not** the rendered Rego: ``aiac.pdp.service.policy.
      opa.rego``'s own grouping functions (``_group_rules``/``_group_rules_deprefixed``) always
      de-duplicate a scope list on the way out, so a duplicate that survived a real merge-engine
      bug would already be collapsed before any check reading rendered Rego could ever see it --
      confirmed in review, an earlier version of this e2e check read the rendered Rego instead and
      could never fail.

    Returns every triple that occurred more than once (sorted), not a count."""
    counts = Counter((r.role.name, r.scope.name, r.effect.value) for r in rules)
    return sorted(triple for triple, n in counts.items() if n > 1)


def orphaned_scope_names(scenario: SimpleNamespace) -> list[str]:
    """No-orphans: every scope the corpus defines should be reachable by at least one role in the
    generated ground truth (``INBOUND_PAIRS``/``OUTBOUND_PAIRS``/``OUTBOUND_SUBJECT_PAIRS``) -- a
    scope with zero truth-table grants is a dead entity nobody could ever legitimately reach
    (mirrors the hand-authored corpus's own ``unreachable_resources`` theme, but checked here as an
    invariant on the *generator's* output, which ``eval.scale_generator.generate_total_corpus``
    guarantees via its own repair pass, rather than a deliberate scenario). Pure data check over
    the scenario's own truth -- independent of any PRB call, so a violation here is an eval-harness
    generator defect, never an LLM finding. Exercised directly, parametrized across a few
    ``(size, seed)`` combinations, in ``eval/test_scale_generator.py`` -- the Scale suite's own
    live-LLM tests do not call this (the generated scenario is already fixed by the time a PRB call
    runs, so re-checking it there would always pass for free, never actually catching anything that
    the offline parametrized check wouldn't already have caught first). Returns every orphaned
    scope name (sorted)."""
    owned_names = {n for agent in scenario.AGENTS.values() for n in agent["inbound_scopes"]}
    owned_names |= {n for agent in scenario.AGENTS.values() for n in agent.get("delegation_scopes", {})}
    owned_names |= {n for tool in scenario.TOOLS.values() for n in tool["scopes"]}
    reachable = {s for _, s in scenario.INBOUND_PAIRS}
    reachable |= {s for _, s in scenario.OUTBOUND_PAIRS}
    reachable |= {s for _, s in scenario.OUTBOUND_SUBJECT_PAIRS}
    return sorted(owned_names - reachable)


@dataclass(frozen=True)
class CostSummary:
    """Token-count cost proxy -- never a fabricated dollar figure (no $/token table exists
    anywhere in this repo to justify one). ``coverage`` < 1.0 means the configured LLM endpoint
    didn't surface usage metadata for every call -- reported explicitly rather than silently
    treating a missing usage dict as zero tokens."""

    total_tokens: int
    calls_with_usage: int
    total_calls: int

    @property
    def coverage(self) -> float:
        return 1.0 if self.total_calls == 0 else self.calls_with_usage / self.total_calls


def summarize_usage(usage_by_name: dict[str, dict[str, dict]]) -> CostSummary:
    """Sum ``total_tokens`` across every call's ``usage_metadata`` dict (``{model_name: {...,
    "total_tokens": N, ...}}``, as ``langchain_core.callbacks.usage.get_usage_metadata_callback()``
    produces -- see ``eval.scale_prb``'s module docstring for why it must be captured per-call
    under threads, not around the whole pool). A call with an empty usage dict (the endpoint
    didn't report usage for that call) counts toward ``total_calls`` but not ``calls_with_usage``."""
    total_tokens = 0
    calls_with_usage = 0
    for usage in usage_by_name.values():
        if usage:
            calls_with_usage += 1
            total_tokens += sum(model_usage.get("total_tokens", 0) for model_usage in usage.values())
    return CostSummary(total_tokens=total_tokens, calls_with_usage=calls_with_usage, total_calls=len(usage_by_name))
