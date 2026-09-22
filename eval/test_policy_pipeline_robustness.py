"""PRB robustness suite — invariance and sensitivity families, both mechanical and semantic tiers
(spec: ``docs/evaluation/eval-framework.md`` §4, ``docs/evaluation/policy-eval-robustness-
consistency.md``; semantic-tier sensitivity and both tiers' trend-log wiring: #2467).

Four independent checks, each its own test function/metric — never blended into one pass/fail
(spec §4's explicit requirement):

1. ``test_prb_invariant_to_mechanical_perturbation`` — **invariance family, mechanical tier**. A
   runtime, deterministic (no RNG) transform (``_mangle_text``) bundling whitespace/newline noise,
   casing noise, and punctuation noise, applied to the policy text and every candidate ``Role``/
   ``Scope`` description, plus candidate-list reordering (``_reordered``). Ground truth is
   *identical* to the original scenario's — pass = output unchanged.
2. ``test_prb_invariant_to_semantic_perturbation`` — **invariance family, semantic tier**. A
   hand-authored, meaning-preserving reworded sibling scenario module from
   ``eval/scenarios_perturbed/``. Same ground truth, same pass criterion as (1), kept as its own
   test/metric so a semantic-tier failure never gets attributed to the mechanical-tier metrics.
3. ``test_prb_sensitive_to_mechanical_edit`` — **sensitivity family, mechanical tier**. A
   deterministic, programmatically-applied minimal edit (``SENSITIVITY_EDITS``) that *deliberately*
   changes meaning — negation, a role swap, an added exception clause, or a restriction word
   ("only"/"just") inserted to narrow an existing grant — so ground truth is *deliberately
   different* from the original. Pass = the output changes to exactly the new, edited ground
   truth. Without this family, "robust" and "broken" (a model that ignores the policy text and
   always emits the same grants) would be indistinguishable — see spec §4.
4. ``test_prb_sensitive_to_semantic_perturbation`` — **sensitivity family, semantic tier** (#2467).
   A hand-authored, meaning-*changing* reworded sibling from ``eval/scenarios_perturbed/
   scenario_eval_<name>_sensitive_perturbed.py`` — the same edit_type and truth delta as (3)'s
   ``SENSITIVITY_EDITS`` entry for that scenario (reused directly via ``SEMANTIC_SENSITIVITY_
   SCENARIOS``), expressed as full paraphrase (e.g. "solely"/"exclusively") instead of a literal
   word insertion. Every one is signed off in ``eval/scenarios_perturbed/SIGNOFF.md`` (enforced by
   ``eval/test_semantic_signoff.py``) before entering the corpus, per spec §4's human-sign-off
   requirement for semantic perturbations.

All four call ``orchestrate_prb(..., best_effort=True)``: a mangled/reworded/edited input can read,
to the auditor, as a genuine contradiction against a coarser-grained inbound scope's own
description (a partial grant/prohibit within one bundled scope) — best-effort falls back to the
last-proposed (never-approved) rule instead of aborting the whole scenario, same rationale and
mechanism as the two correctness suites, so every scenario always scores instead of reporting
"unavailable." A rejection is itself informative (the PRB failing closed rather than cleanly
re-deciding), not a harness bug — all four ``record_property("best_effort_notes", ...)`` and print
a summary line when non-empty, same convention as the correctness suites.

All four variants' grant sets are compared against a truth table via ``truth``
(``eval.test_policy_pipeline_eval``) — for (1)/(2) the *original* scenario's truth, for (3)/(4)
that truth with the edit's known delta applied. Scoped to the PRB's raw output only — see
``test_policy_pipeline_consistency.py`` for the same no-Keycloak rationale, which applies here
unchanged.

Compared against the **ALLOW-effect-only** grant set (``_record_scoring``'s return value, built via
``grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.ALLOW])``), not the raw,
effect-blind ``grant_sets(scenario, rules)``. A ``PolicyRule`` carries an explicit ``effect``
(``ALLOW`` or ``DENY``) — a pair the PRB correctly, explicitly *denies* is a real, present rule, so
comparing the effect-blind set would make a correct explicit-deny response indistinguishable from
an unchanged grant and silently fail a case that should pass (confirmed live: ``empty_descriptions``
initially failed the sensitivity check this way despite the PRB denying every pair it should have).

Each of the four ``record_property``s a boolean (``"invariant"``/``"sensitive"``) plus, via the
shared ``_record_scoring`` helper, ``"true_positives"``/``"denied_total"`` — the same raw counts
``test_prb_correctness`` records. ``eval/conftest.py``'s ``_write_trend_log`` pools each family/tier
across the run into its *own* committed trend-log row — ``suite="robustness_mechanical_invariance"``
for (1), ``robustness_semantic_invariance`` for (2), ``robustness_mechanical_sensitivity`` for (3),
``robustness_semantic_sensitivity`` for (4) — carrying that row's own precision/recall/
denial_precision (``eval.trend_log.pool_correctness_metrics``, the same pooling the two
Correctness suites use, so the resulting charts are directly comparable to them: one measuring
performance against the *original* inputs, the others against *deliberately edited/reworded*
inputs) plus that row's own pass/fail rate (``invariance_rate``/``sensitivity_rate`` — spec §9),
never blended across rows.

All four additionally ``record_property`` (via the shared ``_record_scoring`` helper), purely for
the Markdown report: what the perturbation/edit actually was (``"perturbation"``), the full
expected and actual (ALLOW-only) per-gate grant lists (``"expected_grants"``/``"actual_grants"``),
and the same precision/recall/denial-precision/over-grants/under-grants/incorrectly-denied
breakdown the two correctness suites report (``eval.correctness_scorer.score_scenario``).
``eval/conftest.py``'s ``_render_metrics_block`` renders all of it, dispatching on the same
``"precision"``/``"recall"`` property presence the correctness suites already use.

Run (needs LLM_BASE_URL/LLM_MODEL/LLM_API_KEY exported; no Keycloak/opa needed):
    .venv/bin/pytest eval/test_policy_pipeline_robustness.py \
        -m eval -v
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

pytestmark = pytest.mark.eval

HERE = Path(__file__).resolve().parent  # aiac/eval/
REPO_ROOT = HERE.parent  # -> aiac/
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*``/``eval.*`` resolves
sys.path.insert(0, str(SRC))  # so ``import aiac.*`` resolves

from aiac.policy.model.models import PolicyRule, RuleEffect  # noqa: E402
from eval.correctness_scorer import score_scenario  # noqa: E402
from eval.prb_direct import build_roles_and_scopes  # noqa: E402
from eval.scenarios_digested import digested_policy_path  # noqa: E402
from eval.scenarios_perturbed import (  # noqa: E402
    scenario_eval_agent_delegation_perturbed,
    scenario_eval_agent_delegation_sensitive_perturbed,
    scenario_eval_ambiguous_clause_perturbed,
    scenario_eval_ambiguous_clause_sensitive_perturbed,
    scenario_eval_baseline_perturbed,
    scenario_eval_baseline_sensitive_perturbed,
    scenario_eval_confusable_agents_perturbed,
    scenario_eval_confusable_agents_sensitive_perturbed,
    scenario_eval_empty_descriptions_perturbed,
    scenario_eval_empty_descriptions_sensitive_perturbed,
    scenario_eval_misleading_descriptions_perturbed,
    scenario_eval_misleading_descriptions_sensitive_perturbed,
    scenario_eval_unreachable_resources_perturbed,
    scenario_eval_unreachable_resources_sensitive_perturbed,
    scenario_eval_wildcard_grant_perturbed,
    scenario_eval_wildcard_grant_sensitive_perturbed,
)
from eval.test_policy_pipeline_eval import (  # noqa: E402
    SCENARIOS,
    grant_sets,
    orchestrate_prb,
    truth,
)
from test.system.launcher import require_env_or_skip  # noqa: E402

PERTURBED_SCENARIOS: dict[str, ModuleType] = {
    "baseline": scenario_eval_baseline_perturbed,
    "agent_delegation": scenario_eval_agent_delegation_perturbed,
    "unreachable_resources": scenario_eval_unreachable_resources_perturbed,
    "ambiguous_clause": scenario_eval_ambiguous_clause_perturbed,
    "wildcard_grant": scenario_eval_wildcard_grant_perturbed,
    "misleading_descriptions": scenario_eval_misleading_descriptions_perturbed,
    "confusable_agents": scenario_eval_confusable_agents_perturbed,
    "empty_descriptions": scenario_eval_empty_descriptions_perturbed,
}

# Semantic tier, sensitivity family (#2467): hand-authored, meaning-CHANGING reworded siblings —
# each realizes the exact same edit type and truth delta as its SENSITIVITY_EDITS counterpart
# below, expressed as a full natural paraphrase instead of a literal find/replace. Every one of
# these, and their paired policy .md, has a recorded human sign-off in
# eval/scenarios_perturbed/SIGNOFF.md (enforced by eval/test_semantic_signoff.py) before entering
# this corpus, per spec §4.
SEMANTIC_SENSITIVITY_SCENARIOS: dict[str, ModuleType] = {
    "baseline": scenario_eval_baseline_sensitive_perturbed,
    "agent_delegation": scenario_eval_agent_delegation_sensitive_perturbed,
    "unreachable_resources": scenario_eval_unreachable_resources_sensitive_perturbed,
    "ambiguous_clause": scenario_eval_ambiguous_clause_sensitive_perturbed,
    "wildcard_grant": scenario_eval_wildcard_grant_sensitive_perturbed,
    "misleading_descriptions": scenario_eval_misleading_descriptions_sensitive_perturbed,
    "confusable_agents": scenario_eval_confusable_agents_sensitive_perturbed,
    "empty_descriptions": scenario_eval_empty_descriptions_sensitive_perturbed,
}


def _mangle_text(text: str) -> str:
    """One deterministic pure-function bundle of whitespace/newline noise, casing noise (every
    3rd word forced upper, every 5th forced lower, by word index), and punctuation noise (spaced
    out sentence/list punctuation). Deterministic by construction (word index, not randomness) so
    re-running this suite is itself perfectly reproducible."""
    words = text.split(" ")
    noisy_words = []
    for i, word in enumerate(words):
        if word and i % 3 == 0:
            word = word.upper()
        elif word and i % 5 == 0:
            word = word.lower()
        noisy_words.append(word)
    mangled = "  ".join(noisy_words)
    mangled = mangled.replace(".", " . ").replace(",", " , ")
    mangled = mangled.replace("\n", "\n\n   ")
    return mangled


def _reverse_dict(d: dict) -> dict:
    return dict(reversed(list(d.items())))


def _reordered(scenario: ModuleType) -> SimpleNamespace:
    """A view of ``scenario`` with every candidate list's dict-iteration order reversed
    (``USER_ROLES``, ``AGENTS`` and each agent's ``inbound_scopes``/``delegation_scopes``/``roles``,
    ``TOOLS`` and each tool's ``scopes``), so ``orchestrate_prb`` sees candidates in reordered
    order with zero production-code changes. Name-keyed pair lists are order-insensitive
    (``grant_sets``/``truth`` compare them as sets) so they're copied through unchanged."""
    agents = {
        agent_id: {
            **agent,
            "inbound_scopes": _reverse_dict(agent["inbound_scopes"]),
            "delegation_scopes": _reverse_dict(agent.get("delegation_scopes", {})),
            "roles": _reverse_dict(agent["roles"]),
        }
        for agent_id, agent in reversed(list(scenario.AGENTS.items()))
    }
    tools = {
        tool_id: {**tool, "scopes": _reverse_dict(tool["scopes"])}
        for tool_id, tool in reversed(list(scenario.TOOLS.items()))
    }
    return SimpleNamespace(
        REALM_DEFAULT=scenario.REALM_DEFAULT,
        POLICY_FILE=scenario.POLICY_FILE,
        AGENTS=agents,
        TOOLS=tools,
        USERS=dict(scenario.USERS),
        USER_PASSWORD=scenario.USER_PASSWORD,
        USER_ROLES=_reverse_dict(scenario.USER_ROLES),
        INBOUND_PAIRS=list(scenario.INBOUND_PAIRS),
        OUTBOUND_PAIRS=list(scenario.OUTBOUND_PAIRS),
        OUTBOUND_SUBJECT_PAIRS=list(scenario.OUTBOUND_SUBJECT_PAIRS),
    )


def _record_scoring(
    record_property,
    scenario: ModuleType,
    scenario_name: str,
    rules: list[PolicyRule],
    expected: dict[str, set[tuple[str, str]]],
    perturbation: str,
) -> dict[str, set[tuple[str, str]]]:
    """Record, for the Markdown report (``eval/conftest.py``), exactly what a reader would need to
    judge a robustness case without opening the source: what changed (``perturbation``), what was
    expected, what came back, and the same effect-aware precision/recall/denial-precision/over-
    grants/under-grants/incorrectly-denied breakdown the correctness suites report
    (``eval.correctness_scorer.score_scenario``, scored from ``rules`` split by
    ``RuleEffect.ALLOW``/``DENY``).

    Also records ``true_positives``/``denied_total`` (the same two raw counts
    ``test_prb_correctness`` records), purely so ``eval/conftest.py``'s ``_write_trend_log`` can
    pool this scenario into an aggregate precision/recall/denial_precision the same way it pools
    the two Correctness suites (``eval.trend_log.pool_correctness_metrics``) -- giving each
    robustness family its own precision/recall/denial_precision trend, directly comparable in
    shape to the Correctness charts: one measuring the PRB against the *original* inputs
    (invariance), the other against *deliberately edited* inputs (sensitivity).

    Returns the ALLOW-only grant set (``granted``) so the caller's own exact-match
    ``invariant``/``sensitive`` check compares against the *same* set the metrics above are
    computed from. This matters: a ``PolicyRule`` carries an explicit ``effect`` (``ALLOW`` or
    ``DENY``, not merely "this pair exists") — a pair the PRB correctly, explicitly *denies* is
    a real, present ``PolicyRule``, so comparing against the raw ``grant_sets(scenario, rules)``
    (which classifies a pair as present regardless of effect) would make a correct explicit-deny
    response indistinguishable from an unchanged grant, silently failing a case that should pass.
    """
    granted = grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.ALLOW])
    denied = grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.DENY])
    score = score_scenario(scenario_name, granted, denied, expected)
    record_property("precision", score.precision)
    record_property("recall", score.recall)
    record_property("denial_precision", score.denial_precision)
    record_property("true_positives", score.true_positive_count)
    record_property("denied_total", score.denied_total)
    record_property("over_grants", {g: sorted(p) for g, p in score.over_grants.items()})
    record_property("under_grants", {g: sorted(p) for g, p in score.under_grants.items()})
    record_property("incorrectly_denied", {g: sorted(p) for g, p in score.incorrectly_denied.items()})
    record_property("perturbation", perturbation)
    record_property("expected_grants", {g: sorted(p) for g, p in expected.items() if p})
    record_property("actual_grants", {g: sorted(p) for g, p in granted.items() if p})
    return granted


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_prb_invariant_to_mechanical_perturbation(
    scenario_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record_property
) -> None:
    """Invariance family, mechanical tier: the PRB's grant decision is unchanged under a
    mechanical perturbation of the policy text, candidate descriptions, and candidate-list order
    (whitespace/casing/punctuation noise + reordering — all deterministic, no RNG), compared
    against the *original* scenario's truth table. Calls ``orchestrate_prb(..., best_effort=True)``:
    the mangling can itself manufacture a coarse-scope contradiction (e.g. forcing casing on a
    role's description can make a partial grant/prohibit read as a genuine conflict) — best-effort
    falls back to the last-proposed, never-approved rule instead of aborting the whole scenario, so
    every scenario still scores; see ``test_prb_sensitive_to_mechanical_edit``'s docstring for the
    same mechanism and rationale."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    scenario = SCENARIOS[scenario_name]
    want = truth(scenario)

    roles, scopes = build_roles_and_scopes(scenario)
    mech_roles = {
        name: role.model_copy(update={"description": _mangle_text(role.description or "")})
        for name, role in roles.items()
    }
    mech_scopes = {
        name: scope.model_copy(update={"description": _mangle_text(scope.description or "")})
        for name, scope in scopes.items()
    }
    mech_policy_text = _mangle_text(digested_policy_path(scenario).read_text(encoding="utf-8"))
    mech_policy_path = tmp_path / f"{scenario_name}.mechanical.md"
    mech_policy_path.write_text(mech_policy_text)
    monkeypatch.setenv("AIAC_POLICY_FILE", str(mech_policy_path))
    mech_rules, _, _, best_effort_notes = orchestrate_prb(
        mech_roles, mech_scopes, _reordered(scenario), best_effort=True
    )
    granted = _record_scoring(
        record_property,
        scenario,
        scenario_name,
        mech_rules,
        want,
        perturbation=(
            "Mechanical tier: deterministic whitespace/casing/punctuation noise (_mangle_text) applied to "
            "the policy text and every candidate Role/Scope description, plus full reversal of every "
            f"candidate list's dict order (_reordered). Mangled policy text (truncated): "
            f"{mech_policy_text[:300]!r}"
        ),
    )

    mismatches = {gate: want[gate] ^ granted[gate] for gate in want if want[gate] != granted[gate]}
    invariant = not mismatches
    record_property("invariant", invariant)
    record_property("best_effort_notes", best_effort_notes)
    if best_effort_notes:
        print(f"[invariant-mechanical] {scenario_name}: best_effort_notes={best_effort_notes}")
    assert invariant, (
        f"PRB was not invariant to mechanical perturbation for scenario '{scenario_name}': mismatches={mismatches}"
    )


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_prb_invariant_to_semantic_perturbation(
    scenario_name: str, monkeypatch: pytest.MonkeyPatch, record_property
) -> None:
    """Invariance family, semantic tier: the PRB's grant decision is unchanged under a
    hand-authored, meaning-preserving reworded sibling scenario (``eval/scenarios_perturbed/``),
    compared against the *original* scenario's truth table. Wired into its own trend-log row
    (``suite="robustness_semantic_invariance"``, #2467) — see this module's docstring. Calls
    ``orchestrate_prb(..., best_effort=True)`` for the same reason as the mechanical tier and the
    sensitivity test: a rejected decision still scores via the last-proposed, never-approved rule
    instead of aborting the whole scenario."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    scenario = SCENARIOS[scenario_name]
    want = truth(scenario)

    perturbed = PERTURBED_SCENARIOS[scenario_name]
    p_roles, p_scopes = build_roles_and_scopes(perturbed)
    monkeypatch.setenv("AIAC_POLICY_FILE", str(digested_policy_path(perturbed)))
    sem_rules, _, _, best_effort_notes = orchestrate_prb(p_roles, p_scopes, perturbed, best_effort=True)
    granted = _record_scoring(
        record_property,
        scenario,
        scenario_name,
        sem_rules,
        want,
        perturbation=(
            f"Semantic tier: hand-reworded sibling scenario module `{perturbed.__name__}` — different "
            "phrasing throughout every AGENTS/TOOLS/USER_ROLES description and the paired policy .md "
            "text; every name-keyed field identical to the original."
        ),
    )

    mismatches = {gate: want[gate] ^ granted[gate] for gate in want if want[gate] != granted[gate]}
    invariant = not mismatches
    record_property("invariant", invariant)
    record_property("best_effort_notes", best_effort_notes)
    if best_effort_notes:
        print(f"[invariant-semantic] {scenario_name}: best_effort_notes={best_effort_notes}")
    assert invariant, (
        f"PRB was not invariant to semantic perturbation for scenario '{scenario_name}': mismatches={mismatches}"
    )


Pair = tuple[str, str]


@dataclass(frozen=True)
class SensitivityEdit:
    """One deterministic, meaning-changing minimal edit for a scenario's sensitivity-family
    mechanical-tier matched pair (spec §4). ``policy_find``/``policy_replace`` are applied to the
    scenario's policy ``.md`` text after whitespace-normalization (``" ".join(text.split())`` —
    sidesteps exact line-wrap matching, harmless since the PRB's real input is the flat text, not
    rendered markdown). ``description_edits`` maps a ``Role``/``Scope`` name (a key in
    ``build_roles_and_scopes``'s returned dicts) to a ``(find, replace)`` pair applied to that
    entity's own ``.description`` — kept in lockstep with the policy-text edit so the edited
    scenario's text and descriptions stay mutually consistent, the same way the original
    scenario's were co-authored to agree. ``removed``/``added`` are the per-gate ``(role, scope)``
    pairs that flip relative to ``truth(scenario)`` as a result of the edit — the new expected
    truth a correctly-sensitive PRB must reproduce exactly."""

    edit_type: str  # "negation" | "role_swap" | "exception_clause" | "restriction_word"
    policy_find: str
    policy_replace: str
    description_edits: dict[str, tuple[str, str]]
    removed: dict[str, set[Pair]] = field(default_factory=dict)
    added: dict[str, set[Pair]] = field(default_factory=dict)


# One matched pair per primary correctness scenario (spec §4's acceptance bar). Every
# restriction_word/exception_clause edit narrows *which roles* are eligible for an entire
# existing scope ("only testers may access...", "everyone except front desk staff may
# read...") rather than narrowing *which sub-capability* of one already-bundled scope a role
# keeps ("testers may only read..." while the inbound scope's own description still says
# "reading and updating") — the latter reliably tripped the PRB auditor's contradiction check
# in live testing (a coarse scope bundling two capabilities, one now partially forbidden, reads
# to the auditor as a genuine grant-and-prohibit conflict rather than a clean re-decision — see
# the "coarse-scope" Testing Decision below). A role-eligibility edit removes or adds a role's
# *entire* relationship to a scope, so there is nothing partial for the auditor to reconcile.
# Coverage: negation x5, role_swap x1, restriction_word x1, exception_clause x1 — includes the
# required restriction-word ("only") case, distinct from the negation/role-swap cases, per issue
# #2466's explicit acceptance criterion; role-level phrasing needs >= 2 roles sharing the same
# scope, so restriction_word/exception_clause land on the two scenarios that have that (baseline,
# misleading_descriptions) and every single-role scenario uses negation (a full revoke) instead.
SENSITIVITY_EDITS: dict[str, SensitivityEdit] = {
    "baseline": SensitivityEdit(
        edit_type="restriction_word",
        # Against the DIGESTED policy, each (role, resource, operation) is already its own explicit
        # direct-grant line -- dropping developers' tracker-read line and replacing the two tester
        # lines with an explicit "only" narrowing keeps this edit's defining textual signal (the
        # literal word "only") even though the digested-policy language itself forbids exclusive
        # language in authored corpus text (see docs/specs/digested-policy.md) -- the mechanical
        # tier deliberately tests the PRB's raw reaction to that word, not well-formed digested
        # grammar (the semantic tier's paraphrase, "solely"/"exclusively", is #2467's analog).
        # Testers already had full read+write, so this narrows eligibility without changing
        # testers' own grant -- a pure revoke for developers (`removed` below), no `added` either
        # side.
        policy_find=(
            "- Developers may read the Issue tracker. - Testers may read the Issue tracker. "
            "- Testers may write the Issue tracker."
        ),
        policy_replace="Only testers may read and write the Issue tracker.",
        description_edits={
            "user-role-developer": (
                "who develops the source codebase (writing and maintaining code) and fixes code "
                "defects reported in the issue tracker; works primarily in source and consults "
                "issues for defect reports.",
                "who develops the source codebase: writing and maintaining code. Works exclusively "
                "in source, with no involvement in the issue tracker.",
            ),
        },
        removed={
            "inbound": {("user-role-developer", "agent-scope-triager")},
            "outbound_subject": {("user-role-developer", "tool-scope-tracker-read")},
        },
    ),
    "agent_delegation": SensitivityEdit(
        edit_type="role_swap",
        # Against the digested policy, the swap flips which role's initiate_customs_clearance_on_
        # behalf statement is Allow vs. Deny -- the two dock-worker manifest lines sit between them
        # in the digested text and are carried through unchanged, included only for contiguity.
        policy_find=(
            "- Allow: Subjects in role shipment-coordinator may perform "
            "initiate_customs_clearance_on_behalf on resources of type shipment when the access "
            "attribute coordinated_process = true. - Allow: Subjects in role dock-worker may perform "
            "create_manifest on resources of type shipment_manifest. - Allow: Subjects in role "
            "dock-worker may perform update_manifest on resources of type shipment_manifest. - Deny: "
            "Subjects in role dock-worker may not perform initiate_customs_clearance_on_behalf on "
            "resources of type shipment."
        ),
        policy_replace=(
            "- Deny: Subjects in role shipment-coordinator may not perform "
            "initiate_customs_clearance_on_behalf on resources of type shipment. - Allow: Subjects "
            "in role dock-worker may perform create_manifest on resources of type shipment_manifest. "
            "- Allow: Subjects in role dock-worker may perform update_manifest on resources of type "
            "shipment_manifest. - Allow: Subjects in role dock-worker may perform "
            "initiate_customs_clearance_on_behalf on resources of type shipment when the access "
            "attribute coordinated_process = true."
        ),
        description_edits={
            "user-role-shipment-coordinator": (
                "authorized to create and update shipment manifests through the dispatch agent, and to "
                "have customs clearance carried out on the shipment's behalf as part of that coordinated "
                "process.",
                "authorized to create and update shipment manifests for day-to-day loading and "
                "unloading; not authorized to have customs clearance carried out on the shipment's "
                "behalf.",
            ),
            "user-role-dock-worker": (
                "authorized to create and update shipment manifests through the dispatch agent for "
                "day-to-day loading and unloading; not authorized to have customs clearance carried out "
                "on the shipment's behalf.",
                "authorized to create and update shipment manifests, and to have customs clearance "
                "carried out on the shipment's behalf as part of a coordinated process.",
            ),
        },
        removed={"outbound_subject": {("user-role-shipment-coordinator", "agent-scope-broker")}},
        added={"outbound_subject": {("user-role-dock-worker", "agent-scope-broker")}},
    ),
    "unreachable_resources": SensitivityEdit(
        edit_type="negation",
        policy_find=(
            "- Allow: front desk clerks may read patient records. - Allow: front desk clerks may "
            "update patient records."
        ),
        policy_replace=(
            "- Deny: front desk clerks may not read patient records at all. - Deny: front desk "
            "clerks may not update patient records at all."
        ),
        description_edits={
            "user-role-front-desk-clerk": (
                "authorized to schedule appointments and read and update patient records through the "
                "intake agent; not involved in billing or insurance verification.",
                "NOT authorized to schedule appointments or access patient records at all. Not "
                "involved in billing or insurance verification.",
            ),
            # outbound_target (agent-role-receptionist -> tool-scope-records-*) is decided by its
            # own ROLE_GRAPH call over agent-role-receptionist's own description, which the clerk's
            # negation edit never touches -- assuming that revoke cascades here on the strength of
            # "they name the same worker" gives a faithful PRB (correctly reading its own
            # unedited, still-granting description) no textual reason to revoke, and no way to
            # pass. Edited directly instead, so the removed outbound_target pairs below are
            # grounded in real edited text, not an inferred cascade.
            "agent-role-receptionist": (
                "Covers read and write access to patient records — reading and updating patient record contents.",
                "Covers no access to patient records.",
            ),
        },
        removed={
            "inbound": {("user-role-front-desk-clerk", "agent-scope-receptionist")},
            "outbound_subject": {
                ("user-role-front-desk-clerk", "tool-scope-records-read"),
                ("user-role-front-desk-clerk", "tool-scope-records-write"),
            },
            "outbound_target": {
                ("agent-role-receptionist", "tool-scope-records-read"),
                ("agent-role-receptionist", "tool-scope-records-write"),
            },
        },
    ),
    "ambiguous_clause": SensitivityEdit(
        edit_type="negation",
        policy_find=(
            "1) EnrollmentAdvisor may read enrollment_record - Condition: access.purpose = advisory "
            "- Condition: enrollment_record.time_scope = current"
        ),
        policy_replace="1) EnrollmentAdvisor may not read enrollment_record, under any condition, for any purpose.",
        description_edits={
            "user-role-enrollment-advisor": (
                "Enrollment Advisor — authorized to access enrollment information for advising purposes.",
                "Enrollment Advisor — NOT authorized to access enrollment information.",
            ),
        },
        removed={
            "inbound": {("user-role-enrollment-advisor", "agent-scope-registrar")},
            "outbound_subject": {("user-role-enrollment-advisor", "tool-scope-enrollment-status")},
        },
    ),
    "wildcard_grant": SensitivityEdit(
        edit_type="negation",
        policy_find=(
            "- Allow: Subjects = Inventory managers; Operations = all inventory operations; "
            "Resources = inventory resources; Conditions = none."
        ),
        policy_replace=(
            "- Deny: Subjects = Inventory managers; Operations = all inventory operations; "
            "Resources = inventory resources; Conditions = none."
        ),
        description_edits={
            "user-role-inventory-manager": (
                "authorized to perform all inventory operations: checking stock levels, adjusting "
                "counts, and placing reorders.",
                "NOT authorized to perform any inventory operations.",
            ),
        },
        removed={
            "inbound": {("user-role-inventory-manager", "agent-scope-stocker")},
            "outbound_subject": {
                ("user-role-inventory-manager", "tool-scope-inventory-check"),
                ("user-role-inventory-manager", "tool-scope-inventory-adjust"),
                ("user-role-inventory-manager", "tool-scope-inventory-reorder"),
            },
        },
    ),
    "misleading_descriptions": SensitivityEdit(
        edit_type="exception_clause",
        # Keeps the literal "except" exclusivity signal (mechanical tier's defining trait, same
        # rationale as baseline's literal "only" above) while still landing as an explicit Deny,
        # matching the digested corpus's own Allow/Deny convention.
        policy_find=(
            "- Allow: Front desk staff may read reservation details. - Allow: Front desk staff may read guest notes."
        ),
        policy_replace=(
            "- Deny: Front desk staff may not read reservation details or guest notes -- everyone "
            "except front desk staff may read reservation details and guest notes."
        ),
        description_edits={
            "user-role-front-desk-staff": (
                "authorized to read reservation details and guest notes through the guest-services agent.",
                "NOT authorized to read reservation details or guest notes at all.",
            ),
            # user-role-vip-manager's own description literally reads "Real access matches
            # user-role-front-desk-staff" -- left as-is, a faithful PRB revoking front-desk-staff
            # would reasonably revoke vip-manager too (it explicitly says its access IS
            # front-desk-staff's), corrupting this edit's `added={}` expectation that vip-manager
            # is unaffected. Rewritten to state vip-manager's own grant on its own terms, with no
            # reference to any other role, so the edit only ever touches the role it names.
            "user-role-vip-manager": (
                "Real access matches user-role-front-desk-staff.",
                "Real access: authorized to read reservation details and guest notes.",
            ),
        },
        removed={
            "inbound": {("user-role-front-desk-staff", "agent-scope-concierge")},
            "outbound_subject": {
                ("user-role-front-desk-staff", "tool-scope-reservation-read"),
                ("user-role-front-desk-staff", "tool-scope-guest-notes-read"),
            },
        },
    ),
    "confusable_agents": SensitivityEdit(
        edit_type="negation",
        policy_find="- Team trainers may read the team roster. - Team trainers may update the practice schedule.",
        policy_replace="- Team trainers may not read the team roster. - Team trainers may not update the practice schedule.",
        description_edits={
            "user-role-team-trainer": (
                "authorized to read the team roster and update the practice schedule through the "
                "coaching agent; not involved in performance evaluations.",
                "NOT authorized to read the team roster or update the practice schedule at all. Not "
                "involved in performance evaluations.",
            ),
        },
        removed={
            "inbound": {("user-role-team-trainer", "agent-scope-coach")},
            "outbound_subject": {
                ("user-role-team-trainer", "tool-scope-roster-read"),
                ("user-role-team-trainer", "tool-scope-schedule-write"),
            },
        },
    ),
    "empty_descriptions": SensitivityEdit(
        edit_type="negation",
        # The user role and the agent role share one name, "grounds-worker" (user-role-grounds-
        # worker / agent-role-grounds-worker) -- unlike an earlier revision where they were named
        # user-role-field-operator/agent-role-groundskeeper, two different words for the same
        # worker, which needed an explicit apposition in the policy text to ground the
        # outbound_target cascade. With one shared name, "Grounds workers may not ..." directly
        # names agent-role-grounds-worker too (every description in this scenario is deliberately
        # "" -- the whole point per its own docstring -- so this policy sentence is the only signal
        # either role gets).
        policy_find="Direct grants - Grounds workers may open irrigation valves. - Grounds workers may close irrigation valves.",
        policy_replace="Direct grants - Grounds workers may not open irrigation valves. - Grounds workers may not close irrigation valves.",
        description_edits={},
        removed={
            "inbound": {("user-role-grounds-worker", "agent-scope-grounds-worker")},
            "outbound_subject": {
                ("user-role-grounds-worker", "tool-scope-valve-open"),
                ("user-role-grounds-worker", "tool-scope-valve-close"),
            },
            "outbound_target": {
                ("agent-role-grounds-worker", "tool-scope-valve-open"),
                ("agent-role-grounds-worker", "tool-scope-valve-close"),
            },
        },
    ),
}


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_prb_sensitive_to_mechanical_edit(
    scenario_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record_property
) -> None:
    """Sensitivity family, mechanical tier: the PRB's grant decision changes, in exactly the
    predicted direction, under a deterministic minimal edit (``SENSITIVITY_EDITS``) that
    *deliberately* changes meaning — compared against the original scenario's truth table with
    that edit's known delta applied. The control that proves the PRB isn't just numb to its
    input: a model that ignores the policy text and always emits the same grants would score
    perfectly on the invariance family while failing every case here."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    scenario = SCENARIOS[scenario_name]
    edit = SENSITIVITY_EDITS[scenario_name]

    roles, scopes = build_roles_and_scopes(scenario)
    for name, (find, replace) in edit.description_edits.items():
        target = roles if name in roles else scopes
        current = target[name].description or ""
        new_description = current.replace(find, replace)
        # Mirrors the policy-text staleness assert below: str.replace silently no-ops when `find`
        # no longer matches (e.g. a future corpus reword), leaving the description unedited while
        # the policy text is still flipped -- a policy/description pair that disagree with no
        # signal the fixture went stale, instead of a loud failure here.
        assert new_description != current, (
            f"sensitivity edit description_edit for '{scenario_name}'/{name!r} did not match -- find={find!r} is stale"
        )
        target[name] = target[name].model_copy(update={"description": new_description})

    normalized_text = " ".join(digested_policy_path(scenario).read_text(encoding="utf-8").split())
    edited_text = normalized_text.replace(edit.policy_find, edit.policy_replace)
    assert edited_text != normalized_text, (
        f"sensitivity edit for '{scenario_name}' did not match the current policy text -- "
        f"policy_find={edit.policy_find!r} is stale"
    )
    edited_policy_path = tmp_path / f"{scenario_name}.sensitivity.md"
    edited_policy_path.write_text(edited_text)
    monkeypatch.setenv("AIAC_POLICY_FILE", str(edited_policy_path))

    # best_effort=True: a sensitivity edit deliberately introduces a narrower/negated capability
    # inside what may be a coarser-grained inbound scope's own (unedited) description — the
    # auditor can reasonably read that as a genuine contradiction and reject the decision rather
    # than partially granting it. Falls back to a best-effort, never-approved proposal instead of
    # aborting the whole scenario, exactly like the two correctness suites (`orchestrate_prb`'s
    # docstring) — by the same rationale: every scenario should score, and a rejection here is
    # itself informative (the PRB failing closed on an edit rather than re-deciding cleanly), not
    # a harness bug.
    rules, _, _, best_effort_notes = orchestrate_prb(roles, scopes, scenario, best_effort=True)
    want = truth(scenario)
    want_edited = {gate: (want[gate] - edit.removed.get(gate, set())) | edit.added.get(gate, set()) for gate in want}
    granted = _record_scoring(
        record_property,
        scenario,
        scenario_name,
        rules,
        want_edited,
        perturbation=f"{edit.edit_type}: {edit.policy_find!r} -> {edit.policy_replace!r}",
    )

    mismatches = {gate: granted[gate] ^ want_edited[gate] for gate in want_edited if granted[gate] != want_edited[gate]}
    sensitive = not mismatches
    record_property("sensitive", sensitive)
    record_property("edit_type", edit.edit_type)
    record_property("best_effort_notes", best_effort_notes)
    if best_effort_notes:
        print(f"[sensitivity] {scenario_name}: best_effort_notes={best_effort_notes}")
    assert sensitive, (
        f"PRB was not sensitive to edit ({edit.edit_type}) for scenario '{scenario_name}': mismatches={mismatches}"
    )


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_prb_sensitive_to_semantic_perturbation(
    scenario_name: str, monkeypatch: pytest.MonkeyPatch, record_property
) -> None:
    """Sensitivity family, semantic tier (#2467): the PRB's grant decision changes, in exactly the
    predicted direction, under a hand-authored, meaning-changing reworded sibling
    (``eval/scenarios_perturbed/scenario_eval_<name>_sensitive_perturbed.py`` — every one signed
    off in ``eval/scenarios_perturbed/SIGNOFF.md`` per spec §4), compared against the original
    scenario's truth table with that same edit's known delta applied. The delta is reused directly
    from ``SENSITIVITY_EDITS[scenario_name]`` — the mechanical tier's own sensitivity edit for this
    scenario — since it's a property of the meaning change, not of how it's expressed (literal
    word insertion there, full paraphrase here). Calls ``orchestrate_prb(..., best_effort=True)``
    for the same reason as every other test in this module: a rejected decision still scores via
    the last-proposed, never-approved rule instead of aborting the whole scenario."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    scenario = SCENARIOS[scenario_name]
    edit = SENSITIVITY_EDITS[scenario_name]

    sensitive_perturbed = SEMANTIC_SENSITIVITY_SCENARIOS[scenario_name]
    sp_roles, sp_scopes = build_roles_and_scopes(sensitive_perturbed)
    monkeypatch.setenv("AIAC_POLICY_FILE", str(digested_policy_path(sensitive_perturbed)))
    rules, _, _, best_effort_notes = orchestrate_prb(sp_roles, sp_scopes, sensitive_perturbed, best_effort=True)

    want = truth(scenario)
    want_edited = {gate: (want[gate] - edit.removed.get(gate, set())) | edit.added.get(gate, set()) for gate in want}
    granted = _record_scoring(
        record_property,
        scenario,
        scenario_name,
        rules,
        want_edited,
        perturbation=(
            f"Semantic tier: hand-reworded, meaning-changing sibling scenario module "
            f"`{sensitive_perturbed.__name__}` — realizes the same edit_type ({edit.edit_type}) and "
            "truth delta as SENSITIVITY_EDITS, expressed as full paraphrase instead of literal word "
            "insertion. Signed off in eval/scenarios_perturbed/SIGNOFF.md."
        ),
    )

    mismatches = {gate: granted[gate] ^ want_edited[gate] for gate in want_edited if granted[gate] != want_edited[gate]}
    sensitive = not mismatches
    record_property("sensitive", sensitive)
    record_property("edit_type", edit.edit_type)
    record_property("best_effort_notes", best_effort_notes)
    if best_effort_notes:
        print(f"[sensitivity-semantic] {scenario_name}: best_effort_notes={best_effort_notes}")
    assert sensitive, (
        f"PRB was not sensitive to semantic edit ({edit.edit_type}) for scenario '{scenario_name}': "
        f"mismatches={mismatches}"
    )
