# Eval Spec: policy-eval-robustness-consistency — `test_policy_pipeline_consistency.py` + `test_policy_pipeline_robustness.py`

> **One spec among several.** This document specifies a **family** of integration tests.
> Eval specs live **one spec per test** under `docs/evaluation/`
> (a sibling of `components/`), and the master PRD's *Integration test specifications* section
> ([../PRD.md](../specs/PRD.md)) is the index of them. This is the **policy-eval-robustness-consistency**
> family — it is a **companion to**, not a replacement for,
> [policy-eval-scenarios.md](policy-eval-scenarios.md): that family's eight heavy scenarios (full
> pipeline, `opa eval` truth tables) and two light scenarios (guardrail-contract `xfail`s) are
> reused here as the scenario **corpus**, unmodified, but neither this family's two suites touch
> Keycloak, the PCE, `opa`, or the filesystem Rego stub — they call the Policy Rules Builder (PRB)
> directly and compare its raw output.

## Location

Both suites live under `eval/`, alongside `policy-eval-scenarios.md`'s heavy
scenarios, and reuse that family's scenario corpus rather than defining their own:

- `eval/test_policy_pipeline_consistency.py` — the consistency suite, `@pytest.mark.eval`.
- `eval/test_policy_pipeline_robustness.py` — the robustness suite, `@pytest.mark.eval`,
  four test functions: `test_prb_invariant_to_mechanical_perturbation`,
  `test_prb_invariant_to_semantic_perturbation`, `test_prb_sensitive_to_mechanical_edit`,
  `test_prb_sensitive_to_semantic_perturbation` (#2467; see
  [Robustness suite](#robustness-suite)).
- `eval/scenarios_perturbed/SIGNOFF.md` + `eval/test_semantic_signoff.py` — the human sign-off
  ledger every semantic perturbation (invariance or sensitivity) requires before entering the
  corpus, and the unmarked, no-LLM test that enforces it (#2467; see
  [Sensitivity family, semantic tier](#sensitivity-family-semantic-tier)).
- `eval/prb_direct.py` — shared helper, `build_roles_and_scopes(scenario)`,
  used by both suites (see [No-Keycloak design](#no-keycloak-design) below).
- `eval/scenarios_perturbed/` — eight hand-authored semantic-sibling scenario
  modules + policy `.md` files, one per `policy-eval-scenarios.md` scenario (including
  `agent_delegation`, even though its **original** lives at `test/system/` top level, not
  under `eval/`) — used only by the robustness suite's semantic tier (see
  [Perturbation tiers](#perturbation-tiers)).
- Both suites import `SCENARIOS`, `orchestrate_prb`, `grant_sets`, `truth` from
  `eval.test_policy_pipeline_eval` **unmodified** — no changes to that module's
  own logic were needed for this work, beyond the unrelated file-reorg noted below.
- `eval/conftest.py` — the same per-run Markdown report generator
  `policy-eval-scenarios.md` documents, widened to also cover these two suites' markers (see
  [Test report](#test-report)).

**Unrelated but adjacent change, done as prerequisite cleanup for this work:** the seven
`eval/`-resident scenario modules from `policy-eval-scenarios.md` (`scenario_eval_baseline.py` and
six siblings, plus their `policy.eval_*.md` files) were moved from `eval/` directly into a new
`eval/scenarios/` subpackage, so the growing `eval/` directory doesn't flatten test modules,
scenario-data modules, and (now) two more scenario-data variants (`scenarios_perturbed/`) into one
namespace. `scenario_eval_agent_delegation.py`/`policy.eval_agent_delegation.md` are unaffected —
they already lived at `test/system/` top level and stay there. `test_policy_pipeline_eval.py`'s
imports were updated accordingly; no test logic changed.

## Description

`policy-eval-scenarios.md` proves the PRB's grant decisions are **correct** against a truth table,
once per scenario. It does not check whether those decisions are **consistent** (same input, run
again, same output) or **robust** (a small, meaning-preserving change to the input shouldn't flip
the output). Both properties matter for an LLM-backed access-control decision-maker in a way they
would not for a deterministic one: an LLM call can vary run-to-run on identical input, and can be
sensitive to phrasing/formatting/ordering in ways a human reviewer would not expect to matter. This
family adds two suites that isolate exactly those two properties, both scoped to the PRB's raw
output only — no OPA/PCE/k8s pipeline stage is involved in either (see
[No-Keycloak design](#no-keycloak-design)).

Both suites reuse the exact same 8-scenario corpus `policy-eval-scenarios.md` already defines
(`baseline`, `agent_delegation`, `unreachable_resources`, `ambiguous_clause`, `wildcard_grant`,
`misleading_descriptions`, `confusable_agents`, `empty_descriptions`) — one parametrized test case
per scenario, per suite.

### Digested corpus

Both suites run every scenario against its **committed digested** policy, not the source prose next
to the scenario module. Production feeds the Policy Rules Builder only digested policy (see
`docs/specs/digested-policy.md` and the PRB spec's "digested input retires exclusivity handling and
Door B" decision) — running these suites against raw source prose would test an input shape
production no longer produces. `eval/scenarios_digested/convert_scenarios.py` digests every scenario
and perturbed-sibling `.md` **once, out of band** (plus `agent_delegation`'s original, digested with
one extra targeted call since its source lives at `test/system/`, outside the two default source
dirs); the output is committed under `eval/scenarios_digested/`, one file per scenario/sibling, same
filename as the source. `eval/scenarios_digested/digested_policy_path(scenario)` is the single
resolver every suite in this family (and `test_policy_pipeline_correctness_prb.py` /
`test_policy_pipeline_eval.py`) calls instead of resolving the scenario module's own directory.
Regenerate the corpus by re-running the batch command (needs `LLM_BASE_URL`/`LLM_MODEL`/
`LLM_API_KEY`) whenever a scenario's source policy changes — this is a manual, deliberate step, not
part of any suite's runtime path.

`test_policy_pipeline_faithfulness.py` is the one exception: it exists specifically to test the
digester itself (`digest_policy`) against the source, so it digests live each run rather than
reading the committed artifact.

### Consistency suite

`test_prb_consistent_across_repeats` runs `orchestrate_prb()` `N` times (default 5, overridable via
`PRB_CONSISTENCY_REPEATS`) against the **same, unperturbed** scenario input, classifies each run's
rules via `grant_sets()`, and asserts every run's grant sets are exactly equal across all three
gates (`inbound`/`outbound_subject`/`outbound_target`) — run 0 is the pivot; equal-to-pivot for
every other run transitively proves all N runs pairwise equal. No tolerance, no majority vote: this
is access control, so any run-to-run disagreement is itself the finding, not noise to average away.
A failing scenario's assertion message names the offending gate, the specific `(role, scope)` pairs
that differ, and which run index disagreed with run 0.

### Robustness suite

Per `docs/evaluation/eval-framework.md` §4, Robustness is scored as **two families, never
blended**: **invariance** (a meaning-preserving edit — output must stay unchanged) and
**sensitivity** (a meaning-*changing* edit — output must change, in the predicted direction). Four
test functions, one metric each — no test combines two families' or two tiers' results into one
assert:

- `test_prb_invariant_to_mechanical_perturbation` — invariance family, mechanical tier (see
  [Perturbation tiers](#perturbation-tiers) below).
- `test_prb_invariant_to_semantic_perturbation` — invariance family, semantic tier (see
  [Perturbation tiers](#perturbation-tiers) below).
- `test_prb_sensitive_to_mechanical_edit` — sensitivity family, mechanical tier (see
  [Sensitivity family](#sensitivity-family-mechanical-tier) below).
- `test_prb_sensitive_to_semantic_perturbation` — sensitivity family, semantic tier (#2467; see
  [Sensitivity family, semantic tier](#sensitivity-family-semantic-tier) below).

All four compare against `truth(scenario)` (from `test_policy_pipeline_eval.py`) — the invariance
tests directly, the sensitivity tests against that truth table with its edit's known delta applied
(see below). Each is its own pass/fail per scenario; the assertion message states the mismatching
pairs per gate.

#### Perturbation tiers

1. **Mechanical** — a deterministic, RNG-free transform (`_mangle_text`) applied to the policy text
   and to every candidate `Role`/`Scope` description: whitespace/newline noise, casing noise (every
   3rd word forced upper, every 5th forced lower, by word index — not randomness, so the tier is
   itself perfectly reproducible run to run), and punctuation noise (space out `.`/`,`). Combined
   with candidate-list reordering (`_reordered`): a `SimpleNamespace` view of the scenario with
   every dict-iteration-order-sensitive field (`USER_ROLES`, `AGENTS`/`TOOLS` and each entry's
   nested scope/role dicts) reversed, since `orchestrate_prb()` derives every candidate list's
   order directly from the scenario module's own dict order. Name-keyed pair lists
   (`INBOUND_PAIRS` etc.) are order-insensitive (compared as sets downstream) and are copied through
   unchanged.
2. **Semantic** — a hand-authored, meaning-preserving reworded sibling scenario module from
   `eval/scenarios_perturbed/` (different phrasing throughout every `AGENTS`/`TOOLS`/`USER_ROLES`
   description and the paired policy `.md` text; every name-keyed field — ids, role/scope names,
   `INBOUND_PAIRS`/`OUTBOUND_PAIRS`/`OUTBOUND_SUBJECT_PAIRS`, and the two scenario-specific fields
   `EXPECT_NO_REGO`/`IDENTITY_CONFUSION_PROBES` where present — is byte-identical to the original).
   `empty_descriptions`' perturbed sibling is special-cased: its descriptions stay `""` (that
   scenario's whole point is the absence of description text), only its policy `.md` is reworded.
   Because names are guaranteed identical between a scenario and its perturbed sibling, `truth()`
   and `grant_sets()`'s name-based classification apply to the perturbed sibling's rules with no
   special-casing — `grant_sets(scenario, sem_rules)` (the **original** module, not the perturbed
   one) is exactly the right call.

Neither tier changes any production code: both drive `AIAC_POLICY_FILE` (via `monkeypatch.setenv`)
and pass perturbed `Role`/`Scope`/scenario-shaped objects into the existing, unmodified
`orchestrate_prb()` — called with `best_effort=True` (see
[Sensitivity family](#sensitivity-family-mechanical-tier) below for the mechanism; mangled/reworded
text can itself manufacture a coarse-scope contradiction the auditor rejects, and best-effort scores
it anyway rather than erroring the whole test out). Both tiers' invariance tests feed the trend log
(see [Trend log](#trend-log)) — `test_prb_invariant_to_mechanical_perturbation` as
`robustness_mechanical_invariance`, `test_prb_invariant_to_semantic_perturbation` as
`robustness_semantic_invariance` (#2467).

#### Sensitivity family (mechanical tier)

`test_prb_sensitive_to_mechanical_edit` is the control that proves the PRB isn't just numb to its
input: a model that ignores the policy text and always emits the same grants would score perfectly
on the invariance family while failing every case here. One deterministic, programmatically-applied
edit per scenario (`SENSITIVITY_EDITS: dict[str, SensitivityEdit]`, `test_policy_pipeline_
robustness.py`), each a small but *meaning-changing* minimal edit:

| `edit_type` | What it does | Scenarios |
|---|---|---|
| `negation` | revokes a role's entire relationship to a scope ("may not use ... at all") | `unreachable_resources`, `ambiguous_clause`, `wildcard_grant`, `confusable_agents`, `empty_descriptions` |
| `role_swap` | swaps which of two roles an entire scope-level grant covers | `agent_delegation` |
| `restriction_word` | inserts "only" to narrow *which roles* are eligible for an entire existing scope | `baseline` |
| `exception_clause` | adds an explicit "except ..." carving a role *out of* eligibility for an entire scope | `misleading_descriptions` |

Every edit operates at **whole-scope granularity**: it adds or removes a role's *entire*
relationship to a given scope (all of that scope's downstream pairs together), never a partial
slice of what one scope's own description bundles. This was a deliberate design correction made
after live testing: an earlier revision of several edits (`baseline`, `wildcard_grant`,
`unreachable_resources`, `confusable_agents`, `misleading_descriptions`) narrowed just *one*
sub-capability of a role's access — e.g. "testers may only read the issue tracker" — while the
relevant inbound scope's own (unedited) description still bundled both capabilities together
("reading **and updating** issues"). Against a real LLM, the auditor read that as a genuine
grant-and-prohibit contradiction on the bundled scope and rejected the decision outright, every
time — not occasional flakiness, but a structural consequence of asking the auditor to
partially honor a scope its own description asserts as one indivisible unit. Restriction_word and
exception_clause are still represented — they just restrict/except *role eligibility for an entire
scope* ("only developers may access the issue tracker", "everyone except front desk staff may use
the guest-services agent") rather than a role's *sub-capability within* one scope, which needs no
partial reconciliation from the auditor. Role-eligibility phrasing needs at least two roles sharing
the same scope to have something to restrict/except, so it only fits `baseline` and
`misleading_descriptions`; every single-role scenario (and `confusable_agents`, whose two roles use
disjoint agents) instead gets a full `negation`.

Each `SensitivityEdit` carries:

- `policy_find`/`policy_replace` — applied to the scenario's policy `.md` text *after*
  whitespace-normalization (`" ".join(text.split())`, so the edit doesn't depend on the file's
  exact line-wrapping — the PRB's real input is the flat text, not rendered markdown).
- `description_edits` — a `{role_or_scope_name: (find, replace)}` map applied to that entity's own
  `.description` (via `.model_copy(update=...)`, the same mechanism the mechanical-tier mangle
  uses), keeping the edited scenario's policy text and descriptions mutually consistent — the same
  way the original scenario's were co-authored to agree. Empty for `empty_descriptions`: every
  description in that scenario is deliberately `""` by design, so its policy `.md` text is the
  PRB's only signal.
- `removed`/`added` — the per-gate `(role, scope)` pairs that flip relative to `truth(scenario)`.
  The test recomputes the expected truth as `truth(scenario)` with this delta applied, and asserts
  the PRB's actual output matches it **exactly** — not merely "changed somewhere in the right
  direction". Exact-match is deliberate: a looser check would pass even if the edit had an
  unintended side effect elsewhere in the grant set (e.g. also moving a gate it wasn't meant to
  touch), which is exactly the failure mode worth catching.

Every edit was verified to touch only the intended gate(s) by checking, for each scenario, whether
the *agent's own role name* names a worker genuinely distinct from the user role being edited — e.g.
`wildcard_grant`'s `agent-role-stocker` (a stocker) is a different job from `user-role-inventory-manager`
(a manager), and `agent_delegation`'s `agent-role-dispatcher` is distinct from either
`user-role-shipment-coordinator` or `user-role-dock-worker`, so revoking/swapping the user-facing
sentence alone leaves `outbound_target` unaffected for those. `empty_descriptions`
(`agent-role-grounds-worker` / `user-role-grounds-worker` — literally the same name, not just the
same worker under two different words) and `unreachable_resources` (`agent-role-receptionist` /
`user-role-front-desk-clerk`, two different words for the same worker) are the two exceptions: in
both, the agent role names the same real-world worker as the user role it's paired with, so their
edit's delta touches `outbound_target` too — a partial revoke that left the identically-named
agent role untouched was not defensible, and live testing bore this out, with the auditor denying
the agent role's access right alongside the user role's rather than respecting an artificial split
between two names for the same job. This holds independently of whether the agent role happens to
carry its own description text (`agent-role-receptionist` does — "Covers read and write access to
patient records"); a description that's merely independently *written* doesn't make the two roles
independently *real*.

Even whole-scope edits are not guaranteed friction-free against a live auditor — in testing,
`baseline`'s "only developers may access..." phrasing triggered a *different*, softer auditor note
about how exclusivity should be signaled internally (not a contradiction), and a clean revoke can
still occasionally be rejected as an unsupported prohibition (`ambiguous_clause`, in testing). Both
are handled by `best_effort=True` (see [Testing Decisions](#testing-decisions)) and are qualitatively
different from the coarse-scope contradiction this redesign specifically eliminates: they're
LLM-behavior nuances the eval framework's own philosophy already treats as genuine findings, not
harness bugs — see [Expected output](#expected-output).

#### Sensitivity family (semantic tier)

`test_prb_sensitive_to_semantic_perturbation` (#2467) is the semantic-tier counterpart of
`test_prb_sensitive_to_mechanical_edit` above: a hand-authored, meaning-*changing* reworded sibling
module — `eval/scenarios_perturbed/scenario_eval_<name>_sensitive_perturbed.py` + its paired
`policy.eval_<name>_sensitive_perturbed.md` — one per scenario, mapped by
`SEMANTIC_SENSITIVITY_SCENARIOS` (`test_policy_pipeline_robustness.py`, alongside the existing
`PERTURBED_SCENARIOS`).

Each sibling realizes the **exact same `edit_type` and truth delta** as its mechanical-tier
`SENSITIVITY_EDITS` counterpart for that scenario — the delta (`removed`/`added`) is reused
directly, not re-derived, since it's a property of the meaning change itself, not of how it's
expressed. Only the *expression* differs:

| `edit_type` | Mechanical tier (literal) | Semantic tier (paraphrase) |
|---|---|---|
| `restriction_word` (`baseline`) | inserts "only" | "solely"/"exclusively" phrasing — the issue's explicit acceptance criterion, distinguishing this from the mechanical tier's literal word insertion |
| `exception_clause` (`misleading_descriptions`) | inserts "everyone except ..." | "every role other than front desk staff ... front desk staff themselves have no such access" |
| `role_swap` (`agent_delegation`) | swaps an exact text block | swaps which role's own description/policy sentence claims the capability |
| `negation` (the other five scenarios) | inserts "may not ... at all" | a full reworded revoke, e.g. "front desk clerks are entirely blocked from patient records" |

Every entity *not* touched by the edit is copied verbatim from that scenario's existing semantic-
*invariance* sibling (`eval/scenarios_perturbed/scenario_eval_<name>_perturbed.py`) — so a semantic-
sensitivity sibling is, by construction, "the invariance sibling's reworded prose, plus one
deliberate meaning-changing edit," the same layering relationship the mechanical tier's sensitivity
edit has to the mechanical tier's mangling. The two cascade cases (`unreachable_resources`,
`empty_descriptions`) apply the same direct-edit-not-inferred-cascade discipline as their
mechanical-tier counterparts: `agent-role-receptionist`'s description is revoked directly rather
than left to a cascade, and `empty_descriptions`' user and agent role share one name,
`grounds-worker`, so its policy text names the agent role directly with no apposition needed (see
[Sensitivity family (mechanical tier)](#sensitivity-family-mechanical-tier)'s cascade-case note).

**Sign-off ledger.** Every perturbed policy `.md` under `eval/scenarios_perturbed/` — both this
family's 8 new files and the existing 8 semantic-invariance files — has a row in
`eval/scenarios_perturbed/SIGNOFF.md` recording its content hash, the reviewer, the date, and a
confirmation that it preserves (invariance) or changes as intended (sensitivity) the original's
meaning, per spec §4's human-sign-off requirement. `eval/test_semantic_signoff.py` (unmarked, no
LLM, runs in the default fast unit pass) enforces this mechanically: every perturbed `.md` must
have a row, and that row's recorded hash must match the file's current content — an edited-but-not-
resigned perturbation fails loudly instead of shipping silently. The 8 pre-existing invariance
files are backfilled (marked as such in the ledger) since they shipped before this gate existed;
the 8 new sensitivity files carry a real sign-off obtained before they entered the corpus.

## No-Keycloak design

Both suites build synthetic `Role`/`Scope` objects directly (`prb_direct.build_roles_and_scopes`)
instead of provisioning a live Keycloak realm the way `test_policy_pipeline_eval.py`'s heavy
scenarios do. This is deliberate, not a shortcut taken for convenience: the agreed scope for both
suites is **the PRB's raw output only** — no OPA/PCE/k8s pipeline stage is exercised, so there is
nothing downstream that needs a real IdP-backed `Role`/`Scope` (`serviceId` mappings, Keycloak
client scopes, realm roles). `orchestrate_prb()` only ever reads `.name`/`.description` off these
objects (plus the scenario module's own dict order, for candidate-list ordering) — a synthetic
`id` is sufficient for everything else on the model.

Practical consequence: both suites need only `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY` — no
`KEYCLOAK_URL`, no Keycloak admin creds, no `opa` binary on `PATH`. This is a strictly lighter
prerequisite set than `policy-eval-scenarios.md`'s heavy scenarios, despite reusing the same
scenario corpus.

**The live-cluster UC1 onboarding ladder (`uc1-onboarding-pipeline.md`) is untouched and unused by
this work** — that ladder validates real in-cluster onboarding against a deployed AIAC stack, an
entirely different concern from this family's PRB-output-only scope.

## Expected output

Both suites parametrize over all 8 scenario names and expect **all 8 to pass** given a
well-behaved LLM endpoint. A failing case names the scenario, the failing family/tier (robustness
only), the failing gate, and the exact `(role, scope)` pairs that diverged — see
[Description](#description) above for each suite's exact failure-message shape.

Because both suites' subject is LLM behavior itself, a failure is a genuine finding about the
configured LLM's determinism or phrasing-sensitivity for this class of decision, not necessarily a
scenario-authoring defect — the same caveat `policy-eval-scenarios.md`'s
[Further Notes](policy-eval-scenarios.md#further-notes) makes about its own adversarial scenarios
applies here across the board, since every case in both suites is, by construction, comparing an
LLM decision against a fixed oracle.

## Scenario

See [policy-eval-scenarios.md § Scenario](policy-eval-scenarios.md#scenario) for the eight
underlying scenario modules' full entity lists and role→access facts — this family adds no new
ground truth, it only re-exercises the existing one under repetition (consistency) and perturbation
(robustness). The eight `eval/scenarios_perturbed/scenario_eval_*_perturbed.py` modules are each a
reworded-description mirror of their corresponding original; see each perturbed module's own
docstring for exactly what was reworded, and `scenario_eval_agent_delegation_perturbed.py`'s
docstring specifically for the note on why its perturbed sibling lives under `eval/` while its
original does not.

## Configuration (env)

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | The only required variables — both suites call the PRB directly against a real LLM endpoint. |
| `AIAC_POLICY_FILE` | Set per test call (via `monkeypatch.setenv`), not from the environment. Every base text is now the scenario's **committed digested** policy in `eval/scenarios_digested/` (`digested_policy_path`, see [Digested corpus](#digested-corpus) below), not the source `.md` next to the scenario module: the consistency suite points it there directly; the robustness suite points it at a `tmp_path`-written mangled copy of that digested text (invariance, mechanical tier), the perturbed sibling's own digested counterpart, `eval/scenarios_digested/policy.eval_<name>_perturbed.md` (invariance, semantic tier), or a `tmp_path`-written edited copy of the digested text (sensitivity, mechanical tier — see [Sensitivity family](#sensitivity-family-mechanical-tier)). |
| `PRB_CONSISTENCY_REPEATS` | Optional, consistency suite only. Number of repeat PRB runs per scenario. Default `5`. |

Neither suite reads `KEYCLOAK_URL`, `KEYCLOAK_ADMIN_USERNAME`/`PASSWORD`, `AIAC_PDP_CONFIG_URL`,
`AIAC_POLICY_STORE_URL`, `AIAC_PDP_POLICY_URL`, or `OPA_BIN` — see
[No-Keycloak design](#no-keycloak-design).

## Runbook

```bash
# Both suites need only LLM_BASE_URL/LLM_MODEL/LLM_API_KEY — no Keycloak/opa:
.venv/bin/pytest eval/test_policy_pipeline_consistency.py -m eval -v
.venv/bin/pytest eval/test_policy_pipeline_robustness.py -m eval -v

# Override repeat count for the consistency suite:
PRB_CONSISTENCY_REPEATS=10 .venv/bin/pytest eval/test_policy_pipeline_consistency.py \
  -m eval -v

# A pass/fail/skip/error report for the run is written alongside the policy-eval-scenarios one:
#   eval/reports/report_<DD_MM_HH_MM>.md (Asia/Jerusalem local time)
```

Both suites call `require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")` as the first
line of each parametrized test function (not in a fixture) — matching
`test_policy_pipeline_eval.py`'s existing pattern, this `pytest.skip`s the case (not a crash) if
any is unset/empty.

## Test report

Reuses the exact report described in
[policy-eval-scenarios.md § Test report](policy-eval-scenarios.md#test-report), widened to also
collect this family's `eval`-marked tests (`eval/conftest.py`'s single flat `eval` marker covers
every suite under `eval/`, this family included). Every test in this family falls
through to that report's generic docstring + crash-message rendering (none `record_property`s a
per-cell description the way `test_inbound`/`test_outbound` do) — a single docstring per
parametrized test function already names exactly what's being checked, since none of these suites
sweep a per-cell matrix the way the heavy scenarios' `test_inbound`/`test_outbound` do.
`test_prb_invariant_to_mechanical_perturbation`/`test_prb_sensitive_to_mechanical_edit` additionally
`record_property("invariant"/"sensitive", bool)` — not rendered in the Markdown report, but read
back by `_write_trend_log` (see [Trend log](#trend-log)). `test_prb_sensitive_to_mechanical_edit`
also `record_property("best_effort_notes", ...)` and prints a summary line when non-empty, same
convention as the two correctness suites — naming which scenario's decision fell back to a
best-effort, never-approved proposal (see [Testing Decisions](#testing-decisions)).

## Trend log

`eval/conftest.py`'s `_write_trend_log` collects all four test functions'
`record_property("invariant"/"sensitive", bool)` values, via nodeid-substring matching
(`_ROBUSTNESS_TEST_MARKERS`, since the single flat `eval` marker — shared by every suite under
`eval/` — spans four test functions across two families × two tiers that must stay unblended per
spec §4), and appends **four** rows to the committed, append-only `eval/trend_log.jsonl` from
`pytest_sessionfinish` — one per family/tier combination, never combined: `suite=
"robustness_mechanical_invariance"`, `"robustness_semantic_invariance"` (#2467),
`"robustness_mechanical_sensitivity"`, and `"robustness_semantic_sensitivity"` (#2467). Each row
carries that row's own pass/fail rate (`invariance_rate`/`sensitivity_rate`, mean of that row's
booleans) *and* that row's own `precision`/`recall`/`denial_precision`, pooled from the same
`true_positives`/`denied_total`/`over_grants`/`under_grants`/`incorrectly_denied` shape
`_record_scoring` records (`eval/trend_log.py`'s `pool_correctness_metrics` — the same pooling
function the two Correctness suites use, reused as-is here) — so each row's chart is directly
comparable in shape to a Correctness chart: two measuring the PRB against *original* inputs
(invariance, mechanical vs. semantic tier), two against *deliberately edited/reworded* inputs
(sensitivity, mechanical vs. semantic tier). A row with zero scored scenarios in a run (e.g. a `-k`
filter that only exercises one test function) simply gets no row at all, rather than a shared row
mislabeling one row's count against another's. See `docs/evaluation/eval-framework.md` §9.

## Testing Decisions

- **Switching to the digested corpus surfaced one real gap, fixed at the source, not patched
  around.** `agent_delegation`'s digest (and its perturbed sibling's) stated `create_manifest`/
  `update_manifest` as explicit per-operation grants but never an explicit `read_manifest` grant —
  the original source prose's "may create and update shipment manifests" let the PRB reasonably
  infer read access as a prerequisite, an inference the deliberately-explicit digested-policy
  language (see `docs/specs/digested-policy.md`) does not make on its own. This broke all three
  robustness tests *and* the consistency suite identically for this scenario, both invariance
  (unedited) and sensitivity (edited) — proving it was a corpus gap, not an edit-mechanism bug.
  Fixed in two places: the committed digested `.md` (both original and perturbed sibling) now
  states the read grant explicitly, and `agent-role-dispatcher`'s own description (`test/system/
  scenario_eval_agent_delegation.py` and its perturbed counterpart) now says "reading, creating,
  and updating" instead of just "creating and updating" — the same cascade-needs-its-own-textual-
  grounding principle this file already documents for `unreachable_resources`/`empty_descriptions`
  below, just on the agent-role side this time.
- **The consistency suite now calls `orchestrate_prb(..., best_effort=True)`**, matching every
  other suite in this family. Discovered empirically: against the digested `agent_delegation`
  policy, the auditor can read the coarse `agent-scope-dispatcher` (which bundles manifest
  operations with the explicitly-denied `initiate_customs_clearance_on_behalf`) as a genuine
  partial-grant/partial-deny contradiction on some repeats and not others — without `best_effort`,
  that crashes the whole scenario instead of contributing a comparable result, and a rejection on
  some repeats but not others is itself exactly the kind of run-to-run disagreement this suite
  exists to catch.
- **Reuse the existing corpus and helpers verbatim; add nothing scenario-specific to
  `test_policy_pipeline_eval.py`.** `SCENARIOS`, `orchestrate_prb`, `grant_sets`, `truth` are
  imported, not duplicated or modified — a change to the scenario corpus or to grant-set
  classification logic automatically applies to all three suites at once.
- **No Keycloak for either suite** — see [No-Keycloak design](#no-keycloak-design). This was a
  refinement over the original design-session proposal (which assumed the existing
  Keycloak-provisioning helpers would be reused as-is); confirmed during planning that
  `orchestrate_prb()` never reads anything Keycloak-specific off `Role`/`Scope`.
- **Consistency compares runs to each other, not to a truth table.** Whether the PRB is *correct*
  is `policy-eval-scenarios.md`'s job; this suite only asks whether it's *consistent* with itself.
  A scenario could in principle be consistently wrong (100% reproducible but incorrect) and this
  suite would report it as passing — that's by design, since correctness is a separate, already-
  covered concern.
- **Robustness compares each tier to the original scenario's truth, not to each other, and not to
  the unperturbed run's actual output.** Comparing tiers to each other would only prove
  "perturbation didn't change anything relative to itself," which is a weaker and less
  interesting claim than "the perturbed input still produces the *correct* decision."
- **Deterministic (no-RNG) mechanical perturbation.** `_mangle_text`/`_reordered` are pure
  functions of their input (word index modulo checks, not `random`), so a failing mechanical-tier
  case is exactly reproducible — no need to chase a seed or accept flakiness in the perturbation
  mechanism itself. Any observed variance is attributable entirely to the LLM call.
- **`agent_delegation`'s perturbed sibling lives under `eval/scenarios_perturbed/` despite its
  original living outside `eval/`.** Keeping all eight perturbed siblings in one directory (rather
  than mirroring the split-location convention `policy-eval-scenarios.md` uses for the originals)
  keeps `PERTURBED_SCENARIOS`' construction uniform and avoids inventing a second top-level
  perturbed-scenario file just to preserve an asymmetry that has no bearing on either new suite's
  logic.
- **Sensitivity edits are exact-match-scored, not "changed somewhere in the right direction".**
  `test_prb_sensitive_to_mechanical_edit` asserts the actual grant set equals `truth(scenario)`
  with the edit's delta applied — a looser check would still pass if the edit had an unintended
  side effect elsewhere in the grant set, which is exactly the failure mode worth catching.
- **Sensitivity edits touch the user-facing policy sentence, not the agent's own role, only where
  the agent role names a genuinely distinct worker.** For scenarios where the agent role and user
  role are different jobs (`wildcard_grant`'s `agent-role-stocker` vs. `user-role-inventory-manager`,
  `agent_delegation`'s `agent-role-dispatcher` vs. either of its user roles), revoking/swapping only
  the policy text's user-facing sentence keeps the edit's blast radius to exactly the intended
  gate(s). `empty_descriptions` (`agent-role-grounds-worker`, sharing its name outright with
  `user-role-grounds-worker`) and `unreachable_resources` (`agent-role-receptionist`, a different
  word for the same worker as `user-role-front-desk-clerk`) name the same worker as their paired
  user role, so their edit's delta necessarily touches `outbound_target` too — confirmed against a
  live LLM, which denied the agent role's access right alongside the user role's rather than
  honoring an artificial split between two names for the same job.
- **Every sensitivity edit is whole-scope, not partial-capability — a correction made after live
  testing, not the original design.** The first revision narrowed one sub-capability of a role's
  access while the relevant inbound scope's own description still bundled that capability with
  another ("reading **and updating** issues"); against a real LLM this reliably read as a
  grant-and-prohibit contradiction and the auditor rejected it every time — a structural
  consequence of the edit shape, not occasional model flakiness. The fix: every edit now adds or
  removes a role's *entire* relationship to a scope. `restriction_word`/`exception_clause` are
  still represented, just as role-*eligibility* language ("only developers may access...",
  "everyone except front desk staff may use...") rather than sub-capability language — which needs
  at least two roles sharing one scope to have anything to restrict/except, so it's used only where
  that structure exists (`baseline`, `misleading_descriptions`); every other scenario uses a full
  `negation` instead. See [Sensitivity family](#sensitivity-family-mechanical-tier) for the
  scenario-by-scenario rationale.
- **All four test functions use `orchestrate_prb(..., best_effort=True)`.** Even a whole-scope
  edit, or plain mangling/rewording, isn't guaranteed friction-free against a live auditor —
  confirmed in testing: `baseline`'s "only developers may access..." triggered a softer auditor note
  about how exclusivity should be signaled internally (rejected as an implementation nuance, not a
  contradiction); `ambiguous_clause`'s full revoke was once rejected as an unsupported prohibition on
  a scope nobody had ever been granted; and `agent_delegation`'s mechanical-tier mangling manufactured
  a coarse-scope contradiction on `agent-scope-dispatcher` (which bundles manifest operations and
  customs-clearance coordination in one scope) that the *unmangled* text never triggers. Best-effort
  falls back to the last-proposed, never-approved rule instead of aborting the whole scenario — the
  same mechanism and rationale as the two correctness suites — so a rejection still scores (and is
  itself an informative finding: the PRB failing closed rather than cleanly re-deciding), rather than
  erroring the whole test out and reporting every metric as "unavailable." This was a deliberate
  correction: the invariance tests originally used `best_effort=False` (matching the legacy suite's
  behavior), but that meant a rejected decision surfaced no metrics at all in the report — inconsistent
  with the sensitivity test, which had `best_effort=True` from the start. Whether a given live run's
  `invariance_rate`/`sensitivity_rate` comes out high or low is exactly the signal the trend log exists
  to track over time — the eval framework's own
  philosophy (`docs/evaluation/eval-framework.md`, and this suite's own
  [Expected output](#expected-output)) already treats a failure against a live, non-deterministic
  LLM as a genuine finding, not proof the harness is broken.

## Relationship to other integration tests

This is **one** integration-test spec (covering two suites, 40 parametrized test cases total — the
consistency suite's 8 plus the robustness suite's 4 test functions × 8 scenarios) among several
indexed by the master PRD ([../PRD.md](../specs/PRD.md), § *Integration test specifications*).

- **Companion to, not a replacement for, [policy-eval-scenarios.md](policy-eval-scenarios.md).**
  That family proves correctness once per scenario; this family proves consistency and robustness
  of the same decisions, reusing its corpus and helpers unmodified.
- **Independent of [policy-pipeline.md](../testing/policy-pipeline.md) and
  [uc1-onboarding-pipeline.md](../testing/uc1-onboarding-pipeline.md).** Neither suite here touches Keycloak,
  the PCE, `opa`, or a live cluster — see [No-Keycloak design](#no-keycloak-design).
- **Carries the single flat `eval` marker** (`pyproject.toml`), same as every other suite under
  `eval/` — select this suite specifically by file path or `-k`, not by a dedicated marker (the
  former per-suite `eval_*` markers, including `eval_consistency`/`eval_robustness`, were collapsed
  into one).

## Out of Scope

- **Any OPA/PCE/k8s pipeline stage.** Both suites stop at the PRB's raw `list[PolicyRule]` output —
  see [No-Keycloak design](#no-keycloak-design).
- **New scenarios.** Both suites reuse `policy-eval-scenarios.md`'s existing 8-scenario corpus
  as-is; adding a ninth scenario there automatically extends both suites here once the perturbed
  sibling for it is authored.
- **The two light guardrail scenarios (2, 5).** Those are `xfail`-pinned document-level rejection
  contracts, not grant-decision comparisons — neither "repeat N times" nor "perturb the input"
  is a meaningful operation on a whole-document-reject assertion, so they are not part of this
  family's corpus.
- **Statistical/majority-vote tolerance.** Both suites require exact equality; introducing a
  tolerance threshold (e.g. "passes if 4 of 5 runs agree") is a policy decision explicitly left for
  future work if today's exact-equality bar proves too strict in practice.
- **Default-CI wiring.** Both markers keep this family out of the default `-m "not integration"`
  unit run, matching every other suite indexed in this PRD section (the sign-off enforcement test,
  `eval/test_semantic_signoff.py`, is the one exception — unmarked, so it runs in the default
  fast pass, same as `eval/test_convert_scenarios.py`).

## Blocked-by

Same PRB prerequisites as [policy-eval-scenarios.md](policy-eval-scenarios.md#blocked-by)'s light
scenarios — the PRB entry points (`orchestrate_prb`, itself built on
`build_role_rules`/`build_scope_rules`) and a live LLM. No Keycloak, PCE, OPA, or Policy Store
dependency for either suite in this family.
