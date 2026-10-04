# Eval Spec: policy-eval-scale — `test_policy_pipeline_scale.py`

> **One spec among several.** This document specifies **one** integration test family.
> Eval specs live **one spec per test** under `docs/evaluation/`
> (a sibling of `components/`), and the master PRD's *Integration test specifications* section
> ([../PRD.md](../specs/PRD.md)) is the index of them. Unlike every other family in this index,
> this one uses a **procedurally generated** corpus, not the hand-authored 8-scenario one
> `policy-eval-scenarios.md`/`policy-eval-robustness-consistency.md`/`policy-eval-correctness-prb.md`/
> `policy-eval-correctness-e2e.md` all share — see [Why a generated
> corpus](#why-a-generated-corpus).

## Location

- `eval/scale_generator.py` — the procedural, seeded, deterministic corpus generator.
  `generate_total_corpus`/`generate_per_decision`, returning `ScaleCorpus`/`PerDecisionCorpus`. Pure
  logic, no I/O, no LLM. Unit-tested unmarked in `eval/test_scale_generator.py` (runs in the default
  fast pass).
- `eval/scale_prb.py` — `orchestrate_prb_concurrent`/`run_concurrently`: a thread-pooled counterpart
  of `eval.test_policy_pipeline_eval.orchestrate_prb` that fans the same set of per-scope/per-role
  `_invoke_graph` calls out concurrently instead of running them one after another. See [Why
  concurrency](#why-concurrency). Also `capture_precheck_drops`: a log-capture context manager
  (unit-tested unmarked in `eval/test_scale_prb.py`) that recovers a hallucinated candidate name
  production's own `_precheck` step drops, for the two **sequential** per-decision calls only —
  not thread-safe to use from the concurrent loop above, see its own docstring.
- `eval/scale_structural.py` — the structural-check helpers: `missing_decisions`, `missing_rego`,
  `invalid_selected_names`, `duplicate_rule_triples` (PRB-level, pre-merge), `duplicate_rego_entries`
  (e2e-level, the real rendered output), `orphaned_scope_names`, `summarize_usage`/`CostSummary`.
  Pure logic, no LLM/IO of its own — unit-tested unmarked in `eval/test_scale_structural.py`.
  `orphaned_scope_names` is also exercised directly in `eval/test_scale_generator.py` (see
  [Structural checks](#structural-checks)).
- `eval/test_policy_pipeline_scale.py` — the suite itself, `@pytest.mark.eval`. Eight test
  functions: `test_scale_{total_corpus,per_decision}_{structural,correctness}_{prb,e2e}`.
- Reuses, unmodified: `eval.prb_direct.build_roles_and_scopes`, `eval.test_policy_pipeline_eval`'s
  `_invoke_graph`/`grant_sets`/`truth`/`_connect_admin`/`provision_keycloak_admin`/
  `provision_via_config`/`_read_back`/`_rego_path`/`opa_bin`, `eval.correctness_scorer.score_scenario`,
  and `eval.test_policy_pipeline_correctness_e2e._e2e_grant_sets`.

## Description

Per `docs/evaluation/eval-framework.md` §5, "large number of agents/tools/entitlements" decomposes
into two independent dimensions, never blended into one "scale score":

- **Total-corpus** — many roles/scopes/services overall, each individual PRB decision still facing
  a modest candidate list. Stresses the deterministic merge engine, Rego document size, OPA eval
  latency, and total wall-clock/cost across many PRB calls.
- **Per-decision** — one role/scope facing a very large candidate list in a single PRB call.
  Stresses the LLM itself (context pressure, needle-in-a-haystack attention degradation).

Both dimensions are checked by **two check types**, kept on separate assertions and separate metric
names — but merged onto one trend-log row per dimension/level (see [Test report and trend
log](#test-report-and-trend-log)), since what the spec actually guards against is blending the two
into one number, not which JSON object the keys live in — at **both levels** (PRB-direct and
end-to-end):

- **Structural** — completeness, no duplication, no orphans (gated, objectively pass/fail);
  latency and cost (reported/trended only — no SLA exists anywhere in the spec or the originating
  issue to gate against, same as the Correctness suite's still-TBD under-grant threshold).
- **Correctness** — the same precision/recall scorer (`eval.correctness_scorer.score_scenario`)
  every sibling suite in this family uses, against the generated corpus's ground truth. Same
  zero-tolerance over-grant gate.

This is the **fixed regression tier** (spec §5): a stable, gated 100-service corpus, anchored below
the PRD's only documented scale target ("hundreds of services",
`docs/specs/components/policy-model-store.md`'s pagination note) as a starting point. The
**exploratory breaking-point tier** (geometric scale-up to a 1,000-entity ceiling, manual-invocation
only, no pass/fail) is #2470, out of scope here — see [Out of Scope](#out-of-scope).

## Why a generated corpus

Hand-authored truth tables don't scale past low double digits of entities. `eval.scale_generator`
instead builds policy+truth pairs **procedurally**: a small, seeded `random.Random` decides every
`(role, scope)` grant fact itself, so ground truth is known **by construction**, and the policy text
is rendered directly from those same facts — text and truth can never drift apart.

Both generator functions return an object shaped **exactly** like an existing `eval/scenarios/`
scenario module (`AGENTS`/`TOOLS`/`USER_ROLES`/`USERS`/`USER_PASSWORD`/`REALM_DEFAULT`/
`INBOUND_PAIRS`/`OUTBOUND_PAIRS`/`OUTBOUND_SUBJECT_PAIRS` — a `SimpleNamespace`/`dataclass`, not a
`ModuleType`, since it's built at runtime rather than imported). This is the single biggest reuse
win in this ticket: every existing PRB-level and end-to-end helper function
(`build_roles_and_scopes`, `orchestrate_prb`'s per-call primitives, `grant_sets`, `truth`,
`provision_keycloak_admin`, `provision_via_config`, `_e2e_grant_sets`) works against a generated
corpus with **zero changes**.

Policy text is rendered directly in digested-policy style (`docs/specs/digested-policy.md`'s
direct-grant grammar — "Role X may access Scope Y") rather than routed through the LLM digester
(`eval/scenarios_digested/convert_scenarios.py`): every generated fact is already unambiguous, so
there is nothing for digestion to resolve, and adding an LLM pass would only add cost and a possible
faithfulness drift between the rendered text and the truth it's supposed to match.

**Total-corpus** (`generate_total_corpus`): `n_services` (default 100) agents+tools split evenly,
`n_roles` (default 10) user roles, one inbound scope + one agent role per agent, one scope per tool.
Independent per-`(subject, candidate)` density sampling (`inbound_density`/
`outbound_subject_density`/`outbound_target_density`) decides every grant fact — followed by a
**repair pass** that forces at least one grant onto any scope sampling left with zero, so
`orphaned_scope_names` (see [Structural checks](#structural-checks)) is a **generator invariant**,
never a nondeterministic flake from unlucky sampling.

**Per-decision** (`generate_per_decision`): `n_candidates` (default 100, matching the issue's
fixed-size decision) candidate roles for one focal scope, and symmetrically `n_candidates` candidate
scopes for one focal agent role — each drives exactly one PRB call
(`_invoke_graph`/`SCOPE_GRAPH`/`ROLE_GRAPH`), not `orchestrate_prb`'s loop. The same repair-pass
discipline guarantees a non-degenerate (neither empty nor total) granted set at any `n_candidates`
override, including small dev-iteration sizes. `PerDecisionCorpus.e2e_scenario` is a *second*,
`ScaleCorpus`-shaped view of this **same** ground truth (two agents —
`PER_DECISION_SCOPE_AGENT_ID` owning the focal scope, `PER_DECISION_ROLE_AGENT_ID` owning the focal
role plus a tool owning every candidate scope) — so the end-to-end level scores the identical seed's
truth, just pushed one layer further downstream, not a re-derived one.

## Why concurrency

`orchestrate_prb()`'s own loop (production code, not modified here) makes its PRB calls
sequentially. At the fixed-100 size, total-corpus alone is ~100-150 decisions — sequential would pay
~100-150x one call's LLM round-trip latency for no benefit, since each call is independent (its own
fresh state dict, its own freshly-built `ChatOpenAI` client per `_structured_call`). `eval.scale_prb`
fans the *same* call set out across a `ThreadPoolExecutor` instead
(`orchestrate_prb_concurrent`/`run_concurrently`), capped by `SCALE_CONCURRENCY` (default 20,
mirrors `EVAL_PIPELINE_PARALLELISM`'s existing override convention).

**Confirmed empirically, not merely assumed**, before building anything around it:

1. Concurrent `_invoke_graph` calls sharing one `AIAC_POLICY_FILE` value are thread-safe and produce
   correct, independent results (each call builds its own state and its own LLM client).
2. LangChain's `get_usage_metadata_callback()` (`langchain_core.callbacks.usage`) does **not**
   propagate its context var into `ThreadPoolExecutor` worker threads — a callback scoped around
   the whole pool submission saw zero usage. Scoping one *inside* each worker task instead
   (`eval.scale_prb._invoke_with_usage`) correctly captures that task's own usage, aggregated by the
   caller afterward — see [Cost](#cost).
3. `_read_back`'s flat `Configuration.get_roles()` call does not reliably carry the correct
   `kind`/`actorIds` for an agent-owned role (a service's own `.roles` list does — see
   `eval.test_policy_pipeline_scale._fix_agent_role_actor_ids`, applied after every `_read_back` call
   at the end-to-end level). This is unrelated to concurrency itself but was only caught because the
   end-to-end fixtures exercise a code path the hand-authored 8-scenario corpus's own agent-role
   structure happens not to trigger.
4. The real PDP writer server-side-applies a Kubernetes `AuthorizationPolicy` CR per agent against a
   **live cluster namespace** matching the agent id's own namespace segment — not merely a local
   file dump. Every generated agent id therefore uses the `team1/` namespace every hand-authored eval
   scenario already shares (confirmed to exist in the target cluster), rather than inventing a new
   namespace that would need to be created out of band.

## Structural checks

Defined in `eval.scale_structural`, each returning the **exact offending entities**, never a bare
boolean, so a report reader is never left inferring a failure's cause from a crash message alone
(the same no-opaque-failures discipline `_render_consistency_block`/`_render_metrics_block` already
established for Consistency/Correctness):

| Property | Function | Gated? |
|---|---|---|
| Completeness (total-corpus) | `missing_decisions` — every generated agent-inbound-scope/target-scope/agent-role decision actually ran (`best_effort=True` guarantees a rejected decision still contributes an entry, so a name missing here is an eval-harness bug — including a job `eval.scale_prb.orchestrate_prb_concurrent` itself caught failing outright, see `failed_decisions` below — not an LLM finding) | Yes |
| Completeness (per-decision) | `invalid_selected_names`, fed the names `eval.scale_prb.capture_precheck_drops` recovers directly from production's own `_precheck` step's diagnostic log, **before** it silently filters them out — not the post-filter `selected`/`denied` lists, which by construction can never contain one. **Not** "every candidate resolved to selected or denied": production's own selection schema (`RoleSelection`/`ScopeSelection`) carries only explicit grants/prohibitions with no enumerated "everyone else is denied" complement, and this corpus's grammar never emits explicit prohibitions, so a non-granted candidate absent from both lists is an ordinary implicit deny, not an incomplete response. The one genuinely distinct fidelity signal here is a **hallucinated** candidate name — one that never appeared in the input at all. | Yes |
| Completeness (e2e) | `missing_rego` — every agent that the PRB **actually produced a rule for** got its expected Rego file rendered. Deliberately *not* unconditional over every agent: a live LLM can legitimately propose zero grants for one agent's every decision despite the generator's ground-truth-reachability guarantee — that is a correctness finding (already tracked, non-gating, by the correctness test's `under_grants`), not a structural/rendering defect, and conflating the two would make this "stable regression guard" flake on ordinary LLM variance instead of on an actual pipeline bug. Reported (non-gating) as `agents_with_no_rules`. | Yes (for agents with rules) |
| No duplication (PRB level) | `duplicate_rule_triples` — no `(role, scope, effect)` triple appears more than once in the **raw, pre-merge** PRB output. No merge engine runs at this level, so this cannot catch a merge defect (see `duplicate_rego_entries` below for that) — what it still catches is a duplicate entry in this suite's *own* candidate-list construction, which the PRB would faithfully restate twice. | Yes |
| No duplication (e2e level) | `duplicate_rego_entries` — no candidate name appears more than once in the **real rendered Rego** (`eval.test_policy_pipeline_correctness_e2e._rego_map`'s own per-document output), the one way `compute_and_apply`'s documented role.id+scope.id+effect dedup could actually fail on disk. Supersedes `duplicate_rule_triples` at this level, which checks the same pre-merge rules the PRB-level check already does and so cannot see a real merge defect either. | Yes |
| No orphans | `orphaned_scope_names` — every scope the corpus defines is reachable by at least one role in the **generated ground truth** (a generator invariant per the repair pass above — a violation here is a generator regression, never an LLM finding). A pure property of the generator's own output, independent of any PRB call, so it's exercised directly — parametrized across several `(size, seed)` combinations — in the **offline** `eval/test_scale_structural.py`/`eval/test_scale_generator.py`, not re-checked once per expensive live run here (where the already-fixed scenario would always pass for free). | Yes (offline) |
| Latency | plain `time.perf_counter()` wall-clock around the whole PRB-level call (total-corpus: the full concurrent loop; per-decision: the two sequential calls) and, at e2e level, additionally around PCE/Rego rendering | No — reported/trended |
| Cost | `summarize_usage`/`CostSummary` — summed `total_tokens` across every call's `usage_metadata`, plus a `coverage` fraction (calls the endpoint actually reported usage for) so a partial-coverage run is visible, never silently read as a lower true cost. A call `orchestrate_prb_concurrent` caught failing contributes to neither — see `failed_decisions` below. | No — reported/trended |
| Failed decisions (total-corpus) | `eval.scale_prb.orchestrate_prb_concurrent`'s `failed_decisions` — a `{name: reason}` dict for a job that raised `PolicyRulesBuilderBaseError` (e.g. a rate-limited `LLMAccessError`) outright, kept separate from `best_effort_notes` (which means something different: a proposal the auditor saw and rejected) and from `usage_by_name` (there is no usage to report for a call that never returned). Reported only — the name is already counted once via `missing_decisions` above. | No — reported only |

## Correctness checks

Reuses `eval.correctness_scorer.score_scenario`/`score_gate` (the same scorer
`policy-eval-correctness-prb.md`/`policy-eval-correctness-e2e.md` use), unmodified:

- **Total-corpus**: the PRB's (or, at e2e level, the rendered Rego's) grant/deny output, classified
  by `grant_sets`/`_e2e_grant_sets` into the familiar `inbound`/`outbound_subject`/`outbound_target`
  gates, scored against `truth(scenario)`.
- **Per-decision**: the two directions (`scope_direction`, `role_direction`) are treated as two
  "gates" the way a real scenario's three gates are — each candidate becomes a `(role_name,
  scope_name)` pair against the fixed focal entity (subject-side pairs for the scope direction,
  resource-side pairs for the role direction), so `score_scenario`'s existing per-gate aggregation,
  `eval/conftest.py`'s report rendering, and `eval/trend_log.py`'s pooling all apply with **zero**
  special-casing.

Same zero-tolerance-on-over-grants gate every sibling suite uses; under-grants and incorrect
denials are tracked/reported only (spec: threshold TBD, deferred).

## Test report and trend log

`eval/conftest.py`'s `_SCALE_TEST_MARKERS` maps each of the eight test functions to `(suite,
"structural" | "correctness")` — unlike every prior dict there, a Scale trend-log row is built from
**two** test functions' properties merged together, since structural and correctness for the same
dimension/level are checked by separate test functions but land on one row
(`scale_total_corpus_prb`/`scale_total_corpus_e2e`/`scale_per_decision_prb`/`scale_per_decision_e2e`
— total-corpus and per-decision, and PRB and e2e, always kept on **separate** rows, per spec §5's
explicit warning that a system can pass one dimension/level while silently failing the other).
`eval.trend_log.pool_scale_metrics` pools the structural half (`structural_pass`/
`structural_issue_count`/`wall_clock_seconds`/`total_tokens`/`token_coverage`, common fields both
dimensions record regardless of their own concrete-check taxonomy) into `structural_pass_rate`/
`structural_issue_count`/`total_tokens`/`mean_wall_clock_seconds`/`mean_token_coverage`; the
existing `pool_correctness_metrics` pools the correctness half exactly as it already does for every
other suite. `run_type` is `"regression"` only once **both** halves ran in a session (a `-k` filter
that exercised just one test function produces a `"partial"` row instead — not comparable to a
full-corpus run).

`_render_scale_block` renders every structural field unconditionally, pass or fail (same convention
as `_render_consistency_block`); a Scale correctness test's report entry falls straight through the
existing `"precision" in props and "recall" in props` branch with no new rendering code, since its
`record_property` shape is identical to every other correctness suite's.

## Configuration (env)

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | Required for every PRB-level and end-to-end case. |
| `KEYCLOAK_URL` / `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` | Required for the end-to-end cases only. |
| `SCALE_TOTAL_CORPUS_SIZE` (optional) | Total-corpus dimension's `n_services`. Default `100`. Override to a small size (e.g. `10`) while iterating. |
| `SCALE_TOTAL_CORPUS_ROLES` (optional) | Total-corpus dimension's `n_roles`. Default `10`. |
| `SCALE_PER_DECISION_CANDIDATES` (optional) | Per-decision dimension's `n_candidates`. Default `100`. |
| `SCALE_SEED` (optional) | Generator seed, for both dimensions. Default `0`. |
| `SCALE_CONCURRENCY` (optional) | Max concurrent PRB/Keycloak-admin calls (`eval.scale_prb.concurrency`). Default `20`. |
| `OPA_BIN` (optional) | Path to the `opa` binary for the end-to-end cases; falls back to `opa` on `PATH`. Skips cleanly (not fails) if neither resolves. |

No `AIAC_POLICY_FILE` env var to set by hand — every fixture points it at a generated policy text
written to a `tmp_path`, per call.

## Runbook

Selection stays marker-only, same as every other suite (never a file path) -- `-k scale` narrows
to this suite's eight `test_scale_*` functions within the `eval` marker, same convention as
`CLAUDE.md`'s own `-m system -k uc1_onboard` example:

```bash
# PRB-level only -- needs only LLM_BASE_URL/LLM_MODEL/LLM_API_KEY:
.venv/bin/pytest -m eval -k "scale and prb" -v -s

# End-to-end only -- additionally needs KEYCLOAK_URL+admin creds and opa on PATH:
.venv/bin/pytest -m eval -k "scale and e2e" -v -s

# Small size while iterating (mirrors PRB_CONSISTENCY_REPEATS' existing override convention):
SCALE_TOTAL_CORPUS_SIZE=10 SCALE_TOTAL_CORPUS_ROLES=4 SCALE_PER_DECISION_CANDIDATES=20 \
    .venv/bin/pytest -m eval -k scale -v -s

# Full fixed-100 regression run (both dimensions, both check types, both levels):
.venv/bin/pytest -m eval -k scale -v -s
```

Each dimension/level pair shares one expensive fixture between its structural and correctness test
(module-scoped), so a full run pays for the total-corpus PRB call, the total-corpus e2e pipeline
run, the two per-decision PRB calls, and the two per-decision e2e calls exactly once each — never
twice. At the full fixed-100 size, the total-corpus dimension alone is ~100-150 sequential-in-effect
LLM decisions (fanned out concurrently, per [Why concurrency](#why-concurrency)); expect this run to
take substantially longer than any other suite in this family, matching the spec's own §8 cadence
placement (Nightly, not per-PR).

## Out of Scope

- **The exploratory breaking-point tier** (#2470) — geometric scale-up to a 1,000-entity ceiling,
  manual-invocation only, no pass/fail. Blocked-by this ticket: reuses `eval.scale_generator`
  unmodified, driven at larger sizes.
- **A latency/cost SLA.** Both are reported and trended only — no threshold exists anywhere in the
  spec or the originating issue to gate against (same open item as the Correctness suite's
  under-grant threshold, `docs/evaluation/eval-framework.md` §12).
- **A dollar-cost figure.** `summarize_usage` reports token counts, not a fabricated $/token
  conversion — no such table exists anywhere in this repo to justify one.
- **Raising the fixed-regression size above 100 services**, or revisiting the per-decision
  candidate count, as confidence grows — explicitly named as a future revisit in the spec (§12).

## Blocked-by

\#2091 (the committed trend log — already shipped; `eval.trend_log.append_row`/
`pool_correctness_metrics` reused here unmodified, `pool_scale_metrics` added alongside them). Same
PRB/e2e prerequisites as every other suite in this family — no new production dependency introduced.
