# Eval Spec: policy-eval-correctness-e2e — `test_policy_pipeline_correctness_e2e.py`

> **One spec among several.** This document specifies **one** integration test.
> Eval specs live **one spec per test** under `docs/evaluation/`
> (a sibling of `components/`), and the master PRD's *Test & evaluation specifications* section
> ([../PRD.md](../specs/PRD.md)) is the index of them. This is a **companion to**, not a replacement
> for, [policy-eval-scenarios.md](policy-eval-scenarios.md) and
> [policy-eval-correctness-prb.md](policy-eval-correctness-prb.md): all three families reuse the
> same eight-scenario corpus (`SCENARIOS`, `truth`, from `eval/test_policy_pipeline_eval.py`),
> unmodified, but each isolates a different property or layer of the pipeline.

## Location

- `aiac/eval/correctness_scorer.py` — the reusable scorer (`score_gate`/`score_scenario`),
  reused **unmodified** from #2089 — see
  [policy-eval-correctness-prb.md § Scorer design](policy-eval-correctness-prb.md#scorer-design)
  for the scorer itself; this spec does not repeat it.
- `aiac/eval/correctness_e2e_helpers.py` — this suite's own pure-logic helpers (`_pairs_from_map`,
  `_user_role_rows`, `_owned_pairs`, `_on_target_scopes`, `_accumulate_service_gates`);
  `aiac/eval/test_correctness_e2e_helpers.py` —
  their unmarked unit tests, runs in the default fast pass. Mirrors
  `eval/correctness_scorer.py`/`eval/test_correctness_scorer.py`'s logic-module/test-module split.
- `aiac/eval/test_policy_pipeline_correctness_e2e.py` — the suite itself,
  `@pytest.mark.eval`.
- `aiac/eval/best_effort_rules.py` — the best-effort fallback's own pure-logic helper
  (`_best_effort_rules`); `aiac/eval/test_best_effort_rules.py` — its unmarked unit tests. See
  [Best-effort proposals](#best-effort-proposals).
- Reuses, unmodified, from `eval.test_policy_pipeline_eval`: `SCENARIOS`, the `pipeline` fixture
  (re-exported by import — see [Runbook](#runbook)), `_require_scenario`, `_rego_path`,
  `_scope_owner`, `_agent_inbound_scope_names`, `_agent_delegation_scope_names`,
  `_tool_scope_names`, `_user_role_names`, `opa_bin`, `opa_eval`, `truth`.

## Description

`policy-eval-correctness-prb.md`'s suite scores the PRB's raw grant/deny output directly — no
Keycloak, no PCE, no OPA. This suite scores the **same** primary corpus's grant/deny output one
layer further downstream: real Keycloak provisioning → real Policy Rules Builder → real Policy
Computation Engine → real `opa eval` against the rendered Rego. It is the only correctness check
that can catch an integration bug between those layers (PCE merge logic, Rego rendering, OPA
semantics) that a PRB-only check structurally cannot see — the PRB could return exactly the right
rules and a bug in the PCE's merge or in `rego.py`'s rendering could still produce the wrong
Rego.

Same scoring philosophy as the PRB-level suite: precision and recall tracked separately per gate
and aggregated (never blended), a non-gating denial-precision figure, zero-tolerance on
over-grants, under-grants/incorrect denials reported only.

### Scoring source: the rendered Rego data maps, not per-pair decision probing

Each callee checks the access to itself in its own inbound OPA, from its own CR. So each rule is
in the inbound Rego of the service (agent or tool) that owns its scope. `opa eval` queries the
plain data documents of that inbound package (`data.authbridge.client.inbound.request`, no input)
directly, and does not probe the `allow` decision of each `(role, scope)` pair. One `opa eval`
call for each agent and each tool gives all the role→scopes maps of that service. Each map is
flat, `{role: [scope, ...]}`: the callee's own CR is the key, so a map is keyed by role only.
`_pairs_from_map` flattens a map into `(role, scope)` pairs. It raises `TypeError` when a row is
not a list, so a reader on a nested shape cannot score pairs with no error. `_user_role_rows`
keeps only the subject-map rows whose role is a user role of the scenario (a guard: a correct
render has only user roles in the subject maps).

`_accumulate_service_gates` unions the pairs of each service into the three top-level gate buckets
that `score_scenario` expects. A target scope is a tool scope or an agent delegation scope.

| Gate | Source | ALLOW map | DENY map |
|---|---|---|---|
| `inbound` | the inbound Rego of each agent, every row | `subject_role_allow_scopes` | `subject_role_deny_scopes` |
| `outbound_subject` | the inbound Rego of each agent and tool, the rows on a target scope | `subject_role_allow_scopes` | `subject_role_deny_scopes` |
| `outbound_target` | the inbound Rego of each agent and tool, every row | `source_role_allow_scopes` | `source_role_deny_scopes` |

The inbound renders `source_role_deny_scopes` (the calling-agent DENY gate), so the
`outbound_target` gate also has a deny side.

**A source row on an agent inbound scope.** The truth tables pair an agent role with a target
scope only. The agent inbound is agent-level (D26a), so a source row on an ordinary inbound scope
of an agent lets the calling agent call that agent. So `outbound_target` keeps every source row,
and the suite scores such a row as an over-grant.

**The owner of each row.** The suite checks each row against the owner of its scope
(`_scope_owners` in the test module, built with `_scope_owner`). A row on a scope that the service
does not own, or on a scope with no owner (a writer or PCE regression that puts the rule in the
wrong inbound), gives `(role, "<scope>@<service_id>")` (`_owned_pairs`). No truth table has that
pair, so a grant there is an over-grant, and the owner's `(role, scope)` pair is an under-grant.
So a rule that the PCE routes to the wrong service is never a true positive. An outbound bucket
keeps such a row whatever its scope is (`_on_target_scopes`), so the suite never drops a misrouted
row.

**Scope names.** The tool inbound maps are de-prefixed; the agent inbound maps keep the full scope
names. The scenario scope names have no `<owner>.` prefix, so both match the names that the truth
tables use — no re-prefixing logic is needed.

**A delegation scope.** A delegation scope is a scope of an agent, so its subject rows go to
`inbound` and to `outbound_subject`. The truth tables put such a pair only in
`OUTBOUND_SUBJECT_PAIRS`. So in `agent_delegation` a correct render also gives
`(user-role-shipment-coordinator, agent-scope-broker)` in `inbound`, and the suite scores it as an
`inbound` over-grant.

## Configuration (env)

| Variable | Purpose |
|---|---|
| `KEYCLOAK_URL` / `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` | Real Keycloak admin API — the `pipeline` fixture provisions one realm per scenario. |
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | The PRB's real LLM calls (`orchestrate_prb`, same as every other suite reusing this fixture). |
| `OPA_BIN` (optional) | Path to the `opa` binary; falls back to `opa` on `PATH`. The suite skips cleanly (not a failure) if neither resolves. |
| `EVAL_PIPELINE_PARALLELISM` (optional, default = scenario count, currently 8) | Max concurrent `ProcessPoolExecutor` workers in the shared `pipeline` fixture — see [Parallelization](#parallelization). An escape hatch, not a tuning knob with a "correct" lower value; lower it only if the LLM endpoint rate-limits under full concurrency. |

`eval/conftest.py` auto-loads the repo-root `.env` (gitignored, override=False) if present, so a
local `.env` with the above removes the need to `export`/source anything before invoking `pytest`
directly.

## Parallelization

The shared `pipeline` fixture (`eval/test_policy_pipeline_eval.py`, also used by the scenarios
suite in that file) provisions all 8 scenarios **concurrently**, one `ProcessPoolExecutor` worker
per scenario — not `pytest-xdist`'s `-n` (still unsupported/unneeded here: the parallelism lives inside the
fixture, across scenarios, not across pytest's own test-collection workers).

Separate **processes**, not threads, because the fixture's per-scenario setup mutates
process-global state while it runs — `os.environ["KEYCLOAK_REALM"]`/`["AIAC_POLICY_FILE"]`
(read at call time by `compute_and_apply`/`FilePolicySource.fetch()`) and a `KeycloakAdmin`
connection's `change_current_realm` — which two *threads* sharing one process would race on, but
separate OS processes don't (each gets its own `os.environ` and its own `KeycloakAdmin`). Each
worker also gets its own idp/store/opa port triple (offset from the module defaults by scenario
index), since fixed ports collide regardless of thread vs. process.

One further constraint, discovered empirically against a real Keycloak instance: concurrent
`admin.create_realm(...)` calls 409 with `"Duplicate resource error"` even across *distinct* realm
names — an internal Keycloak race on concurrent realm creation, not a naming collision on this
fixture's side. A `multiprocessing.Lock()`, passed to every worker via the pool's
`initializer`/`initargs` (a plain `multiprocessing.Lock()` cannot be passed as a regular per-task
argument under the `forkserver`/`spawn` start methods — only through that inheritance path),
serializes just the realm-provisioning step (`provision_keycloak_admin`). Everything after that per
scenario — the LLM-heavy `orchestrate_prb` calls and the idp/store/opa subprocess trio — still runs
fully concurrently; realm provisioning is a small fraction of one scenario's wall-clock next to the
PRB's several sequential LLM calls.

This benefits every suite that shares the `pipeline` fixture (the scenarios suite in
`test_policy_pipeline_eval.py` primarily, plus this suite) — see [Relationship to other integration
tests](#relationship-to-other-integration-tests).

## Best-effort proposals

The PRB's generate→audit loop (`aiac.agent.policy_rules_builder.graph`'s `_audit`) can reject a
scope/role decision outright — a genuine contradiction (`PolicyContradictionError`) or an
exhausted retry budget (`PolicyRulesBuilderError`, after `MAX_AUDIT_RETRIES=3`). By default this
aborts `orchestrate_prb()` entirely for that scenario — `compute_and_apply` never runs, so there's
no Rego to score at all, and the scenario's report entry shows "setup failed" with nothing else.

The shared `pipeline` fixture instead calls `orchestrate_prb(..., best_effort=True)` (see
[Parallelization](#parallelization) — same fixture, applies to both its consumers, confirmed with
the user): a rejected decision falls back to whatever was last proposed before the auditor
rejected it, built the same way the PRB's own `build` node would have
(`eval.best_effort_rules._best_effort_rules`, unit-tested unmarked). That best-effort rule flows
into `compute_and_apply` and gets rendered into real Rego like any other rule — every other
decision in the scenario proceeds normally, and the scenario as a whole now completes and scores.

**This is an explicit, user-requested tradeoff**: the rendered Rego for a scenario with a
best-effort decision can contain a rule a real deployment never would (the auditor rejected it —
a real pipeline run aborts instead). `record_property("best_effort_notes", ...)` — a
`{scope_or_role_name: reason}` dict — and the printed summary line name exactly which decisions
this applies to; the report renders it as an extra field with an explicit caveat whenever
non-empty. See [`policy-eval-correctness-prb.md` §Best-effort
proposals](policy-eval-correctness-prb.md#best-effort-proposals) for the sibling suite's identical
mechanism (same underlying `orchestrate_prb` parameter).

## Runbook

```bash
# Unit-test the pure-logic helpers first (no live infra, runs in the default fast pass):
.venv/bin/pytest -k test_correctness_e2e_helpers -v

# The suite itself — needs KEYCLOAK_URL + admin creds + LLM_* + opa on PATH:
.venv/bin/pytest -m eval -k test_policy_pipeline_correctness_e2e -v -s

# Sanity-check the fixture's primary consumer still passes against the now-parallelized fixture:
.venv/bin/pytest -m eval -k test_policy_pipeline_eval -v
```

`require_env_or_skip(...)` is the first line of the parametrized test function; `opa_bin()` skips the test
cleanly (not a failure) if `opa` isn't resolvable. Same skip-clean philosophy as every sibling
suite — this suite never false-passes when its infra isn't available.

## Expected output

Parametrized over all 8 scenario names (`sorted(SCENARIOS)`); expects all 8 to pass (zero
over-grants) given a healthy Keycloak instance and a well-behaved LLM endpoint (but see the
delegation-scope note in [Scoring source](#scoring-source-the-rendered-rego-data-maps-not-per-pair-decision-probing)
for `agent_delegation`). Before
`best_effort=True` was wired in (see [Best-effort proposals](#best-effort-proposals)), a real run
against the rossoctl kind cluster showed 6/8 passing and 2/8 failing at the *setup* stage, from the
pre-existing PRB audit/retry-convergence bug (see [Out of Scope](#out-of-scope)). With
`best_effort=True`, such a scenario now scores, and `best_effort_notes` names each decision that was
not auditor-approved.
Each test case `record_property`s `precision`, `recall`, `denial_precision`, `over_grants`,
`under_grants`, `incorrectly_denied` (the latter three as `{gate: sorted(pairs)}`), and
`best_effort_notes`, and prints:

```text
[correctness-e2e] wildcard_grant: precision=1.000 recall=1.000 denial_precision=1.000
  over_grants={}
  under_grants={}
  incorrectly_denied={}
  best_effort_notes={}
```

A failing case's assertion message names the scenario and the exact over-granted `(role, scope)`
pairs per gate.

## Test report

Covered by `eval/conftest.py`'s existing Markdown report and its generic
`"precision" in props and "recall" in props` render-branch dispatch (already used by
`test_prb_correctness`) — no per-suite special-casing was needed; the report picks up every
`eval/test_policy_pipeline_*.py` nodeid. See
[policy-eval-correctness-prb.md § Test report](policy-eval-correctness-prb.md#test-report) for the
render behavior itself.

## Trend log

Same mechanism as
[policy-eval-correctness-prb.md § Trend log](policy-eval-correctness-prb.md#trend-log) (#2091,
`eval/trend_log.py`) — `test_e2e_correctness` `record_property`s the same `true_positives`/
`denied_total` counts, and `eval/conftest.py` pools them into a `suite="correctness_e2e"` row in
the same committed `eval/trend_log.jsonl`, distinct from the PRB-level suite's
`"correctness_prb"` row.

## Relationship to other integration tests

This is **one** integration-test spec among several indexed by the master PRD
([../PRD.md](../specs/PRD.md), § *Test & evaluation specifications*).

- **Companion to, not a replacement for,
  [policy-eval-correctness-prb.md](policy-eval-correctness-prb.md).** Same corpus, same scorer,
  same philosophy — the PRB-level suite isolates the PRB's own grant decisions with no
  Keycloak/PCE/OPA in the loop; this suite scores the same corpus one layer further downstream,
  through the full pipeline, and is the only one of the two that can catch a PCE-merge or
  Rego-rendering bug.
- **Shares the `pipeline` fixture with the scenarios suite** (`test_policy_pipeline_eval.py`), so
  the [parallelization](#parallelization) and the [best-effort fallback](#best-effort-proposals)
  apply to both suites. The scenarios suite's per-cell tests (`test_inbound`/`test_outbound`/
  `test_grant_set_matches_truth_table`) can therefore show a real (and possibly wrong) result for a
  best-effort decision, instead of a skip. Confirmed as the accepted tradeoff with the user.
- **Carries the single flat `eval` marker** (`pyproject.toml`), like every suite under `eval/`.

## Out of Scope

- **Fixing the PRB audit/retry-convergence bug** (`aiac.agent.policy_rules_builder.graph._audit`,
  around line 200-220) that causes `agent_delegation`/`unreachable_resources` (or, on other runs,
  `confusable_agents` — which scenario(s) hit it varies with LLM sampling, but at least one of
  `agent_delegation`/`confusable_agents` reproduces consistently) to reject a scope/role decision
  with `PolicyContradictionError`/`PolicyRulesBuilderError`. Confirmed pre-existing and unrelated
  to this suite (reproduces identically in the PRB-direct `test_policy_pipeline_correctness_prb.py`
  suite).
  `best_effort=True` (see [Best-effort proposals](#best-effort-proposals)) changes how a rejection
  is *reported* (scored with a caveat instead of "setup failed") — it does not fix the underlying
  bug. The user has already deferred fixing `graph.py` itself as a separate follow-up — not this
  ticket's job.
- **An under-grant tolerance threshold.** Still TBD per the originating spec; under-grants are
  tracked/reported only, never gated.
- **New scenarios.** Reuses the existing 8-scenario corpus unmodified — see
  [policy-eval-correctness-prb.md § Taxonomy cross-check](policy-eval-correctness-prb.md#taxonomy-cross-check).
- **Parallelizing across pytest itself (`-n`/xdist).** The parallelism lives inside the shared
  `pipeline` fixture (see [Parallelization](#parallelization)), which already gets the wall-clock
  benefit without the 8x duplicated-provisioning problem `-n` would cause for a suite built on one
  session-scoped fixture.

## Blocked-by

None — #2089 (the PRB-level suite and `correctness_scorer.py`) is done, and this suite is the last
consumer that `correctness_scorer.py` was explicitly designed to support.
