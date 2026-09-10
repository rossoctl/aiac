# Eval suite — quick reference

`eval/` is a top-level package (sibling of `test/`) holding the AIAC evaluation framework's
live-infra test suites. Each `test_policy_pipeline_*.py` module below has its own full spec under
this directory — this README is a one-page map, not a replacement for those specs. Framework-wide
design (what each attribute measures, scoring philosophy, reporting) lives in
[`eval-framework.md`](eval-framework.md).

## Scripts

| Script | Marker | Level | Spec | What it checks |
|---|---|---|---|---|
| `test_policy_pipeline_eval.py` | `eval_extended` | End-to-end | [policy-eval-scenarios.md](policy-eval-scenarios.md) | Full Keycloak+PRB+PCE+OPA pipeline over the 8-scenario corpus — per-cell `opa eval` assertions, grant-set equality, guardrail `xfail` checks (prompt injection, direct contradiction). |
| `test_policy_pipeline_correctness_prb.py` | `eval_correctness_prb` | PRB-level | [policy-eval-correctness-prb.md](policy-eval-correctness-prb.md) | PRB called directly (synthetic Role/Scope, no Keycloak/OPA) — precision/recall/denial-precision per scenario, zero-tolerance over-grant gate. Feeds the committed trend log. |
| `test_policy_pipeline_correctness_e2e.py` | `eval_correctness_e2e` | End-to-end | [policy-eval-correctness-e2e.md](policy-eval-correctness-e2e.md) | Same scorer as the PRB-level suite, one layer further downstream (real Keycloak+PCE+OPA) — the only level that catches PCE-merge/Rego-rendering bugs. Feeds the committed trend log. |
| `test_policy_pipeline_consistency.py` | `eval_consistency` | PRB-level | [policy-eval-robustness-consistency.md](policy-eval-robustness-consistency.md) | PRB run N times (default 5) on identical input, exact grant-set equality gate. **Legacy suite — not yet extended to the new eval-framework spec** (no trend-log wiring; tracked as #2468). |
| `test_policy_pipeline_robustness.py` | `eval_robustness` | PRB-level | [policy-eval-robustness-consistency.md](policy-eval-robustness-consistency.md) | PRB grant sets checked under mechanical + semantic *meaning-preserving* perturbation (invariance family only). **Legacy suite — not yet extended to the new eval-framework spec** (no sensitivity family, no trend-log wiring; tracked as #2466/#2467). |

All five need only `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY` at minimum; `eval_extended` and
`eval_correctness_e2e` additionally need a live Keycloak and `opa`.

## `eval/.env`

`eval/conftest.py` auto-loads `eval/.env` (gitignored, `override=False`) before any suite runs, so
a local file removes the need to `export`/`source` anything before invoking `pytest` directly —
real shell/CI exports still take precedence.

| Variable | Required by | Purpose |
|---|---|---|
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | All five scripts | The PRB's real LLM calls. `LLM_MODEL` is also the pinned model version recorded on every trend-log row. |
| `KEYCLOAK_URL`, `KEYCLOAK_ADMIN_USERNAME`, `KEYCLOAK_ADMIN_PASSWORD` | `eval_extended`, `eval_correctness_e2e` | Real Keycloak admin API — the shared `pipeline` fixture provisions one realm per scenario. |
| `OPA_BIN` (optional) | `eval_extended`, `eval_correctness_e2e` | Path to the `opa` binary; falls back to `opa` on `PATH`. Both suites skip cleanly (not fail) if neither resolves. |
| `EVAL_PIPELINE_PARALLELISM` (optional) | `eval_extended`, `eval_correctness_e2e` | Max concurrent workers provisioning scenarios in the shared `pipeline` fixture; defaults to the scenario count (8). |
| `PRB_CONSISTENCY_REPEATS` (optional) | `eval_consistency` | Repeats per scenario; default 5, must be ≥ 2. |
| `EVAL_REPORT_TZ` (optional) | none (report only) | Timezone for the Markdown report's timestamp/filename; default UTC. |

Minimal `eval/.env` for the PRB-level suites only:

```
LLM_BASE_URL=<your LLM endpoint>
LLM_MODEL=<pinned model, e.g. Azure/gpt-5-mini-2025-08-07>
LLM_API_KEY=<your key>
```

Add these three for the end-to-end suites too:

```
KEYCLOAK_URL=<your Keycloak URL>
KEYCLOAK_ADMIN_USERNAME=<admin username>
KEYCLOAK_ADMIN_PASSWORD=<admin password>
```

## Runbook

`.venv/bin/pytest` from the repo root. All commands are opt-in — every marker below is excluded
from the default `pytest` run (`pyproject.toml`'s `addopts`).

The 8 scenarios are independent in every suite; `-n 8` (`pytest-xdist`, a declared `test`-extra
dependency) fans them out across processes for a near-linear wall-clock win wherever a suite
doesn't already parallelize scenarios internally:

```bash
# eval_extended — full pipeline; concurrency across scenarios is already internal to the
# shared `pipeline` fixture (ProcessPoolExecutor), so -n is not used here.
.venv/bin/pytest eval/test_policy_pipeline_eval.py -m eval_extended -v

# eval_correctness_prb — PRB-direct, no shared fixture, -n parallelizes cleanly.
.venv/bin/pytest eval/test_policy_pipeline_correctness_prb.py -m eval_correctness_prb -n 8 -v -s

# eval_correctness_e2e — same shared-fixture internal concurrency as eval_extended, no -n.
.venv/bin/pytest eval/test_policy_pipeline_correctness_e2e.py -m eval_correctness_e2e -v -s

# eval_consistency — PRB-direct, no shared fixture, -n parallelizes cleanly.
# (legacy suite; not yet wired into the trend log — see table above)
.venv/bin/pytest eval/test_policy_pipeline_consistency.py -m eval_consistency -n 8 -v

# eval_robustness — PRB-direct, no shared fixture, -n parallelizes cleanly.
# (legacy suite; not yet wired into the trend log — see table above)
.venv/bin/pytest eval/test_policy_pipeline_robustness.py -m eval_robustness -n 8 -v
```

Every suite's parametrized test is the first thing to call `require_env(...)`, so a missing
variable raises `SystemExit(2)` immediately rather than failing deep into a run.

## Reports

Every run of the five markers above writes a Markdown report to the gitignored `eval/reports/`
(`report_<DD_MM_HH_MM_SS>.md`) — see `eval/conftest.py`. The two Correctness suites additionally
append one row each to the **committed** `eval/trend_log.jsonl` (spec:
[eval-framework.md §9](eval-framework.md#9-reporting-and-trend-persistence)) — see
[policy-eval-correctness-prb.md § Trend log](policy-eval-correctness-prb.md#trend-log).
