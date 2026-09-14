# Evaluation strategy

> Eval specs live **one spec per suite** under `docs/evaluation/` (a top-level sibling of
> [`../specs/`](../specs/PRD.md) and [`../testing/`](../testing/testing-strategy.md)). This document
> is the framing those specs slot into; [`README.md`](README.md) is the one-page operational map and
> [`eval-framework.md`](eval-framework.md) is the framework-wide design (what each attribute
> measures, scoring philosophy, reporting).

Where [testing](../testing/testing-strategy.md) asks *does the code do what it is supposed to do*,
**evaluation** asks *how well does the LLM-driven policy pipeline do its job* — the Policy Rules
Builder's grant/deny decisions over a corpus of authored scenarios, scored against hand-authored
truth tables.

## One flat `eval` marker

Every suite under `eval/` carries the single marker `@pytest.mark.eval`. The five former per-suite
markers (`eval_extended`, `eval_correctness_prb`, `eval_correctness_e2e`, `eval_consistency`,
`eval_robustness`) were **collapsed into one flat `eval`**. Consequences:

- Selection is marker-only, consistent with the rest of the suite: `.venv/bin/pytest -m eval`.
- The default `pytest` deselects `eval` (it is heavy and live-infra), so evaluation is opt-in.
- To run **one** suite, pass its file path or use `-k` — the marker no longer distinguishes them
  (see [README.md § Runbook](README.md#runbook)).
- The committed trend log disambiguates rows by **nodeid substring**, not by marker — see
  [`../../eval/conftest.py`](../../eval/conftest.py) and
  [eval-framework.md §9](eval-framework.md#9-reporting-and-trend-persistence).

## Clean-skip, never false-pass

Every suite's parametrized test calls `require_env_or_skip(...)` first, so a missing
`LLM_*` / `KEYCLOAK_*` variable (or absent `opa`) **skips the suite cleanly** rather than failing
deep into a run or silently passing.

## Suites

See [README.md § Scripts](README.md#scripts) for the full table. In brief:

| Suite | Layer | Spec |
|---|---|---|
| `test_policy_pipeline_eval.py` | Full Keycloak+PRB+PCE+OPA pipeline | [policy-eval-scenarios.md](policy-eval-scenarios.md) |
| `test_policy_pipeline_correctness_prb.py` | PRB-direct (no Keycloak/OPA) | [policy-eval-correctness-prb.md](policy-eval-correctness-prb.md) |
| `test_policy_pipeline_correctness_e2e.py` | Real Keycloak+PCE+OPA, one layer downstream of PRB | [policy-eval-correctness-e2e.md](policy-eval-correctness-e2e.md) |
| `test_policy_pipeline_consistency.py` | PRB-direct, N-run grant-set equality | [policy-eval-robustness-consistency.md](policy-eval-robustness-consistency.md) |
| `test_policy_pipeline_robustness.py` | PRB-direct, perturbation invariance | [policy-eval-robustness-consistency.md](policy-eval-robustness-consistency.md) |
