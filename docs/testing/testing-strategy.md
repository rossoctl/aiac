# Testing strategy

> Test specs live **one spec per test** under `docs/testing/` (a top-level sibling of
> [`../specs/`](../specs/PRD.md)); the evaluation suite is specced separately under
> [`../evaluation/`](../evaluation/README.md). This document is the taxonomy those specs slot into.

AIAC's automated checks split into two top-level trees, each its own pytest collection root
(`testpaths = ["test", "eval"]` in [`pyproject.toml`](../../pyproject.toml)):

- **Testing** — `test/` — does the code do what it is supposed to do? Correctness of units and
  their integration.
- **Evaluation** — `eval/` — how *well* does the LLM-driven policy pipeline do its job? Precision,
  recall, robustness, consistency over a scenario corpus. See the
  [evaluation strategy](../evaluation/evaluation-strategy.md).

## Selection is marker-only

**No path is ever passed to `pytest`.** `testpaths` collects both trees; selection is by marker.
The default `addopts` deselects every live-infra / eval marker:

```
addopts = ["-m", "not integration and not system and not llm and not eval"]
```

so a bare `pytest` is the offline unit suite. A command-line `-m` overrides that default (last
`-m` wins): `-m integration`, `-m system`, `-m llm`, `-m eval`.

## Testing levels (scope-based)

The `test/` tree has three levels, distinguished by **what a test needs to run**, not by what it
covers:

| Level | Marker | Location | Needs |
|---|---|---|---|
| **unit** | *(untagged)* | `test/unit/` (mirrors `src/aiac/`) | Nothing external — in-process, a single unit under test. Runs in the default `pytest`. |
| **integration** | `integration` | *(reserved — no such tests yet)* | Several AIAC units cooperating in-process on a laptop, **no cluster**. The marker exists so the level has a home; the directory is intentionally absent until the first such test. |
| **system** | `system` | `test/system/` | A live Kind cluster / Rosso / deployed AIAC — see [`k8s/opa-kind-runbook.md`](../../k8s/opa-kind-runbook.md). Closes the real OPA evaluation loop through AuthBridge. |

## The `llm` tag (orthogonal)

`llm` is **not** a level — it is an orthogonal tag on a test that calls a **real external LLM** but
needs **no cluster**. It lets a cluster-free live-LLM test be selected on its own with `-m llm`.
The live-LLM Policy Rules Builder suite
(`test/unit/agent/policy_rules_builder/test_graph_live_llm.py`) is the canonical example: it drives
the real LLM end-to-end but mocks only the role/scope descriptions and policy source in-process, so
it needs an LLM endpoint and nothing else. It **skips cleanly** when `LLM_BASE_URL` / `LLM_MODEL` /
`LLM_API_KEY` are unset.

## Clean-skip discipline

A live suite must never false-pass when its environment is absent. System and live-LLM tests use
`require_env_or_skip(...)` (a clean `pytest.skip`) so an unset variable or an unwired cluster
**skips** rather than fails or silently passes.

## Specs in this directory

| Spec | Level | What it documents |
|---|---|---|
| [pdp-policy-writer.md](pdp-policy-writer.md) | write-only launcher | Standalone `generate_rego.py` launcher — applies a `PolicyModel` and writes Rego for manual inspection. Not a `@pytest.mark`-tagged test. |
| [policy-pipeline.md](policy-pipeline.md) | write-only launcher | Standalone `policy_pipeline.py` launcher driving the full identity→policy pipeline for manual Rego inspection. |
| [uc1-onboarding-pipeline.md](uc1-onboarding-pipeline.md) | system | The UC-1 onboarding ladder — `@pytest.mark.system`, real in-cluster onboarding asserted through the deployed OPA plugin. |
