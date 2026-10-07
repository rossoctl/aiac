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
| **unit** | *(untagged)* | `test/unit/` (mirrors `src/aiac/`) | Nothing external — in-process, a single unit under test — **except a live LLM endpoint when the test also carries the orthogonal `llm` tag** (see below); those are deselected by the default `pytest`. Runs in the default `pytest`. |
| **integration** | `integration` | `test/integration/` (mirrors `src/aiac/`) | Several AIAC units cooperating in-process on a laptop, **no cluster**, no LLM endpoint. Deselected by the default `pytest`; run with `-m integration`. The first test is the D32 test of shared roles and scopes (`test/integration/policy/computation/test_shared_roles.py`). |
| **system** | `system` | `test/system/` | A live Kind cluster / Rosso / deployed AIAC — see [`k8s/opa-kind-runbook.md`](../../k8s/opa-kind-runbook.md). Closes the real OPA evaluation loop through AuthBridge. |

## The `llm` tag (orthogonal)

`llm` is **not** a level — it is an orthogonal tag on a test that calls a **real external LLM** but
needs **no cluster**. It lets a cluster-free live-LLM test be selected on its own with `-m llm`. An
`llm`-tagged test keeps the placement of its scope level, so a single-unit live-LLM test lives under
`test/unit/`; the LLM endpoint it reaches is the one exception the tag opts into over the unit
tree's otherwise "nothing external" rule.
The live-LLM Policy Rules Builder suite
(`test/unit/agent/policy_rules_builder/test_graph_live_llm.py`) is the canonical example: it drives
the real LLM end-to-end but mocks only the role/scope descriptions and policy source in-process, so
it needs an LLM endpoint and nothing else. It **skips cleanly** when `LLM_BASE_URL` / `LLM_MODEL` /
`LLM_API_KEY` are unset.

## Clean-skip discipline

A live suite must never false-pass when its environment is absent. System and live-LLM tests use
`require_env_or_skip(...)` or an equivalent direct `pytest.skip` (a clean skip) so an unset variable or an unwired cluster
**skips** rather than fails or silently passes.

## Writing a new test — where and how

The placement of a test follows what the test **touches**, not what it is about.
Use this ladder. The first match wins:

1. **One unit, in-process, no external service** → **unit**. Put it under
   `test/unit/` at the path that **mirrors** the module under test. For example,
   a test for `src/aiac/pdp/policy/…` goes in `test/unit/pdp/policy/`. Do not tag
   it (no `pytestmark`). A bare `pytest` then runs it. If the mirror directory
   does not exist, create it.
2. **Several AIAC units cooperating in-process, no cluster** → **integration**.
   Tag the module with `pytestmark = pytest.mark.integration` (or the single test
   with `@pytest.mark.integration`). Put it under `test/integration/`, at the
   path that mirrors the main module under test (`test/integration/` is a
   mirror of `src/aiac/`, as `test/unit/` is). If the mirror directory does not
   exist, create it. Stub the LLM seam; a test that calls a real LLM also gets
   the `llm` tag (see below).
3. **Needs a live Kind cluster / Rosso / deployed AIAC** → **system**. Put it in
   `test/system/` and tag it `@pytest.mark.system`. It **must skip cleanly** when
   the cluster or env is missing. Use `require_env_or_skip`. Do not use
   `require_env`, because it exits hard.
4. **Heavy policy-pipeline evaluation** → **eval**. Put it under `eval/` and tag
   it `@pytest.mark.eval`. The same clean-skip rule applies. Exception: offline
   tests of the eval harness helpers (scorer, dashboard, trend log, …) also live
   under `eval/`, but have no tag. A bare `pytest` runs them in the unit lane.

Then, if the test calls a real external LLM but needs no cluster, also add the
`llm` tag. A unit or integration test can have the `llm` tag. To put more than one
marker on a test, use `pytestmark = [pytest.mark.system, pytest.mark.llm]`.

Rules of thumb:

- Use the **lowest** level that still tests what you need. Most tests are unit
  tests.
- Do not import by a hard-coded path. Get the repo root with
  `Path(__file__).resolve().parents[N]`. **Count N from the actual location of the
  file**: a file in `test/unit/pdp/policy/` is 4 levels below the repo root.
- Each test above the unit level skips cleanly when its infra is not available.

To run each lane, see [`../agents/test.md`](../agents/test.md).

## Specs in this directory

| Spec | Level | What it documents |
|---|---|---|
| [pdp-policy-writer.md](pdp-policy-writer.md) | write-only launcher | Standalone `generate_rego.py` launcher — applies a `PolicyModel` and writes Rego for manual inspection. Not a `@pytest.mark`-tagged test. |
| [policy-pipeline.md](policy-pipeline.md) | system | `test/system/test_policy_pipeline.py` — `@pytest.mark.system`, the full inbound/outbound matrix + negative controls over the fully onboarded stack, asserted through the deployed OPA plugin. |
| [uc1-onboarding-pipeline.md](uc1-onboarding-pipeline.md) | system | The UC-1 onboarding ladder — `@pytest.mark.system`, real in-cluster onboarding asserted through the deployed OPA plugin. |
