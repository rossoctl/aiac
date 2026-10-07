# Test lanes

Contract for the global `test` skill. The skill reads this file to learn how
this repo selects and runs each test lane. For the test taxonomy and for where
to put a new test, see `docs/testing/testing-strategy.md`.

## Selection rules

- Selection is **marker-only**. Never give `pytest` a path. `testpaths` in
  `pyproject.toml` collects `test/` and `eval/`.
- The default `addopts` is
  `-m "not integration and not system and not llm and not eval"`. Thus a bare
  `pytest` runs the offline unit lane.
- A command-line `-m` overrides the default (the last `-m` wins). `-m` accepts
  boolean expressions. `-k` narrows **within** a lane by name substring.
- There is **no literal `unit` marker**. The unit lane is the untagged tests.
  Thus `-m "unit or llm"` does **not** add the unit tests. To run the unit tests
  **and** the `llm` lane, remove `llm` from the exclusion:
  `-m "not integration and not system and not eval"`.
- Use `--collect-only -q` to see which tests a selection gives before you run a
  live lane.
- Always use the project venv: `.venv/bin/pytest`.

```bash
.venv/bin/pytest                              # unit lane (the default addopts)
.venv/bin/pytest -m system                    # only the system lane
.venv/bin/pytest -m "system or eval"          # union of two lanes
.venv/bin/pytest -m system -k uc1_onboard     # system lane, narrowed by name substring
```

## Lanes

| Lane | Selection | `test` skill profile | Needs |
|---|---|---|---|
| unit | bare `pytest` | `unit` | Nothing |
| integration | `-m integration` | `integration` | Nothing. **Reserved but empty**: no tests and no directory yet. |
| llm | `-m llm` | `system` | An LLM endpoint only (no cluster, no Keycloak) |
| system | `-m system` | `system` | A wired Kind cluster, Keycloak admin credentials, an LLM endpoint |
| eval | `-m eval` | `system` | Keycloak, an LLM endpoint, `opa` on `PATH` for the e2e level |

All live lanes (`llm`, `system`, `eval`) **skip cleanly** when their env is not
set or the cluster is not wired. A skip is not a pass.

## Env

The live lanes read the repo-root `.env` (gitignored): `LLM_BASE_URL`,
`LLM_API_KEY`, `LLM_MODEL`, `KEYCLOAK_URL`, `KEYCLOAK_ADMIN_USERNAME`,
`KEYCLOAK_ADMIN_PASSWORD`. Load it before you run a live lane:

```bash
set -a; . .env; set +a
```

## `llm` lane

The live-LLM Policy Rules Builder tests
(`test/unit/agent/policy_rules_builder/test_graph_live_llm.py`) run the **real**
LLM end-to-end. They assert that the emitted `(name, effect)` rule set matches
the policy text: for allow-only policies, and for policies with explicit,
description-driven, and exclusivity denies. The tests mock only the role/scope
descriptions and the policy source. The `_structured_call` LLM seam stays live.
The lane needs only `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY`.

```bash
set -a; . .env; set +a
.venv/bin/pytest -m llm
```

## `system` lane

The system tests close the **real OPA evaluation loop**. They onboard through
the in-cluster Controller, send real HTTP requests **through AuthBridge**, and
assert the allow/deny of the **deployed OPA plugin**. They do not use
`opa eval`, so they do not need `opa` on `PATH`.

Preconditions:

- A rossoctl/Kind cluster with the AuthBridge OPA pipeline wired into both legs,
  and the demo `github-agent` / `github-tool` deployed and registered.
- The AIAC global combiner. It denies a pod that has no `AuthorizationPolicy`
  CR, and the Controller does not start without it.
- `k8s/opa-kind-enable.sh` does both steps (run it one time).

The lane runs under the enforcement side that `AIAC_ENFORCEMENT_SIDE` sets in the
`aiac-agent-config` ConfigMap (default `target-side`: each callee, the tool
included, checks its own inbound from its own CR). To change the side, see
`docs/agents/deploy.md`.

Full prerequisites, wiring, the side switch, and manual probe commands:
`k8s/opa-kind-runbook.md`. The per-loop shape: `test/system/uc1_onboard.py`.

```bash
k8s/opa-kind-enable.sh          # one time: wire the OPA plugin and the AIAC combiner into Kind
set -a; . .env; set +a
.venv/bin/pytest -m system
```

## `eval` lane

The heavy, live-infra policy-pipeline evaluation suite under `eval/`. See
`docs/evaluation/`.

```bash
set -a; . .env; set +a
.venv/bin/pytest -m eval
```

## Smoke test (not a pytest lane)

This script calls every `Configuration` method against a live service at
`AIAC_PDP_CONFIG_URL` (default `http://127.0.0.1:7071`):

```bash
.venv/bin/python test/unit/idp/configuration/show_keycloak_data.py
```
