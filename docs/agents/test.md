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
.venv/bin/pytest -m integration               # only the integration lane (offline)
.venv/bin/pytest -m system                    # only the system lane
.venv/bin/pytest -m "system or eval"          # union of two lanes
.venv/bin/pytest -m system -k uc1_onboard     # system lane, narrowed by name substring
```

## Lanes

| Lane | Selection | `test` skill profile | Needs |
|---|---|---|---|
| unit | bare `pytest` | `unit` | Nothing |
| integration | `-m integration` | `integration` | Nothing (offline: several AIAC units in one process, no cluster, no LLM endpoint). The tests are under `test/integration/`, a mirror of `src/aiac/`. |
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

A git worktree does not get the gitignored `.env` of the main checkout. Copy or
link it into the worktree first, or every live lane skips.

## `integration` lane

The integration tests make several AIAC units work together in one process, with
no cluster, no Keycloak and no LLM endpoint. So they need no env and no `.env`,
and they do not skip. The default `addopts` deselects them, so a bare `pytest`
does not run them. The tests wire the real focal resolver, Service Policy
Builder (with the LLM seam stubbed), PCE and PDP Policy Writer render — for
example the D32 shared roles and scopes, quarantine lift, shared decommission
and snapshot repair. Fakes stand in for Keycloak, the Policy Model Store and the
Kubernetes API (`fakes.py` next to the tests).

```bash
.venv/bin/pytest -m integration
```

## `llm` lane

The live-LLM Policy Rules Builder tests
(`test/unit/agent/policy_rules_builder/test_graph_live_llm.py`) run the **real**
LLM end-to-end. They assert that the emitted `(name, effect)` rule set matches
the policy text: for allow-only policies, and for policies with explicit and
description-driven denies. The tests mock only the role/scope
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

- A rossoctl/Kind cluster with the AuthBridge OPA pipeline wired into both legs.
- The AIAC global combiner. It denies a pod that has no `AuthorizationPolicy`
  CR, and the Controller does not start without it.
- `k8s/opa-kind-enable.sh` does both steps (run it one time).
- The event path wired: the NATS broker and the `aiac-event-listener` Keycloak
  SPI (see `docs/testing/uc1-onboarding-pipeline.md`, "Preconditions").
- An LLM key that the endpoint accepts, in the Controller's Secret
  `aiac-system/aiac-agent-secret`. The in-cluster Controller does not read
  `.env`. If the endpoint refuses the key, each onboarding rolls back, and the
  fixtures time out with "agent did not converge" or "tool did not converge".
  The Controller log then shows `LLMCredentialsError`. To check or change the
  key: `k8s/aiac-deployment-guide.md`, step 3b, "Check or change the API key".

Do **not** deploy the demo `github-agent` / `github-tool` yourself. The session
fixture (`onboarded_stack` in `test/system/uc1_onboard.py`) builds and loads the
demo images (`demo/assets/kind-load.sh`), removes any demo workloads and their
registrations, deploys the workloads as the onboarding trigger, and removes them
again at teardown.

The lane runs under the enforcement side that `AIAC_ENFORCEMENT_SIDE` sets in the
`aiac-agent-config` ConfigMap (default `target-side`: each callee, the tool
included, checks its own inbound from its own CR). No test changes the side. To
test both sides, run the lane, do a clean redeploy with the other side (see
`docs/agents/deploy.md`), and run the lane again.

The platform prerequisites, wiring, verification and the setting of the side:
`k8s/opa-kind-runbook.md`. The fixture enables Direct Access Grants on the login
client `rossoctl` itself, once per session, and turns it off again at session end
if it turned it on, so the lane needs no manual realm step. A client attribute
records that the harness turned it on, so a run that is killed is undone by the
next run. A
manual probe with the password grant outside the lane needs the grant set by hand:
see the runbook section "Direct Access Grants on the login client". The per-loop
shape: `test/system/uc1_onboard.py`.

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
