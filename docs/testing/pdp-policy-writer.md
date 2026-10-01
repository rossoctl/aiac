# Launcher: PDP Policy Writer (OPA) — `generate_rego.py`

> **One spec among several.** This document specifies a **single** write-only launcher.
> Test specs live **one spec per test** under `docs/testing/`
> (a sibling of `specs/`), and the master PRD's *Test & evaluation specifications* section
> ([../PRD.md](../specs/PRD.md)) is the index of them. This is the **PDP Policy Writer (OPA)** write-only
> launcher — not the definition of integration testing in general, and not the only test spec.

## Location
`test/unit/pdp/policy/generate_rego.py`

## Description

A standalone launcher script that exercises the PDP Policy Writer (OPA) — the always-on
`AuthorizationPolicy` CR writer (`aiac.pdp.service.policy.opa.main:app`) — end-to-end and leaves the
generated Rego on disk for a human to eyeball. It is **not** a pytest
test, **not** part of CI, and **not** marked `@pytest.mark.integration` — it is run by hand when an
operator wants to see the actual `.rego` output for a known scenario.

The script drives the service through its real HTTP surface using the real client library, so it
covers the whole path: `PolicyModel` → HTTP → ASGI app → Rego generator → CR (and files on disk). Nothing is
mocked. There is no filesystem stub: the writer always server-side-applies the agent's
`AuthorizationPolicy` CR on the Kubernetes API, and it writes the same Rego to `REGO_OUTPUT_DIR` only
as an additive dump when `POLICY_WRITER_DUMP_REGO` is truthy
([../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md),
§ *Always-on CR write + additive debug dump*).

### What it does

1. Choose a local `REGO_OUTPUT_DIR` (a known directory the operator can inspect afterward).
2. Launch `aiac.pdp.service.policy.opa.main:app` as a **`uvicorn` subprocess** (no Docker), passing
   `REGO_OUTPUT_DIR` and `PORT` in its environment.
3. Poll `GET /health` until it returns `200 {"status": "ok"}` (the writer reports healthy once the
   Kubernetes API is reachable and the `AuthorizationPolicy` CRD is served; else 503), with a bounded timeout.
4. Build the fixed `PolicyModel` scenario (below) and apply it via
   `aiac.pdp.policy.library.api.apply_policy` — a real `POST /policy` over HTTP.
5. Terminate the `uvicorn` subprocess.
6. Print the `REGO_OUTPUT_DIR` path so the operator knows where to look.

**Write-only.** The script performs no read-back and makes **no assertions**. Verification is
manual: the operator opens the generated `.rego` files and confirms they match the package shapes in
[../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md)
(§ *Rego package structure*). There is no pass/fail exit contract beyond the script running to
completion.

## Scenario

A single agent, fixed so the generated Rego is reproducible and reviewable by inspection. The values
below come from `test/system/scenario.py`.

| Element | Value |
|---------|-------|
| Agent | `github-agent` |
| Agent roles | `source_operations`, `issue_operations` |
| Agent scopes | `source-access`, `issues-access` |
| Subject (user) roles | `developer`, `tester`, `devops` (`devops` has no grants) |
| Tool | `github-tool` |
| Tool scopes | `source-read`, `source-write`, `issues-read`, `issues-write` |
| Calling service (source) | none |

Role → access, as encoded by the model's inbound and outbound rules:

- `developer` — source read/write, issues read.
- `tester` — issues read/write.
- `devops` — no access (in no rule).

This user→tool access is encoded in the model's `outbound_subject_allow_rules` (`(user_role, tool_scope)`
pairs — this fixture is allow-only), which the outbound package renders as `subject_role_allow_scopes`. The model's
`inbound_subject_allow_rules` (user→agent-scope) and `outbound_target_allow_rules` (agent-role→tool-scope) are unchanged.

With the dump on, applying this `PolicyModel` writes two files under `REGO_OUTPUT_DIR`, one per
policy path of the agent's CR (`<ns>/<name>` comes from the agent id):

- `<ns>/<name>/inbound/request.rego` — package `authbridge.client.inbound.request`
- `<ns>/<name>/outbound/request.rego` — package `authbridge.client.outbound.request`

Both must match the package shapes in
[../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md): the input is the
live plugin shape (`input.identity.subject` and `input.identity.client_id`; on the outbound side also
`input.identity.service_id`, `input.mcp.method` and `input.mcp.params.name`); all role/scope maps are
embedded in the package; the inbound gate is subject-mandatory + source-optional; the outbound
`tools/call` gate requires both subject and target capability to pass on the same
`input.mcp.params.name`. Its **subject** gate is user→**tool** — the tool name must be in
`subject_role_allow_scopes[role]` (grouped from `outbound_subject_allow_rules`) for a role of the
subject — distinct from the inbound user→agent gate. `target_allow_ok` (the capability gate) is
`input.mcp.params.name in target_allow_scopes[input.identity.service_id]`, and `target_allow_scopes`
keeps its target-id keys with the scope values de-prefixed to the bare tool names. The MCP session
messages (`initialize`, `notifications/initialized`, `ping`, `tools/list`) are allowed to a target when
at least one tool of that target passes the same per-tool check. The `agent_roles` ×
`agent_role_scopes` maps are still emitted (informational — a single map, no allow/deny split). All rule lists here are allow-only, so the
deny maps (`*_deny_scopes`) are emitted empty (`{}`); the generated `allow` still applies deny-overrides, which is vacuous when
the deny lists are empty. Because the input carries no per-request scope on the inbound side, that decision is
coarse — a principal passes on having access to **at least one** relevant scope.

The `PolicyModel` / `AgentPolicyModel` / `PolicyRule` objects come from `aiac.policy.model.models`
([../components/policy-model.md](../specs/components/policy-model.md)); the script constructs them in
Python rather than reading them from Keycloak.

## Configuration (env)

| Variable | Purpose | Default |
|----------|---------|---------|
| `AIAC_PDP_POLICY_URL` | Base URL the library client posts to. The launcher sets it to `http://127.0.0.1:{PORT}` itself; a value you set is ignored | `http://127.0.0.1:7072` |
| `REGO_OUTPUT_DIR` | Directory the writer's additive dump writes `.rego` files to (only when `POLICY_WRITER_DUMP_REGO` is truthy); passed to the subprocess and printed at the end | `test/unit/pdp/policy/rego_out` |
| `PORT` | Port the `uvicorn` subprocess binds; the launcher derives `AIAC_PDP_POLICY_URL` from it | `7072` |

The launcher derives `AIAC_PDP_POLICY_URL` from `PORT`, so the client always posts to the port the
subprocess listens on.

## Runbook

```bash
.venv/bin/python test/unit/pdp/policy/generate_rego.py
# then inspect the printed REGO_OUTPUT_DIR, e.g.:
#   <ns>/<name>/inbound/request.rego
#   <ns>/<name>/outbound/request.rego
```

To pin the output location and port explicitly:

```bash
REGO_OUTPUT_DIR=/tmp/aiac-rego PORT=7072 \
  .venv/bin/python test/unit/pdp/policy/generate_rego.py
```

## Testing Decisions

- **Highest seam available.** The test drives the service through its real HTTP boundary
  (`AIAC_PDP_POLICY_URL`) using the real client library
  ([../components/library-pdp-policy.md](../specs/components/library-pdp-policy.md), `aiac.pdp.policy.library.api`),
  and observes the real filesystem output. It asserts on **external behavior** (files produced on
  disk), never on internal generator functions.
- **Launch as a `uvicorn` subprocess.** The script spawns
  `uvicorn aiac.pdp.service.policy.opa.main:app` as a child process (no Docker), polls `GET /health`
  before applying the model, and terminates the subprocess at the end. This exercises the full
  HTTP + ASGI stack the way a caller would, and keeps the service lifecycle self-contained.
- **Write-only, human-verified.** The value of this test is the concrete `.rego` output for a known
  scenario — so a reviewer can confirm the ID-only redesign renders correctly. It intentionally
  makes no automated assertions; the generator's assertable behavior is covered by the OPA
  service/`rego.py` unit tests.
- **Prior art.** The writer itself and its unit tests (`test/unit/pdp/service/policy/opa/`,
  covering `main.py` and `rego.py`) verify endpoint and rendering behavior automatically; this
  launcher complements them with an eyeball-the-output workflow. The live-Keycloak pytest
  integration tests (issue `testing/5.1-integration-tests.md`) are the marker-gated counterpart for
  the read-side services.

## Relationship to other integration tests

This is **one** test spec among several indexed by the master PRD
([../PRD.md](../specs/PRD.md), § *Test & evaluation specifications*). It is distinct from the
**live-Keycloak pytest integration tests**, which are a different flavor — `@pytest.mark.integration`,
run in/near CI against a live Keycloak/NATS, asserting on typed responses — tracked by issue
`testing/5.1-integration-tests.md`. This launcher, by contrast, is standalone, write-only, and
manually inspected.

**Status: not built yet** — no live-Keycloak/NATS pytest suite exists under `test/`; if it is built, it takes `@pytest.mark.system` (live services), not `integration`.

For the full identity→policy pipeline (Keycloak → PRB → PCE → OPA) — which drives the same
`github-agent` scenario end to end through the real Policy Computation Engine rather than a
hand-built `PolicyModel` — see [policy-pipeline.md](policy-pipeline.md).

Tracking issue for this test: `testing/5.2-pdp-writer-integration-test.md`.

## Out of Scope

- **The Rego generator implementation** — package rendering and the gate logic
  are specified by [../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md)
  and covered by the OPA service unit tests, not here.
- **The canonical policy model** — `PolicyModel` / `AgentPolicyModel` / `PolicyRule` shapes and
  semantics belong to [../components/policy-model.md](../specs/components/policy-model.md).
- **The `AuthorizationPolicy` CR schema** — the writer always writes the CR; its schema is specified by
  [../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md), not here.
- **Live-Keycloak integration** — the marker-gated pytest integration tests (issue
  `testing/5.1-integration-tests.md`).
- **Automated pass/fail** — no assertions, no CI wiring, no `@pytest.mark.integration`.

## Further Notes

- Depends on the launcher script itself (created separately) and the OPA Policy Writer
  (`aiac.pdp.service.policy.opa.main`). The former filesystem stub (issue
  `pdp-policy-writer/1.14-pdp-policy-writer-opa-stub.md`) is gone; only its additive dump remains.
- The scenario is deliberately fixed. If `test/system/scenario.py` changes, update the
  scenario table here to match so the generated Rego stays reviewable against a single source of
  truth.
