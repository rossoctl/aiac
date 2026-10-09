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
covers the whole path: policy model → HTTP → ASGI app → Rego generator → CRs (and files on disk). Nothing is
mocked. There is no filesystem stub: the writer always server-side-applies one
`AuthorizationPolicy` CR per entry of the policy model — one per managed service, agent or tool — on
the Kubernetes API, and it writes the same Rego to `REGO_OUTPUT_DIR` only
as an additive dump when `POLICY_WRITER_DUMP_REGO` is truthy
([../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md),
§ *Always-on CR write + additive debug dump*).

### What it does

1. Choose a local `REGO_OUTPUT_DIR` (a known directory the operator can inspect afterward).
2. Launch `aiac.pdp.service.policy.opa.main:app` as a **`uvicorn` subprocess** (no Docker), passing
   `REGO_OUTPUT_DIR` and `PORT` in its environment.
3. Poll `GET /health` until it returns `200 {"status": "ok"}` (the writer reports healthy once the
   Kubernetes API is reachable and the `AuthorizationPolicy` CRD is served; else 503), with a bounded timeout.
4. Build the fixed scenario (below) as the policy model of one enforcement side — a
   `TargetSidePolicyModel` (the default) or an `AgentSidePolicyModel` — and apply it via
   `aiac.pdp.policy.library.api.apply_policy` — a real `POST /policy` over HTTP. The writer reads the
   side from the policy-model tag (`enforcement_side`), not from an env var.
5. Terminate the `uvicorn` subprocess.
6. Print the `REGO_OUTPUT_DIR` path so the operator knows where to look.

**POST only.** The launcher calls only `POST /policy` (`apply_policy`, an upsert of one CR per
entry). It does not call the other writer routes: `PUT /policy` (`replace_policy`: upsert, then delete
every other CR with the managed-by label `app.kubernetes.io/managed-by: aiac-pdp-policy-writer`),
`DELETE /policy/services/{service_id:path}` (`delete_service_cr`: delete the CR of one service; a 404
counts as success), and `DELETE /policy` (`delete_policy`: delete every AIAC CR). With the AIAC global
combiner, a pod that has no client CR is denied (D20), so each of these deletes denies the pods of the
services whose CR it removes. A hand-run launcher must not do that on a shared cluster. The writer unit
tests cover these routes.

**Write-only.** The script performs no read-back and makes **no assertions**. Verification is
manual: the operator opens the generated `.rego` files and confirms they match the package shapes in
[../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md)
(§ *Rego package structure*). There is no pass/fail exit contract beyond the script running to
completion.

## Scenario

A single agent and a single tool, fixed so the generated Rego is reproducible and reviewable by
inspection. The values below come from `test/system/scenario.py`.

| Element | Value |
|---------|-------|
| Agent | `github-agent` |
| Agent roles | `source_operations`, `issue_operations` |
| Agent scopes | `source-access`, `issues-access` |
| Subject (user) roles | `developer`, `tester`, `devops` (`devops` has no grants) |
| Tool | `github-tool` |
| Tool scopes | `source-read`, `source-write`, `issues-read`, `issues-write` |
| Calling service (source) | agent inbound: none; tool inbound (target side): `github-agent` |

Role → access, as encoded by the rules of the policy model:

- `developer` — source read/write, issues read.
- `tester` — issues read/write.
- `devops` — no access (in no rule).

The two sides encode the same rules in different entries:

- **Target side** (the default) — `TargetSidePolicyModel(services=[SPM(github-agent), SPM(github-tool)])`.
  A rule is stored on the SPM of the service that owns its scope. So `SPM(github-agent)` holds the
  user→agent-scope rules in `inbound_allow_rules`. `SPM(github-tool)` holds, in `inbound_allow_rules`,
  the user→tool rules (`(user_role, tool_scope)` pairs — this fixture is allow-only) and the
  agent-role→tool-scope rules. Each `Role` carries its `kind` (`User` or `Agent`) and its `actorIds`
  (the usernames, or the agent's id), so the shared projection (`project_inbound`, D18b) can build the
  identity maps `subject_roles` and `source_roles`. The tool's inbound package renders the user→tool
  rules as `subject_role_allow_scopes` and the agent-role→tool-scope rules as
  `source_role_allow_scopes`.
- **Agent side** — `AgentSidePolicyModel(agents=[APM(github-agent)], pass_through=[github-tool])`.
  This user→tool access is encoded in the APM's `outbound_subject_allow_rules` (`(user_role, tool_scope)`
  pairs — this fixture is allow-only), which the outbound package renders as `subject_role_allow_scopes` (keyed by role and then by the target, LIM-02). The APM's
  `inbound_subject_allow_rules` (user→agent-scope) and `outbound_target_allow_rules` (agent-role→tool-scope) are unchanged.
  github-tool is only an ID in `pass_through`.

With the dump on, applying this policy model writes four files under `REGO_OUTPUT_DIR`, one per
policy path of each CR (`<ns>/<name>` comes from the service id, through `identity_ref`). Both sides
give the same four paths:

- `<ns>/<agent-name>/inbound/request.rego` — package `authbridge.client.inbound.request`
- `<ns>/<agent-name>/outbound/request.rego` — package `authbridge.client.outbound.request`
- `<ns>/<tool-name>/inbound/request.rego` — package `authbridge.client.inbound.request`
- `<ns>/<tool-name>/outbound/request.rego` — package `authbridge.client.outbound.request`

Every file must match the package shapes in
[../components/pdp-policy-writer-opa.md](../specs/components/pdp-policy-writer-opa.md). The input is the
live plugin shape: `input.identity.subject` and `input.identity.client_id`; on a tool's inbound also
`input.mcp.method` and `input.mcp.params.name`; on the agent-side outbound also
`input.identity.service_id`, `input.mcp.method` and `input.mcp.params.name`. All role/scope maps are
embedded in the package. A rules-based package has `default allow := false` (D25). A pass-through
package is only `allow := true` (D24).

- **The agent's inbound** (both sides, D26a): the inbound gate is subject-mandatory + source-optional.
  Because the input carries no per-request scope on the inbound side, that decision is
  coarse — a principal passes on having access to **at least one** relevant scope (agent-level).
- **Target side — the tool's inbound** (D26): two gates on the same bare `input.mcp.params.name`, and
  a deny vetoes an allow. The user gate maps `input.identity.subject` → `subject_roles` →
  `subject_role_allow_scopes`. The calling-agent gate maps `input.identity.client_id` →
  `source_roles` → `source_role_allow_scopes`. The callee is the key, so there is no target-id map.
  The MCP session messages (`initialize`, `notifications/initialized`, `ping`, `tools/list`) are
  allowed when at least one of the tool's own tools passes the same per-tool check. Every other MCP
  method is denied. No request without identity passes (D27).
- **Target side — every outbound** (the agent's and the tool's): a pass-through (D24).
- **Agent side — the agent's outbound:** the outbound
  `tools/call` gate requires both subject and target capability to pass on the same
  `input.mcp.params.name`. Its **subject** gate is user→**tool** — the tool name must be in
  `subject_role_allow_scopes[role][input.identity.service_id]` (grouped from
  `outbound_subject_allow_rules` by role and then by the owner of the scope copy of each rule, LIM-02)
  for a role of the subject — distinct from the inbound user→agent gate. `target_allow_ok` (the capability gate) is
  `input.mcp.params.name in target_allow_scopes[input.identity.service_id]`, and `target_allow_scopes`
  keeps its target-id keys with the scope values de-prefixed to the bare tool names. The MCP session
  messages (`initialize`, `notifications/initialized`, `ping`, `tools/list`) are allowed to a target when
  at least one tool of that target passes the same per-tool check. The `agent_roles` ×
  `agent_role_scopes` maps are still emitted (informational — a single map, no allow/deny split).
- **Agent side — the tool's CR:** a pass-through CR; both request packages are pass-throughs (D24).

All rule lists here are allow-only, so the
deny maps (`*_deny_scopes`) are emitted empty (`{}`); the generated `allow` still applies deny-overrides, which is vacuous when
the deny lists are empty.

The `TargetSidePolicyModel` / `AgentSidePolicyModel` / `ServicePolicyModel` / `AgentPolicyModel` /
`PolicyRule` objects come from `aiac.policy.model.models`
([../components/policy-model.md](../specs/components/policy-model.md)); the script constructs them in
Python rather than reading them from Keycloak.

## Configuration (env)

| Variable | Purpose | Default |
|----------|---------|---------|
| `AIAC_PDP_POLICY_URL` | Base URL the library client posts to. The launcher sets it to `http://127.0.0.1:{PORT}` itself; a value you set is ignored | `http://127.0.0.1:7072` |
| `REGO_OUTPUT_DIR` | Directory the writer's additive dump writes `.rego` files to (only when `POLICY_WRITER_DUMP_REGO` is truthy); passed to the subprocess and printed at the end | `test/unit/pdp/policy/rego_out` |
| `PORT` | Port the `uvicorn` subprocess binds; the launcher derives `AIAC_PDP_POLICY_URL` from it | `7072` |
| `AIAC_ENFORCEMENT_SIDE` | The side of the policy model the launcher builds: `target-side` (a `TargetSidePolicyModel`) or `agent-side` (an `AgentSidePolicyModel`). The launcher reads it; the writer does not (it reads the side from the policy-model tag) | `target-side` |

The launcher derives `AIAC_PDP_POLICY_URL` from `PORT`, so the client always posts to the port the
subprocess listens on.

## Runbook

```bash
.venv/bin/python test/unit/pdp/policy/generate_rego.py
# then inspect the printed REGO_OUTPUT_DIR, e.g.:
#   <ns>/<agent-name>/inbound/request.rego
#   <ns>/<agent-name>/outbound/request.rego
#   <ns>/<tool-name>/inbound/request.rego
#   <ns>/<tool-name>/outbound/request.rego
```

To pin the output location and port explicitly:

```bash
REGO_OUTPUT_DIR=/tmp/aiac-rego PORT=7072 \
  .venv/bin/python test/unit/pdp/policy/generate_rego.py
```

To render the agent side instead of the default target side:

```bash
AIAC_ENFORCEMENT_SIDE=agent-side REGO_OUTPUT_DIR=/tmp/aiac-rego-agent-side \
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
  the read-side services. The writer unit tests (untagged, in
  the unit lane: a bare `.venv/bin/pytest`) cover:
  - the policy-model parse: a target-side body parses to `TargetSidePolicyModel`, an agent-side body to
    `AgentSidePolicyModel`, and a body with a wrong or missing tag gives 422 (D18a);
  - a tool CR: the name and namespace from `identity_ref`, the managed-by label, the field manager,
    and both request packages (D20);
  - a batch (`POST /policy`, one CR per entry);
  - `PUT /policy`: it deletes the stale labelled CRs and keeps the others (D18c);
  - `DELETE /policy/services/{service_id:path}`: a 404 counts as success (D18c);
  - the Rego with `opa eval` (`_assert_opa_allow` / `_opa_verdict`, which skip without `opa` on
    PATH): both renderings for an agent and for a tool; the tool inbound (a granted `tools/call`
    passes, an ungranted one is denied, a deny vetoes an allow, the session messages pass only for a
    granted caller or for the tool's own client (the self-discovery rule; never `tools/call`), the
    other MCP methods are denied, a request with no identity is denied — D26,
    D27); the agent inbound (agent-level, and a request with no identity is denied — D26a, D27); and
    the pass-through outbound allows (D24);
  - LIM-02, the per-target outbound subject maps (in `test/unit/pdp/service/policy/opa/test_rego.py`):
    `test_outbound_subject_grant_on_one_target_gives_nothing_on_another` and
    `test_outbound_subject_deny_on_one_target_blocks_nothing_on_another` (two different scopes with
    the same bare name on two tools: each rule decides on its own target, for `tools/call` and
    `tools/list`); `test_outbound_shared_scope_grant_and_deny_are_per_copy` (a D32 shared scope, with
    the grant and the deny rules placed on one copy or on both copies: a grant or a deny decides only
    on the copy that it names, as under target side);
    `test_outbound_session_on_a_shared_scope_copy_with_no_rule_is_denied` and
    `test_outbound_subject_map_has_no_entry_for_a_copy_with_no_rule`;
    `test_outbound_deny_on_both_copies_blocks_the_user_on_both_copies` and
    `test_outbound_subject_deny_map_has_the_deny_of_each_copy_on_that_copy` (the APM that the PCE
    gives when both copies deny a role: one deny rule for each copy, and a grant of another role on
    one copy; the deny blocks the user on both copies);
    `test_outbound_subject_deny_map_keys_a_deny_only_on_its_own_copy` and
    `test_outbound_subject_deny_on_a_copy_that_the_agent_is_denied_stays_on_that_copy`;
    `test_outbound_subject_map_takes_each_target_tool_from_its_own_copy` and
    `test_outbound_subject_deny_map_takes_each_target_tool_from_its_own_copy`;
    `test_outbound_subject_maps_are_keyed_by_role_then_target`; and
    `test_outbound_subject_map_escapes_its_keys_and_values`.

  The shared projection (D18b) has its own unit tests under `test/unit/policy/model/`: for one SPM,
  `project_inbound` gives the same inbound gates as the APM inbound that `_derive` builds.

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
- **The canonical policy model** — `PolicyModel` (the base, with its `enforcement_side` tag) /
  `TargetSidePolicyModel` / `AgentSidePolicyModel` / `ServicePolicyModel` / `AgentPolicyModel` /
  `PolicyRule` shapes and semantics belong to [../components/policy-model.md](../specs/components/policy-model.md).
- **The writer routes other than `POST /policy`** — `PUT /policy`, `DELETE /policy/services/{service_id:path}`
  and `DELETE /policy` are covered by the writer unit tests, not by this launcher.
- **The `AuthorizationPolicy` CR schema** — the writer always writes the CRs; their schema is specified by
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
