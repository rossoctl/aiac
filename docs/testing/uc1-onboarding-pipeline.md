# System Test: uc1-onboarding-pipeline — a ladder of UC-1 onboarding tests

> **One spec among several.** This document specifies the **UC-1 onboarding** system tests.
> Test specs live under `docs/testing/` (a sibling of `specs/`), indexed
> by the master PRD's *Test & evaluation specifications* section ([../PRD.md](../specs/PRD.md)). This is the
> phase-1 service-onboarding demo driven end-to-end through the **real UC-1 agent** against
> **really-deployed** demo workloads, and **enforced by the deployed AuthBridge OPA plugin** — not the
> definition of system testing in general.

> **Ladder, not one test.** This spec was previously a single "complete two-policy" test that assumed a
> **two-stack** topology (one AIAC stack per `policy.md` variant) which is **not deployed** and so could
> never run. It is now a **ladder** of three gradual, runnable happy-path tests against **one** AIAC
> stack, one failure-path rung (rung 5), two Controller-restart rungs (rungs 6 and 7), and one
> **deferred** rung (two-policy):
>
> | Rung | Issue | Onboards | Proves |
> |---|---|---|---|
> | 1 | `testing/5.4.1-uc1-onboard-agent-only.md` | agent only | agent discovery + inbound enforcement stand alone; **inbound gate only** — no tool onboarded, so there is no real outbound call and the outbound leg is not probed live |
> | 2 | `testing/5.4.2-uc1-onboard-agent-then-tool.md` | agent → tool | onboarding the tool **after** the agent completes the tool check (PCE additive merge): under target side it writes the tool's own CR; under agent side it completes the agent's outbound gate. Also the subject on every leg (D31): each client links `aiac-username-sub`, and the exchanged token has `sub` = the username |
> | 3 | `testing/5.4.3-uc1-onboard-tool-then-agent.md` | tool → agent | the happy path; **and, vs rung 2, onboarding-order-independence** |
> | 4 | `testing/5.4.4-uc1-onboard-two-policies.md` | two policies | **deferred / TBD**; two-stack impl discarded |
> | 5 | `testing/5.4.5-uc1-onboard-failure-rollback.md` | agent / tool (build failure) | UC-1 **compensating rollback + PCE quarantine**: the quarantine deletes the CR, so a failed agent is denied (it has no CR, D20), a failed tool is unreachable, and a successful re-onboarding lifts the quarantine. Also the **MCP session** for a granted user. Test file: `test/system/test_uc1_onboard_failure_rollback.py` |
> | 6 | — | agent + tool, then Controller restarts | the **resync** at Controller start (D28) leaves every CR unchanged; a service with **no CR is denied** (D20); the next resync writes the missing CR again. Test file: `test/system/test_uc1_onboard_resync.py` |
> | 7 | — | agent + tool, then a side switch | the **enforcement-side switch** (D16, D29): the demo passes under each side, and a Controller restart with the other `AIAC_ENFORCEMENT_SIDE` value moves every CR, with no mixed state. Test file: `test/system/test_uc1_onboard_side_switch.py` |
>
> **Enforcement side.** Every rung runs under the live **enforcement side** (D16): the
> `AIAC_ENFORCEMENT_SIDE` value in the `aiac-agent-config` ConfigMap (default `target-side`). The
> verdict tables do not depend on the side. Only the CR shapes and the place of a deny depend on it
> (see *[CR end state for each side](#cr-end-state-for-each-side)*).

> **Relationship to `policy-pipeline`.** This is the **onboarding-order-focused sibling** of
> [policy-pipeline.md](policy-pipeline.md). Identical *scenario facts and truth tables* (same three users,
> same role→access facts, same inbound/outbound matrices) and the **same** live enforcement loop — both
> onboard through the real in-cluster UC-1 Controller and assert the **deployed OPA plugin's** allow/deny
> over real HTTP through AuthBridge. `policy-pipeline` is the **full happy-path matrix + negative
> controls** over the fully onboarded stack; this ladder **isolates onboarding-order properties** across
> three rungs (agent-only; agent→tool; tool→agent + order-independence).

## Location

`test/system/` — pytest modules marked `@pytest.mark.system`, one per **implemented** rung
(`test_uc1_onboard_agent_only.py`, `test_uc1_onboard_agent_then_tool.py`,
`test_uc1_onboard_tool_then_agent.py`, `test_uc1_onboard_failure_rollback.py` for rung 5,
`test_uc1_onboard_resync.py` for rung 6, and `test_uc1_onboard_side_switch.py` for rung 7). Rung 4
(two-policy) is **deferred and has no test file**. Rungs 1–3 are thin modules that wrap `onboarded_stack` in a
one-line session fixture and supply only their own rung's oracle (verdicts computed from
`scenario_uc1.py`) and live assertions. Rung 5 wraps `pristine_stack` in a module-scoped fixture and
drives its own four phases. Rungs 6 and 7 wrap `onboarded_stack([agent, tool])` in a module-scoped
fixture, so each rung's stack is torn down when its tests end, and then drive their own Controller
restarts. They import three shared modules:

- `scenario_uc1.py` — the pure-data scenario (users/roles + the pair-lists expressed over the
  **discovered, workload-prefixed** names `github-tool.source-read`, `github-agent.source_operations`, …,
  plus the **bare** runtime names `source-read` the oracle keys on). The old two-variant machinery
  (`VARIANTS`, `POLICY_EXPLICIT`, per-variant URLs/pods) is gone; the truth tables (`USERS`,
  `USER_ROLES`, `INBOUND_PAIRS`, `OUTBOUND_SUBJECT_PAIRS`, `OUTBOUND_TARGET_PAIRS`, `TOOL_SCOPES`,
  `AGENT_SCOPES`, `TOOL_REQUEST_NAMES`) and the single **abstract** `policy.md` remain.
- `uc1_onboard.py` — the shared live harness: config, Keycloak provisioning/cleanup
  (`provision_realm_and_users` / `cleanup_provisioned` / `clear_policy_store`), the **deploy/teardown of
  the rung's workload manifests** (which is what fires the event-driven onboarding trigger — see
  *[Per-rung flow](#per-rung-flow)*), the outbound token-exchange-leg prep (`ensure_github_tool_route` /
  `grant_exchange_scope` / `restart_agent`), the bundle-convergence poll, the live decision oracle
  (`expected_inbound` / `expected_outbound_bare`, `inbound_decision` / `outbound_decision`), and
  `onboarded_stack(workloads)` — the whole per-rung fixture flow parameterised by the ordered workload
  list. It also holds the teardown helpers (`delete_workload_registrations`, `delete_workload_crs`
  — the agent's and the tool's CR; it replaces `delete_agent_cr` — and `sweep_authpolicies`), the
  rung-5 helpers (`pristine_stack`, `controller_llm_unusable`, `publish_service_event`,
  `workload_client`, `authpolicy_policies`, `cr_has_grants`, `spm_present`, `controller_logs`,
  `mcp_session_decisions`), and the side helpers for every rung: `live_enforcement_side` (reads
  `AIAC_ENFORCEMENT_SIDE` from the live `aiac-agent-config` ConfigMap; absent → `target-side`),
  `rego_is_pass_through` (the package is `allow := true` only), `cr_matches_side` (a CR has the
  shape of a given side for an agent or a tool — see
  *[CR end state for each side](#cr-end-state-for-each-side)*), and `deny_origin` (where the raw
  response of a denied tool call comes from: github-tool's inbound or the agent's outbound). The
  rung-6 and rung-7 helpers are `aiac_crs` (every CR with the managed-by label
  `app.kubernetes.io/managed-by: aiac-pdp-policy-writer`, name → `spec.policies`),
  `restart_controller` (rollout restart + wait for Ready), and `controller_enforcement_side(side)`
  (patch `AIAC_ENFORCEMENT_SIDE` in `aiac-agent-config`, restart the Controller, and restore the
  original value with a second restart on every exit path). The subject-scope check (D31) is
  `SUBJECT_SCOPE` (`aiac-username-sub`), the pure helper `subject_scope_problems`, its live reader
  `subject_scope_link_problems`, and `require_subject_scope` (see *[Per-rung flow](#per-rung-flow)*,
  step 2). The rung-2 `sub` probes are `login_subject` (a password-grant token through `rossoctl`) and
  `exchanged_subject` (a token exchanged as the agent client to the tool audience). The race hint
  (handoff 20, D33) is the pure helper `commit_race_hint`, its live reader
  `controller_commit_race_hint`, and `append_hint` (see *[Per-rung flow](#per-rung-flow)*, step 2).
  Resolution-by-`name` (`"{ns}/github-agent"` / `"{ns}/github-tool"`) is still how the harness
  **reads back** Keycloak state; it no longer resolves an internal UUID to trigger onboarding (except
  rung 5, which re-fires the trigger for an existing client — see below).
- `launcher.py` — the shared live-cluster half: `kubectl` wrappers, `port_forward`, `resolve_pod`,
  `mint_token`, `exchange_token` (an RFC 8693 token exchange as a client; it raises
  `TokenExchangeError`), `jwt_claim`, `inbound_probe` / `outbound_probe`, `inbound_outcome` / `outbound_outcome`
  (classified by body, not status: an OPA denial → `deny`, a token-exchange refusal → `error`),
  `poll_until`, and the skip gates (`require_pipeline`,
  `require_env_or_skip`, `require_event_path`, `verify_subject_mapper`). There is **no** `opa_eval`, no `kubectl_cp` of
  `/rego`, and no standalone probe module: the evaluator is the deployed AuthBridge OPA plugin, and the
  input documents are built by AuthBridge's own parsers.

## Description

`@pytest.mark.system` tests that validate the **phase-1 deliverable** and confirm the runnable demo:
they drive the **real UC-1 Service Onboarding agent** through its **production, event-driven trigger** —
**deploying** the `github-agent` + simplified `github-tool` workloads — and then assert the **enforced
decision** is correct by driving **real HTTP requests through AuthBridge** and reading the **deployed OPA
plugin's** allow/deny.

**The production trigger is a Keycloak `CLIENT_CREATED` event, not an HTTP call.** Deploying a workload
is what starts onboarding; the tests fire it by *deploying*, not by a `POST`:

```
deploy github-agent / github-tool into the Kind cluster
  → rossoctl-operator reconciles the bundled AgentRuntime CR
  → operator registers a Keycloak client  (client.name = "{ns}/{workload}")
  → Keycloak emits a CLIENT_CREATED admin event
  → AIAC Keycloak SPI (aiac-event-listener) publishes to the NATS Event Broker
  → the AIAC Agent's NATS consumer runs onboard_service(uuid)   ← same handler the POST calls
```

The consumer is wired into the in-cluster Controller and calls the same `onboard_service` handler the
debugging `POST` route calls, which upserts the `AuthorizationPolicy` CR of each affected service (D23)
on the live Kubernetes API — the tool's CR included. The SPI maps `CLIENT_CREATED` to the internal client UUID and publishes
`aiac.apply.service.{uuid}`, so the harness never resolves a UUID to trigger onboarding (except rung 5,
which reads the client UUID with `workload_client` and re-fires the trigger for an existing client by
publishing `aiac.apply.service.<uuid>` with `publish_service_event`). The `POST` route
survives only as a **documented debugging escape hatch** (`aiac-agent.md`); the system tests do not call
it.

Live enforcement is now **in scope and is the whole point**: each rung onboards, enables the outbound
token-exchange leg where a tool is present (Part B), waits for `bundle-service` + the AuthBridge OPA
sidecars to recompose and reload the bundle, then drives real requests through AuthBridge on the **inbound
leg always** — plus the **outbound leg only where a tool is onboarded** (rungs 2/3, 5–7)
(`jwt-validation` builds `input.identity` inbound; `token-exchange` + `mcp-parser` build the outbound
`input.identity` + `input.mcp.params.name`). Under **target side** the agent's outbound is a
pass-through (D24), and github-tool's own inbound OPA decides each tool call: on github-tool's inbound,
`jwt-validation` builds `input.identity` from the exchanged token (`subject` = the user, `client_id` =
the calling agent) and `mcp-parser` builds `input.mcp.params.name`. Under **agent side** the agent's
outbound OPA decides, as above. Rung 1 (agent only) probes the **inbound leg only**: with no
tool onboarded there is no real `agent -> tool` call, and token-exchange short-circuits before OPA (no
`github-tool` audience grant on the agent client), so an outbound probe would observe a Keycloak audience
refusal rather than the AIAC OPA policy the rung exists to prove. The agent's own CrewAI reasoning flow is
**not** triggered — the probes are synthetic requests through AuthBridge (an inbound `ping/nonexistent` JSON-RPC call;
an outbound bare `tools/call`) — but the traffic is real and the deployed plugin enforces it.

The enforced decision is the **artifact under test** — the LLM/PCE that produced the policy might be
wrong — so the tests never trust it. Expected verdicts are **computed from** the `scenario_uc1.py`
pair-lists (the intended policy), keyed on the **bare** runtime tool names AuthBridge sends. A mismatch
fails the test and names the exact cell.

Because they need a live rossoctl/Kind cluster with the AuthBridge OPA pipeline wired into both legs +
operator + Keycloak + a real LLM, they are `@pytest.mark.system` (out of the default unit run,
`-m "not integration and not system and not llm and not eval"`) and **skip cleanly** when the cluster/pipeline is not wired or the env is unset
(they never false-pass).

## Topology

- **One in-cluster AIAC stack + the deployed AuthBridge OPA pipeline.** A single AIAC agent (Controller +
  in-pod NATS consumer) + Policy Model Store + **OPA Policy Writer**, mounting the **single abstract**
  `policy.md`. AIAC runs in-cluster so UC-1's `analyze_tool` can reach the tool's MCP endpoint at its
  cluster-internal DNS name (`github-tool.{ns}.svc.cluster.local`); the tests trigger onboarding by
  **deploying** the workload (the event-driven chain above), not over `kubectl port-forward`.
- **The event path is part of the wired platform.** The NATS Event Broker
  (`aiac-event-broker-service`, ns `aiac-system`) and the Keycloak SPI listener (`aiac-event-listener`,
  emitting `CLIENT_CREATED` over NATS) are standing platform components — like the OPA pipeline / SPIRE /
  bundle-service — that carry a workload deployment through to `onboard_service`.
- **The deployed OPA plugin is the evaluator.** Onboarding upserts the `AuthorizationPolicy` CR of each
  affected service (D23) on the live Kubernetes API — one CR per managed service, the agent's and the
  tool's (D20); `bundle-service` (in `rossoctl-system`) recomposes the namespace bundle,
  and each workload pod's AuthBridge OPA sidecar polls + reloads it (~20–30 s). There is **no** `/rego`
  dump and **no** `kubectl cp` — the artifact under test is the enforced decision, not a file.
- **One enforcement side for every callee.** The Controller reads `AIAC_ENFORCEMENT_SIDE` (ConfigMap
  `aiac-agent-config`, default `target-side`) at start. Under target side, each callee (github-agent
  and github-tool) checks the access to itself in its own inbound OPA, from its own CR. Under agent
  side, github-agent's outbound OPA checks its calls to github-tool, and github-tool has a pass-through
  CR. The two sides never exist together. The harness reads the live side with
  `live_enforcement_side` and asserts the CR shapes and the deny origin of that side.
- **Convergence by polling real decisions.** After the CR is upserted (and, for the outbound leg, after
  Part B + the agent restart), `onboarded_stack` polls real requests through AuthBridge until this run's
  policy is reflected in the plugin's decisions, up to `AIAC_BUNDLE_TIMEOUT`.

## Preconditions (the wired platform — not stood up by the tests)

Deployment and Keycloak registration are **no longer** preconditions — they are test steps (see
*[Per-rung flow](#per-rung-flow)*). What the tests assume is the standing platform, and they **skip
cleanly** when any of it is absent (they never stand it up, and never false-pass):

- **Pipeline wired.** The AuthBridge OPA plugin is wired into both legs (`k8s/opa-kind-enable.sh`);
  `require_pipeline` skips cleanly if not (no `kubectl`, `AuthorizationPolicy` CRD not served,
  `bundle-service` not Running, the `opa` plugin not present on both legs, or the global combiner
  still allows a pod that has no client CR — see the next item).
- **The changed global combiner (D20).** `k8s/opa-kind-enable.sh` applies a changed `default`
  `AuthorizationPolicy` CR in `rossoctl-system`. Its two request packages have no
  `client_ok if not data.authbridge.client.inbound.request` /
  `client_ok if not data.authbridge.client.outbound.request` line, so the combiner denies a pod that
  has no client CR. The response packages keep the default. The Controller does not start without
  this combiner (start check #4, D30). So `require_pipeline` reads the `default` CR and skips cleanly
  when a line is still there or the CR is missing. A `helm upgrade` of the operator reverts the
  change; run the script again.
- **Tool pods with the sidecar.** The script sets `injectTools=true`. It restarts the
  `rossoctl.io/type=tool` pods as well as the `rossoctl.io/type=agent` pods, because the webhook
  injects the sidecar only on pod CREATE. The namespace inbound pipeline has `mcp-parser` and `opa`
  (the onboarding check #2 for a tool under target side). The fixture deploys fresh workload pods, so
  github-agent and github-tool both get the sidecar at CREATE.
- **The enforcement side.** `AIAC_ENFORCEMENT_SIDE` in the `aiac-agent-config` ConfigMap selects the
  side (default `target-side`; the other value is `agent-side`). The suite runs under the live side.
  Only rung 7 changes it, and rung 7 restores it on every exit path.
- **Event Broker running.** The NATS broker `aiac-event-broker-service` (ns `aiac-system`, port `4222`,
  from `k8s/event-broker-deployment.yaml`) is deployed and reachable, and the Agent's in-pod consumer is
  connected — its `aiac-init` initContainer gates on NATS and provisions the `aiac-events` stream. The
  broker is opt-in; when it is absent the suite skips.
- **Keycloak SPI listener installed.** The custom Keycloak image carries the AIAC SPI (`keycloak-spi/`)
  and the realm has `aiac-event-listener` in its `eventsListeners` with `adminEventsEnabled: true`. This
  is manual/Helm setup outside this repo (`keycloak-spi/README.md`). Without it a `CLIENT_CREATED` event
  never reaches NATS and onboarding never fires — the suite skips.
- **Kind image toolchain on the test host.** The `github-agent` and simplified `github-tool` images must
  be present in the Kind node before deploy — but the fixture now **fulfills that itself** as a test step:
  before deploying, it runs `demo/assets/kind-load.sh` (`load_workload_images`) to build-if-absent +
  `kind load` exactly the image(s) the rung deploys. So the standing precondition is only the toolchain the
  load needs: the `kind` CLI, `kubectl`, and a container runtime (`podman`/`docker`) on the machine running
  pytest, and that machine hosting the Kind node (the suite's local-Kind topology — a remote-cluster runner cannot
  `kind load`). When the toolchain is absent the load exits non-zero and the test **fails loudly** (never a
  false pass); `--rebuild` is not passed, so an already-built image is only re-loaded, never silently
  rebuilt from stale source. The `deploy_workload` step itself only `kubectl apply`s manifests and waits. The
  target Kind cluster is derived from the current kube-context (`kind` names it `kind-<cluster>`; override with
  `AIAC_KIND_CLUSTER`), so a cluster not named `rossoctl` still loads correctly.
- **Users + realm roles.** The fixture provisions them (UC-1 does not) — see
  *[Scenario](#scenario)* — via `KeycloakAdmin` into `AIAC_TEST_REALM`, **before** deploying (the PRB
  reads the realm role universe when the event fires `onboard_service`); idempotent; left in place.
  `verify_subject_mapper` confirms the `username → sub` mapper of the login client `rossoctl` + Direct Access Grants (else skip).
  It checks only the login token (through the `rossoctl` client). The exchanged token gets the same
  mapping from the client scope `aiac-username-sub`, which AIAC links to each onboarded client (D31).
  That link is not a precondition: AIAC makes it at onboarding, so `require_subject_scope` checks it
  as a test step (*[Per-rung flow](#per-rung-flow)*, step 2). Together the two checks cover both
  sources of the rule.

## Per-rung flow

**Provision realm/users + mount policy → load demo image(s) into the Kind node → deploy workload(s)
sequentially, each converging before the next → enable outbound leg (rungs 2/3, 6, 7) → poll bundle → drive
real requests + assert → full teardown.**

1. **Clean slate, then setup — ordering matters.** First `capture_aiac_crs` writes the leftover CRs of
   an earlier run to the pytest host (phase `pre-run-slate`; see step 6). Then the pre-run reset to a
   no-workloads slate: `undeploy_workload` for both workloads, then `_scrub_to_pristine` — `delete_workload_registrations`
   (the two Keycloak clients, their `*-aud` scopes, the credentials Secret), `delete_workload_crs` (the
   agent's and the tool's `AuthorizationPolicy` CRs), `sweep_authpolicies` (every other `AuthorizationPolicy` CR),
   `cleanup_provisioned` (the **agent's and tool's** provisioned realm roles + client scopes), and
   `clear_policy_store` (persisted SPMs in the in-cluster Policy Store, whose SQLite outlives redeploys,
   so pre-fix cruft would otherwise accumulate — onboarding appends with `override=False`). Then
   `reenable_provisioned_clients` restores any disabled client, and the harness polls until both clients
   are gone (a leftover client would stop the deploy from firing `CLIENT_CREATED` again). Then `provision_realm_and_users` (idempotent) + `ensure_agent_policy` (mount
   the abstract `policy.md` on the Controller pod). Both **must** run **before** deploying, because when
   the `CLIENT_CREATED` event fires `onboard_service` the PRB reads the realm role universe and the
   mounted `policy.md`.
2. **Load images, then deploy in the rung's order, one workload at a time, waiting for convergence** before
   deploying the next. First `load_workload_images` runs `demo/assets/kind-load.sh` (build-if-absent +
   `kind load`) for exactly the image(s) this rung deploys, fulfilling the images precondition on the Kind
   host; then `deploy_workload` only `kubectl apply`s the workload's manifests and waits. Deploying is the
   trigger:
   the operator registers the Keycloak client (`client.name = "{ns}/{workload}"`), Keycloak emits
   `CLIENT_CREATED`, the SPI publishes over NATS, and the Agent's consumer runs `onboard_service`.
   - **Tool** (`github-tool`) → `onboard_service` classifies it a **Tool**, writes its bootstrap CR
     before Provision (so that the discovery `tools/list` passes D20; under target side through the self-discovery rule), reads
     the MCP manifest,
     provisions scopes `github-tool.{source-read, source-write, issues-read, issues-write}`, sets
     `client.type=Tool`. The rules on the tool's scopes are stored on `SPM(github-tool)` (the service
     that owns the scopes). The PCE stores `SPM(github-tool)` also when it has zero rules (D21), so the
     tool is in the managed set and gets its own CR with both request packages (D20). Under target side
     that CR has the rules-based tool inbound (D26) and a pass-through outbound (D24). Under agent side
     it is a pass-through CR (D24). **Tool convergence** = those `github-tool.*` client scopes are
     provisioned in Keycloak **and** github-tool's CR is present with both request packages. The
     bootstrap CR is present before Provision, so the CR check alone does not prove the final CR. For the
     tool, the CR check is the per-workload gate, because a live decision on github-tool's inbound
     needs the outbound token-exchange leg (step 3). The live proof is the step-4 poll.
   - **Agent** (`github-agent`) → `onboard_service` classifies it an **Agent**, reads the AgentCard,
     provisions **one operator role per skill** `github-agent.{source_operations, issue_operations}`
     (mirroring the scopes) + scopes `github-agent.{source_operations, issue_operations}`, sets
     `client.type=Agent`; the Service Policy Builder maps roles→scopes via the real PRB (real LLM,
     `temperature=0`) and the Controller calls `compute_and_apply(rules, override=False)`; the OPA Policy
     Writer upserts the agent's `AuthorizationPolicy` CR. **Agent convergence** = a live inbound
     `dev-user` request through AuthBridge → OPA reaches `allow` (polled up to `AIAC_BUNDLE_TIMEOUT`).
     The harness does not check that the CR is present: a CR proves only that the operator reconciled,
     not that OPA loaded the bundle. The combiner denies the agent pod until its CR is loaded (D20), so
     the `allow` cannot come from a missing CR.

     Sequential deploy-and-wait is what keeps rung order meaningful (rung 2: agent→tool; rung 3:
     tool→agent) and the order-independence proof intact.
   - **The gate budgets and the event-before-commit race (handoff 20, D33).** The agent gate polls up
     to `AIAC_BUNDLE_TIMEOUT` (default 300 s) and the tool gate up to `AIAC_ONBOARD_TIMEOUT` (default
     600 s). An SPI without the handoff-20 fix publishes `CLIENT_CREATED` before Keycloak commits the
     new client. Then the Controller's first IdP read gets Keycloak's `404 "Could not find client"`,
     and the onboarding starts only with the NATS redelivery after `ACK_WAIT` (600 s), so one race hit
     fails the gate. The fix has two layers. The Keycloak image with the SPI that publishes after the
     commit removes the race. The IdP Configuration Service (`aiac-pdp-config`), which keeps a Keycloak
     `404`, and the Controller (`aiac-agent`), which then reads a new client again for a bounded time
     (`ONBOARD_CLIENT_WAIT_ATTEMPTS` / `ONBOARD_CLIENT_WAIT_BACKOFF`, about 30 s by default), are
     defense in depth. Use the default gates when the deployed SPI image has the fix, or when both the
     IdP Configuration Service and the Controller images have it. Otherwise one race hit can still fail
     the gate. Verified live on 2026-10-07 (`kind-rossoctl`, with the fix in all three images: the SPI,
     `aiac-pdp-config` and `aiac-agent`): rungs 1, 2 (twice) and 3 passed with the default gates, each
     rung in its own pytest call. In all 7 onboardings, the Controller's first IdP read came 0.05-0.2 s
     after the Keycloak `CREATE` admin event and got `200`. The IdP log had no `404` and the Controller
     log had no `Could not find client`. Thus the bounded wait and the delayed nak did not trigger; only
     unit tests cover them. The run did not test the case where only the IdP Configuration Service and
     the Controller images have the fix.
   - **The race hint in a gate failure.** When the agent gate or the tool gate times out, its
     `RuntimeError` message ends with a hint if the Controller log shows the race:
     `controller_commit_race_hint` reads the Controller log (`kubectl logs`, the current
     `app=aiac-agent` pod in `aiac-system`, container `aiac-agent`) from 30 s before the deploy, at most
     the last 5000 lines. The pure helper `commit_race_hint` keeps only the lines with Keycloak's
     `Could not find client` (not `Could not find client scope`) or the Controller's
     `ServiceNotVisibleError` that name the UUID of the workload's client (if the client is gone or
     its lookup fails, every such line counts). So a redelivery for a client of an earlier run gives no hint.
     The hint gives the number of
     these lines and the first one, says that the onboarding event probably came before the Keycloak
     commit (handoff 20 / D33), and tells what to check: that the Keycloak image has the
     `aiac-event-listener` SPI that publishes after the commit, and that the Controller has the bounded
     wait (`ONBOARD_CLIENT_WAIT_*`). With no such line there is no hint. The read is read-only and
     best-effort: a failure gives a warning and no hint, never an exception, so the gate's own error
     stays.
   - **The subject scope (D31), for each workload.** Right after a workload converges,
     `onboarded_stack` calls `require_subject_scope(admin, workload)`. It checks with the admin API
     that `aiac-username-sub` exists, has a mapper with the `username → sub` mapping (it checks the
     mapper type and mapping, not the mapper name) and no `aiac.managed` marker, and is a default scope
     of the workload's client, and that the login client `rossoctl` does not link it. AIAC makes this
     link at onboarding, so a missing
     link is an AIAC fault: the check **fails** (it raises `RuntimeError` that lists the problems), it
     does not skip. So a missing link gives a clear message at once, not only a deny in the step-4
     poll.
3. **Enable the outbound token-exchange leg (Part B)** — runs **only when a tool is onboarded** (rungs 2
   and 3). The harness gates the whole step on `has_outbound` (a rung has an outbound convergence signal),
   so on rung 1 the route, grant, and restart are **all skipped** — rung 1 then asserts the exact bundle
   the live event-driven onboard produced, with no restart papering over a bad compose.
   `ensure_github_tool_route` adds the `github-tool` outbound route to
   `authproxy-routes`, `grant_exchange_scope` grants the agent's client the `github-tool` audience scope
   as optional, and `restart_agent` restarts the agent so it reloads the route (and its OPA sidecar
   re-fetches the recomposed bundle). Assigning the agent's `*-aud` scope is **not** operator-automatic,
   so it stays harness provisioning (the operator creates that `*-aud` scope only on **tool** deploy, so
   it does not even exist on the tool-less rung). Without this the outbound call passes through
   unexchanged and never reaches OPA. Under target side the step is still necessary: the agent's
   outbound is a pass-through, but github-tool's inbound `jwt-validation` accepts only a token whose
   audience is github-tool, so `token-exchange` must mint it.
4. **Poll until the pipeline converges.** `poll_until` drives real decisions until this run's CR is
   reflected (inbound `dev-user` allow, `test-user` allow, `devops-user` deny; and, **only when a tool is
   onboarded** (rungs 2/3, 6, 7), outbound `dev-user` `source-read` allow and `test-user` `issues-read` allow),
   waiting out the bundle poll +
   post-restart token-exchange window, up to `AIAC_BUNDLE_TIMEOUT`. On rung 1 the convergence set is
   **inbound-only** (`_default_ready_signals` appends the two outbound signals only under
   `tool_onboarded`).
5. **Validate the outcomes at the end** (no intermediate checks, except the step-2 subject-scope
   check):
   1. **Keycloak provisioning.** The expected realm role(s) + client scopes exist with the expected
      names/descriptions (via `KeycloakAdmin`) — and, for rung 1, that **no** tool scopes were provisioned.
   2. **Enforced decisions.** Drive **real HTTP requests through AuthBridge** and read the **deployed OPA
      plugin's** allow/deny:
      - **Inbound** — per `subject`, `inbound_decision` (200 → `allow`, 403 → `deny`); expected from
        `expected_inbound`.
      - **Outbound (per-scope two-gate AND)** — **rungs 2/3 only** (a tool is onboarded); rung 1 does not
        probe the outbound leg. Per `(subject × bare tool name)`, a real MCP `tools/call`
        for the **bare** tool through AuthBridge's forward proxy (`outbound_decision`). Under target
        side github-tool's inbound OPA decides: its reverse proxy rejects an ungranted call with HTTP
        403 and a plain JSON body (`error: "policy.forbidden"`, `plugin: "opa"`), and the agent's
        pass-through outbound relays that response. Under agent side the agent's outbound OPA
        decides: its denial is a JSON-RPC error frame (`error.data.plugin: "opa"`) at HTTP 200. The
        harness classifies both as `deny`. A **token-exchange refusal** (`error.data.plugin: "token-exchange"` /
        `upstream.token-exchange-failed`) classifies as `"error"` — not `deny`, not `allow` — because the
        outbound authz decision was never reached; this keeps a genuine token-exchange fault on rungs 2/3
        from masquerading as an `allow`. Expected from `expected_outbound_bare` — allowed iff the subject
        **and** some agent role both reach that tool's scope.
      - **The enforcement point** — rungs 2/3. One node reads the raw response of
        an ungranted call (`test-user` × `source-read`) and asserts with `deny_origin` that the deny
        comes from the side's enforcement point: from github-tool's inbound under target side (so the
        agent's outbound let the call through), from the agent's outbound under agent side. One node
        asserts with `cr_matches_side` that github-agent's and github-tool's CRs have the shape of the
        live side (see *[CR end state for each side](#cr-end-state-for-each-side)*).
      - Verdicts are **computed from** `scenario_uc1.py`, never from the policy. A failing node names the
        exact cell.
   3. **The subject on every leg (D31)** — rung 2.
      - `test_subject_scope_linked`: `aiac-username-sub` exists, has a mapper with the
        `username → sub` mapping (type and mapping, not the name) and no `aiac.managed` marker; both
        clients (github-agent and github-tool) link it as a default
        scope; `rossoctl` does not link it and still has its own `username-to-sub` mapper; a `rossoctl`
        password-grant token for `dev-user` has `sub` = `dev-user`.
      - `test_exchanged_token_subject_is_username`: one node per user. A standard token exchange as
        the agent client to the tool audience gives `sub` = the username. It skips cleanly when
        the agent client uses a client authenticator other than `client-secret` (for example a SPIFFE
        JWT-SVID through `federated-jwt`). The harness exchanges with the agent's client secret, the
        identity that `k8s/opa-kind-enable.sh` gives AuthBridge's `token-exchange`, so a refused secret
        is a failure. It is the one direct check of the exchanged `sub`: under agent side no one-hop
        decision reads it.
6. **Teardown → pristine.** Restore the cluster to its pre-test (no-workloads) state:
   - **Capture the CRs first** (`capture_aiac_crs`, phase `teardown`), on the success and the failure
     path: every AIAC CR (the managed-by label, all namespaces) and the global combiner, written as YAML
     (without `metadata.managedFields`) to the pytest host for post-mortem debugging — one directory
     `<UTC time>__<test module>__<phase>/` per capture, with one `<namespace>__<name>.yaml` per CR and an
     `index.yaml`, under `AIAC_CR_CAPTURE_DIR` (default: the gitignored `test/system/artifacts/cr-captures/`).
     Read-only and best-effort: a capture failure is logged, never raised. A Controller restore (rungs 5
     and 7) and rung 6's hand delete of github-tool's CR capture first too.
   - **Undeploy** each workload (`kubectl delete -f` the manifests, **reverse** deploy order).
   - **Delete the Keycloak clients explicitly** — the two clients `{ns}/github-agent` and
     `{ns}/github-tool`, their credentials Secret, and the `*-aud` audience scope. Do **not** rely on an
     unverified operator cascade.
   - **Sweep every remaining `AuthorizationPolicy` CR in the namespace** so `bundle-service` recomposes a
     clean bundle. **There is no separate OPA-bundle CR/ConfigMap** — the bundle is an in-memory artifact
     `bundle-service` serves over HTTP, so sweeping the CRs is what clears it.
   - **Run the existing provisioned-roles/scopes + policy-store cleanup** (`cleanup_provisioned` +
     `clear_policy_store`).
   - **Verify** the clients and CRs are gone (poll until absent). Leave the **realm, users, and base
     roles** in place.

## Onboarding order is irrelevant (rungs 2 vs 3)

The **final** enforced policy must not depend on the order services are onboarded. This is a
**requirement**: if onboarding order changes the end state, that is a **bug** the ladder exists to catch —
not an accepted difference. Rung 3 (tool → agent) is the **live counterpart of the PCE's
order-independence unit test (8.11)** and the exact repro of the original order-dependence bug: under the
old APM-only design, tool-then-agent **lost** the outbound gate.

Why it holds: `compute_and_apply` is **affected-service** oriented and **additive** (`override=False`, see
[../components/policy-computation-engine.md](../specs/components/policy-computation-engine.md)). When the **tool**
is onboarded, its Service Policy Builder pairs the tool's scopes against the rest of the role universe,
producing `(agent-role, tool-scope)` and `(user-role, tool-scope)` rules; the PCE stores those rules on
`SPM(github-tool)` (the service that owns the scopes). Then the PCE deploys the affected services of the
live side (D23):

- **Target side:** the affected set is the `changed` set — the services whose SPM changed in this run.
  The PCE upserts the CR of each one from its stored SPM. The tool check is github-tool's inbound.
- **Agent side:** the PCE derives the **agent's** `AgentPolicyModel` from the stored SPMs and re-upserts
  the agent's `AuthorizationPolicy` CR, plus the pass-through CR of the focus tool.

So:

- **Rung 2 (agent → tool):** agent onboarding leaves the tool check empty; **tool onboarding fills it
  in**. Under target side, the tool onboarding changes only `SPM(github-tool)`, so it writes github-tool's
  CR with both gates (the agent's roles already exist), and the agent's CR does not change. Under agent
  side, it re-writes the agent's CR with the full outbound gate.
- **Rung 3 (tool → agent):** the tool's scopes already exist, so **agent onboarding produces the full
  gate** in one pass. Under target side, the tool onboarding writes github-tool's CR with the user gate
  only (no agent role exists yet). The agent onboarding adds the `(agent-role, tool-scope)` rules to
  `SPM(github-tool)`, so the `changed` set holds both services, and the PCE writes both CRs: the
  calling-agent gate of github-tool's inbound is then complete. Under agent side, the agent's CR gets
  the full outbound gate.
- **Both converge** to the same enforced decisions. The unit-level `test_order_independence_oracle`
  (`test/unit/agent/uc/onboarding/test_uc1_grant_set_oracles.py`) asserts that rung 3's intended
  end state is **identical** to rung 2's published expectations (`RUNG3_* == RUNG2_*`); rung 3 then proves the
  **real plugin's decisions** match that in the tool→agent order — so onboarding order did not change what
  is enforced.

Rung 1 (agent only) is the exception by construction: with no tool onboarded there are no tool scopes in
the universe, so there is no tool check — under agent side the outbound user gate is **empty**, and
under target side the agent's outbound is a pass-through and no tool CR exists. Rung 1 does **not** probe that gate live (the
outbound leg has no real counterpart — see the inbound-only note above); its emptiness is asserted where
it is deterministic and real: at the unit level by the grant-set oracle
(`test/unit/agent/uc/onboarding/test_uc1_grant_set_oracles.py`) and live by `test_no_tool_scopes_provisioned`
(no `github-tool.*` scope in Keycloak). Inbound is unaffected.

## Failure path — compensating rollback and quarantine (rung 5)

Rungs 1–3 prove the happy path. Rung 5 (`test/system/test_uc1_onboard_failure_rollback.py`) proves the
**failure path**, per the UC-1
[Failure & Rollback](../specs/components/aiac-agent/uc1-service-onboarding.md#failure--rollback) contract
and the PCE [Quarantine](../specs/components/policy-computation-engine.md#quarantine-failed-onboarding).
Service Provision succeeds and creates the service's roles/scopes; the build then fails (a
`_ROLLBACK_ERRORS` failure, for example a broken PRB LLM seam). The Orchestrator rolls back, calls the PCE
`quarantine`, and re-raises. Under the event model the failure surfaces via **NATS redelivery → DLQ**, not
an HTTP status, so the rung asserts only observable end state (Keycloak, CRs, the policy store, the
Controller log, and real requests through AuthBridge + OPA):

The quarantine **deletes** the failed service's CR under both sides (D20). There is no no-rules CR: the
changed combiner denies a pod that has no client CR, so a deleted CR means deny.

- **Failed agent:**
  - the agent has **no** `AuthorizationPolicy` CR (the quarantine deleted it; a 404 counts as success);
  - a real inbound request through AuthBridge + OPA is **denied**. The agent never had a CR in this
    phase, so the deny comes from the combiner (D20): this is the live proof that a pod with no CR is
    denied. With the old combiner, the same request would be allowed;
  - the Keycloak client is **disabled** (`enabled=false`), and its `client.type` is **kept**;
  - the `github-agent.*` roles/scopes that Provision created are **removed**;
  - the shared subject scope `aiac-username-sub` **stays**: it still exists and is still a default
    scope of the disabled agent client (`test_rollback_keeps_the_subject_scope`). Provision keeps the
    link out of the created-manifest, so the rollback does not delete it (D31);
  - the agent has **no SPM** in the policy store;
  - the Controller log shows the injected error (`UnparseableLLMResponseError`) and the move of the event
    to the dead-letter subject `aiac.apply.dlq`.
- **Failed tool:**
  - the tool's CR, which its phase-3 onboarding wrote, is **deleted** (phase 3 records the CR as present,
    so "no CR" is a real transition), and the tool has **no SPM**;
  - the Keycloak client is **disabled** and `client.type=Tool` is **kept**; the failure and the
    dead-letter move are logged;
  - the shared subject scope `aiac-username-sub` **stays**: it still exists and is still a default
    scope of the disabled tool client. The phase-3 onboarding linked it, and the link is not in the
    created-manifest, so the rollback does not delete it (D31). `test_rollback_keeps_the_subject_scope`
    covers the failed agent and the failed tool;
  - the agent's CR, by side: under target side it does not change (the tool owns no role, so the
    footprint purge changes no other SPM) — its inbound grants stay and its outbound stays a
    pass-through. Under agent side, the agent CR's outbound grant bindings are all empty, and its
    inbound grants stay;
  - the agent's call to the tool is **blocked**. Under target side, github-tool has no CR, so the
    combiner denies the call on github-tool's inbound (D20). Under agent side, the agent's outbound OPA
    denies it. Under both sides, Keycloak can instead refuse the token exchange to the disabled tool's
    audience.
- **Lift:** a successful re-onboarding writes the agent's CR again (with grants) and **re-enables** the
  client. The test proves the lift on the agent only: a quarantined tool cannot be re-onboarded today
  (see the known limit in `docs/specs/components/aiac-agent/uc1-service-onboarding.md`; C5), so the failed-tool
  phase runs last.
- **MCP session:** `initialize`, `notifications/initialized`, `tools/list` and `tools/call` work for a
  granted user (a user who holds a grant on at least one tool of the target, here `dev-user`);
  `initialize`, `tools/list` and `tools/call` are denied for `devops-user` (no grant). Under target
  side, github-tool's inbound decides the session (D26), and the agent's outbound passes it through.
  Under agent side, the agent's outbound decides it (the MCP session rule).
- **The race hint (handoff 20, D33).** A failed onboarding that does not settle (the failed agent and
  the failed tool), and a tool that does not converge on the happy path, add the event-before-commit
  race hint to their message (see *[Per-rung flow](#per-rung-flow)*, step 2). The rung reads the hint
  while the Controller pod that ran the onboarding still runs, because the restore of the injection
  restarts the Controller.

## Controller restart — the resync and the no-CR deny (rung 6)

Rung 6 (`test/system/test_uc1_onboard_resync.py`) proves the resync at Controller start (D28) and the
D20 deny of a service that has no CR. At each start the Controller reads the side, runs the start
check #4, and then runs the resync under the PCE lock, before it serves: `PUT /policy` with the full
policy model of the live side (built from the stored SPM of every live service: in the IdP catalog and
not disabled), then a
teardown (quarantine) of each disabled service that still has an SPM. The `PUT` also deletes each AIAC
CR whose service is not in the model. The harness also restarts the Controller in `ensure_agent_policy` (a `policy.md` change)
and in `controller_llm_unusable`, so each of these restarts runs the resync too. The rung onboards
github-agent and github-tool (`onboarded_stack([agent, tool])`, module-scoped), and then runs three
phases in order. Like every rung, it skips cleanly before any cluster mutation when its infra is
absent: `onboarded_stack` runs `require_pipeline`, `require_env_or_skip` and `require_event_path`
first.

1. **Restart, no change.** Record `aiac_crs()` (every AIAC CR: name → `spec.policies`). Call
   `restart_controller`. Assert: the same set of AIAC CRs, each with the same `spec.policies`; and the
   convergence signals still hold (`dev-user` inbound allow, `devops-user` inbound deny, `dev-user`
   outbound `source-read` allow).
2. **No CR, so deny (D20).** Delete github-tool's CR by hand
   (`kubectl delete authorizationpolicy github-tool`). Poll until the `dev-user` `source-read` call,
   which phase 1 allowed, is denied. github-tool now has no client CR, so the combiner denies the call
   on github-tool's inbound (HTTP 403), under both sides.
3. **Restart, repair.** Call `restart_controller` again. The resync writes the missing CR from
   `SPM(github-tool)`. Assert: github-tool's CR is back with the same `spec.policies` as in phase 1, and
   the `dev-user` `source-read` call is allowed again.

## The enforcement-side switch (rung 7)

Rung 7 (`test/system/test_uc1_onboard_side_switch.py`) proves the switch (D16, D29). A side change is
a ConfigMap patch and a Controller restart. The resync then writes every CR in the new side (D28), so
no mixed state stays. Let `S` be the live side at the start, and `O` the other side. The rung onboards
github-agent and github-tool (`onboarded_stack([agent, tool])`, module-scoped), and then runs these
phases in order. It skips cleanly in the same way as rung 6.

1. **Under `S`.** Assert: every AIAC CR matches `S` (`cr_matches_side`), and the full inbound and
   outbound matrix of *[Expected output](#expected-output)* holds.
2. **Switch to `O`.** Enter `controller_enforcement_side(O)`: it patches `AIAC_ENFORCEMENT_SIDE` in
   `aiac-agent-config` and restarts the Controller.
3. **Every CR moved.** Poll until every AIAC CR matches `O`. Then assert: the set of AIAC CRs is the
   same (github-agent and github-tool), and no AIAC CR still matches `S` (no mixed state).
4. **The demo passes under `O`.** Poll until `deny_origin` of an ungranted call (`test-user` ×
   `source-read`) gives the enforcement point of `O`. This proves that the OPA sidecars loaded the new
   bundles (a CR change takes effect at the next poll of the OPA plugin, up to 120 s). Then assert the
   full matrix again: the same verdicts as in phase 1.
5. **Switch back.** Exit the context: it restores the start value and restarts the Controller. Poll
   until every AIAC CR matches `S` again and `deny_origin` gives the enforcement point of `S`. The
   context restores `S` on every exit path, also on a failure, so later rungs run under `S`.

The rung needs no second run of the lane to cover both sides, but the whole lane can also run under
either side (see *[Runbook](#runbook)*).

## Expected output

Verdicts are **computed from** the `scenario_uc1.py` pair-lists (these tables are the human-readable
rendering). They are **identical to policy-pipeline's** and to what the deployed OPA plugin enforces.

`USERS`: `dev-user`→`developer`, `test-user`→`tester`, `devops-user`→`devops`.

**Inbound allow** (the real plugin's inbound decision; all rungs):

| Subject | Inbound |
|---|---|
| dev-user | ✅ |
| test-user | ✅ |
| devops-user | ❌ |

**Outbound allow(subject, tool)** (the real plugin's decision on the agent's call to the tool, per-scope
two-gate AND over the **bare** tool names; the agent reaches all four tool scopes, so the user gate
discriminates; under target side github-tool's inbound OPA decides, under agent side the agent's
outbound OPA decides, and the table is the same) — **rungs 2 and 3** (with a tool onboarded):

| | source-read | source-write | issues-read | issues-write |
|---|---|---|---|---|
| dev-user | ✅ | ✅ | ✅ | ❌ |
| test-user | ❌ | ❌ | ✅ | ✅ |
| devops-user | ❌ | ❌ | ❌ | ❌ |

The table covers `tools/call`. The MCP session messages (`initialize`, `notifications/initialized`,
`ping`, `tools/list`) to `github-tool` are allowed for a user who holds a grant on at least one of its
tools (`dev-user`, `test-user`) and denied otherwise (`devops-user`). Under target side, github-tool's
inbound denies every other MCP method (D26).

**Rung 1 (agent only):** the outbound leg is not probed (see
*[Onboarding order is irrelevant](#onboarding-order-is-irrelevant-rungs-2-vs-3)*).

The pipeline emits one `AuthorizationPolicy` CR per onboarded service — the agent's **and the tool's**
(D20). Each CR has both request packages (`inbound/request.rego`, `outbound/request.rego`), and no
response package. The shape depends on the side (see the next section). Each rung also asserts the
expected Keycloak provisioning end state (agent roles/scopes with the expected descriptions; rung 1
additionally asserts **no** tool scopes exist).

### CR end state for each side

`cr_matches_side` checks these shapes. A rules-based package has `default allow := false` (D25). A
pass-through package is only `allow := true` (`rego_is_pass_through`).

| Side | github-agent CR | github-tool CR | Where the tool check runs |
|---|---|---|---|
| **target side** (default) | inbound: rules, agent-level (D26a), with grants; outbound: pass-through (D24) | inbound: rules, per tool (D26), with grants; outbound: pass-through (D24) | github-tool's inbound |
| **agent side** | inbound: rules, agent-level, with grants; outbound: rules (per-tool checks + the MCP session rule) | inbound and outbound: pass-through (a pass-through CR, D24) | github-agent's outbound |

A service that is not in the managed set (no stored SPM — for example after a quarantine) has **no**
CR, and the combiner denies it (D20). `deny_origin` tells the two enforcement points apart from the raw
response of a denied tool call: HTTP 403 with a plain JSON body (`plugin: "opa"`) relayed from
github-tool's inbound, or HTTP 200 with a JSON-RPC error frame (`error.data.plugin: "opa"`) from the
agent's outbound.

### Prefixed provisioned names vs. bare runtime names

UC-1 names every scope `{workload}.{name}`, so what it **provisions** into Keycloak (and what the oracle's
grant-set constants hold) is **workload-prefixed** — `github-tool.source-read`,
`github-agent.source_operations`. But the request AuthBridge actually sends, and the name the OPA plugin
compares against, is the **bare** runtime tool name (`source-read`) that `mcp-parser` puts in
`input.mcp.params.name`. So the live oracle keys decisions on the **bare** names
(`expected_outbound_bare` / `outbound_decision`); the two naming registers meet in `scenario_uc1.py`
(prefixed provisioned truth + a `bare()` de-prefixer). The enforced decisions are therefore identical to
`policy-pipeline`'s — both share the same harness and enforce over the same bare names.

### The agent→tool gate (capability-matched)

Phase-1 states outbound access is the **per-scope intersection** of the user→tool gate and the
agent→tool gate. UC-1 provisions **one operator role per skill**
(`github-agent.source_operations` / `github-agent.issue_operations`), and the PRB maps those operator
roles to the tool scopes by domain (capability-match under `generic_policy.md`), so the agent's capability
gate is **populated over all four tool scopes**. Because the agent reaches every tool scope, the **user
gate discriminates** — the plugin enforces the real per-scope AND (subject gate AND capability gate on the
same `input.mcp.params.name`) and, for this scenario, its verdicts equal the user-gate slice. The AND is
genuine, not degenerate: if the agent reached only a subset of the tool's scopes, the request would be
denied for the scopes it does not reach.

Under target side the same two gates run in github-tool's own inbound (D26), keyed by the bare tool
name: the user gate on `input.identity.subject`, and the calling-agent gate on
`input.identity.client_id` (the agent that called). A deny vetoes an allow. The callee is the key, so
the gate needs no target ID. Under agent side the gates run in the agent's outbound, and the capability
gate is keyed by the target (`input.identity.service_id`).

## Scenario

Identical role→access facts to `policy-pipeline`, driven through real UC-1 onboarding of deployed
workloads and enforced by the deployed OPA plugin.

| Element | Value |
|---------|-------|
| Realm | `AIAC_TEST_REALM` (must match the deployed stack's `KEYCLOAK_REALM`; default `rossoctl`) |
| Agent | `github-agent` — **discovered** per-skill operator roles `github-agent.source_operations`, `github-agent.issue_operations` (mirroring the scopes); scopes `github-agent.source_operations`, `github-agent.issue_operations` (from AgentCard skills) |
| Tool | `github-tool` (simplified) — **discovered** scopes `github-tool.{source-read, source-write, issues-read, issues-write}` (from MCP `tools/list`) |
| Users | `dev-user` (`developer`), `test-user` (`tester`), `devops-user` (`devops`) |
| `developer` | source read/write + issues read |
| `tester` | issues read/write |
| `devops` | no access (inbound deny; denied every outbound tool) — conveyed by **role description only**, absent from the `policy.md` (deny-by-default) |

## Configuration (env)

The suite reads its config from the repo-root `.env` (gitignored); source it before running
(`set -a; . .env; set +a`). The drivers read these:

| Variable | Purpose | Default |
|----------|---------|---------|
| `KUBECONFIG` | Kubeconfig for the live rossoctl/Kind cluster (read by `kubectl`, not by the harness) | `kubectl` default (`~/.kube/config`) |
| `KEYCLOAK_URL` | External Keycloak base URL | — (required) |
| `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin creds (user/realm-role provisioning + cleanup) | — (required) |
| `KEYCLOAK_ADMIN_REALM` | Realm the admin creds live in | `master` |
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | PRB LLM (pinned `temperature=0`); consumed by the in-cluster AIAC pod | — (required) |
| `AIAC_TEST_REALM` | Realm the tests provision/read back against. **Must match the deployed AIAC stack's `KEYCLOAK_REALM`** — the in-cluster consumer onboards in *its own* realm off the `CLIENT_CREATED` event, so a harness that provisions roles in a different realm would leave onboarding unable to see them | `rossoctl` |
| `AIAC_DEMO_NAMESPACE` | Namespace the tests deploy (and tear down) the demo workloads into | `team1` |
| `AIAC_TRUST_DOMAIN` | SPIFFE trust domain the operator registers the demo workloads under | `localtest.me` |
| `AIAC_ENFORCEMENT_SIDE` (ConfigMap `aiac-agent-config`, not a harness env var) | The enforcement side the Controller uses (`target-side` or `agent-side`). `live_enforcement_side` reads it from the live ConfigMap; rung 7 changes it and restores it | `target-side` |
| NATS Event Broker (not an env var) | Precondition. `require_event_path` skips unless pods labelled `app=aiac-event-broker` in `aiac-system` are Running; the harness has no env var for the broker | — (`k8s/event-broker-deployment.yaml`) |
| SPI listener (realm `eventsListeners`) | Must contain `aiac-event-listener` (with `adminEventsEnabled: true`) so `CLIENT_CREATED` reaches NATS (precondition) | — (Helm/realm setup, per `keycloak-spi/README.md`) |

> Cluster/stack knobs the harness also honors, with defaults matching the deployed stack (rarely
> overridden): the Controller namespace/Deployment/selector (`AIAC_CONTROLLER_NAMESPACE` /
> `AIAC_CONTROLLER_DEPLOYMENT` / `AIAC_CONTROLLER_SELECTOR`, defaults `aiac-system` / `aiac-agent` /
> `app=aiac-agent`; the harness does not port-forward to the Controller), the Policy Store target (`AIAC_STORE_*`,
> `svc/aiac-policy-model-store-service` on `7074`), the abstract-policy ConfigMap/mount
> (`AIAC_POLICY_CONFIGMAP` / `AIAC_POLICY_MOUNT_PATH`), the agent Deployment to restart
> (`AIAC_AGENT_DEPLOYMENT`), the Kind cluster name (`AIAC_KIND_CLUSTER`), the timeouts (`AIAC_DEPLOY_TIMEOUT`,
> `AIAC_BUNDLE_TIMEOUT`, `AIAC_ONBOARD_TIMEOUT`, `AIAC_BUNDLE_POLL_INTERVAL`; defaults 180 s, 300 s, 600 s
> and 10 s; with the handoff-20 fix deployed, do not raise them for the event-before-commit race,
> see *[Per-rung flow](#per-rung-flow)*, step 2), and the rung-5 knobs (`AIAC_ROLLBACK_SETTLE_TIMEOUT`,
> `AIAC_ROLLBACK_LIFT_TIMEOUT`, `AIAC_UNUSABLE_LLM_BASE_URL`). Single stack — one Controller, one policy; the two-variant env
> (`AIAC_EXPLICIT_URL`/`AIAC_ABSTRACT_URL`, per-variant OPA pods) is gone with the two-stack topology.

## Runbook

Runnable against a live rossoctl/Kind cluster (operator + Keycloak + SPIRE) with the AIAC stack + the
AuthBridge OPA pipeline wired into **both** legs, the **NATS Event Broker deployed** and the **Keycloak
SPI installed + `aiac-event-listener` enabled on the realm**, and a real LLM in-pod. The tests **load,
deploy, and tear down** the workloads themselves (for the image toolchain, see
*[Preconditions](#preconditions-the-wired-platform--not-stood-up-by-the-tests)*). Stand the pipeline up with `k8s/opa-kind-enable.sh`;
the full prerequisites, wiring, and manual probe commands are in `k8s/opa-kind-runbook.md`, and the SPI
setup is in `keycloak-spi/README.md`.

```bash
k8s/opa-kind-enable.sh          # one-time: wire the OPA plugin into both legs and apply the changed combiner
# one-time also: deploy the NATS Event Broker, install the Keycloak SPI + enable the realm listener
#                (the suite loads the github-agent / github-tool images itself, per rung, via kind-load.sh)
set -a; . .env; set +a
.venv/bin/pytest -m system -k uc1_onboard -v
# A failing node names the exact cell, e.g.:
#   test_outbound[source-read-test-user] — expected deny, plugin allowed
.venv/bin/pytest -m system -k uc1_onboard_resync -v        # rung 6 only
.venv/bin/pytest -m system -k uc1_onboard_side_switch -v   # rung 7 only
```

The lane runs under the live side (default `target-side`). To run the whole lane under agent side,
change the side first (a ConfigMap patch and a Controller restart; the resync moves every CR), and
restore it afterwards the same way:

```bash
kubectl -n aiac-system patch configmap aiac-agent-config --type merge \
  -p '{"data":{"AIAC_ENFORCEMENT_SIDE":"agent-side"}}'
kubectl -n aiac-system rollout restart deployment/aiac-agent
kubectl -n aiac-system rollout status deployment/aiac-agent
.venv/bin/pytest -m system -k uc1_onboard -v
```

Without `-m system` the suite is deselected (the default `addopts`); when the cluster/pipeline is not wired — including the
**broker/SPI not installed** and the **combiner not changed** — or the env is unset, it **skips cleanly** (`require_pipeline`,
`require_env_or_skip`, `require_event_path`; it never false-passes). Image
loading is **not** a skip condition (see *[Preconditions](#preconditions-the-wired-platform--not-stood-up-by-the-tests)*).
Rungs 6 and 7 restart the Controller twice each, so each one takes several minutes.

## Testing Decisions

- **Highest seam available, verified by the real evaluator.** Real deployed workloads + real operator +
  real UC-1 onboarding + real PRB/PCE + real Keycloak + real LLM, driven through the **production trigger
  — the deploy→`CLIENT_CREATED`→NATS→consumer event chain** (deploying the workload *is* the trigger) —
  and enforced by the **deployed AuthBridge OPA plugin**. Assert only **external behavior** — the
  allow/deny decisions the plugin makes — never internal policy structure. (The `POST /apply/service/{id}`
  route remains only a documented debugging escape hatch; the tests do not call it.)
- **The enforced decision is the artifact under test; the scenario is the oracle.** Verdicts computed from
  `scenario_uc1.py`, keyed on the bare runtime tool names — not from the policy itself.
- **Onboard, then enforce.** Live enforcement / token-exchange / real HTTP through AuthBridge is now the
  whole point (not out of scope). The agent's own CrewAI reasoning flow is not triggered — the probes are
  synthetic requests through AuthBridge — but the traffic is real and the deployed plugin enforces it.
- **Image-load + deploy + teardown are test steps; the event infra is the precondition.** Each
  rung provisions realm/users + mounts policy → **loads** its image(s) into the Kind node → **deploys** its
  workloads sequentially (deploying fires the event
  trigger; each converges before the next) → enables the outbound leg → polls → validates → **tears down
  to pristine**. The NATS broker and the Keycloak SPI listener are the standing preconditions; for the
  image toolchain, see *[Preconditions](#preconditions-the-wired-platform--not-stood-up-by-the-tests)*. Full teardown keeps reruns hermetic.
- **One stack, one policy, the deployed plugin.** Rungs 1–3 need only one AIAC stack; the deployed OPA
  plugin + the upserted `AuthorizationPolicy` CRs (one per managed service) are what make the pipeline observable.
- **Side-aware, verdict-stable.** The verdict tables are the same under each enforcement side. The
  harness reads the live side (`live_enforcement_side`) and selects only the side-dependent assertions:
  the CR shapes (`cr_matches_side`) and the place of a deny (`deny_origin`). Under target side these
  prove that the tool check moved from the agent's outbound to github-tool's inbound: a granted
  `tools/call` passes, github-tool's inbound denies an ungranted one, and the agent's outbound is a
  pass-through.
- **Onboarding-order-independence is asserted, not assumed** (rungs 2 vs 3). Rung 3's intended end state
  is checked identical to rung 2's published expectations at the unit level (`test_order_independence_oracle`
  in `test_uc1_grant_set_oracles.py`), and the real plugin's decisions are asserted in
  the tool→agent order. A divergence is a bug.
- **The failure path asserts observable end state only** (rung 5). A build failure surfaces via **NATS
  redelivery→DLQ**, not an HTTP status, so the rung does not assert a `POST` status. It asserts Keycloak,
  CR and policy-store state, the Controller log (the injected error and the dead-letter move), and real
  requests through AuthBridge + OPA: a failed agent has no
  CR and is denied (D20), its client is disabled with `client.type` kept, its provisioned roles/scopes are
  removed (the shared `aiac-username-sub` stays linked, D31), and it has no SPM; a failed tool loses
  the CR its onboarding wrote, has no SPM, and is unreachable from the agent; a clean re-onboard writes the agent's CR again and
  re-enables the client.
- **The Controller start is tested live** (rungs 6 and 7). A restart with no change leaves every CR
  unchanged (the resync, D28). A CR deleted by hand denies its service (D20), and the next resync
  writes it again. A restart with the other side moves every CR, with no mixed state (D16, D29). The
  side context restores the start side on every exit path, as `controller_llm_unusable` restores the
  LLM env.
- **Per-scope two-gate AND.** UC-1's per-skill operator roles are mapped to the tool scopes by
  capability-match, so the capability gate is populated; the plugin enforces the real per-scope AND. The
  agent reaches all four tool scopes, so the user gate discriminates. Under target side the same AND
  runs in github-tool's inbound (the user gate and the calling-agent gate, D26).
- **Unit-level counterparts.** The unit lane (untagged; a bare `.venv/bin/pytest`; the tests mirror
  `src/aiac/` under `test/unit/`) owns the parts that these system rungs observe only from outside:
  - `test/unit/policy/model/` — the policy-model parse (D18a): a target-side body parses to
    `TargetSidePolicyModel`, an agent-side body to `AgentSidePolicyModel`; and the shared projection
    (D18b): for one SPM, `project_inbound` gives the same inbound gates as the APM inbound that
    `_derive` builds.
  - `test/unit/policy/computation/` — the policy-model stage (D23, D21: the managed set, the zero-rule
    focus SPM, the `changed` set, the affected set for each side); the quarantine and the decommission
    call `delete_service_cr` (D20); the resync (D28: one `PUT` with every live stored SPM, the deletes by
    the label, the teardown of a disabled service); the bootstrap (the CR of a focus tool, and no SPM
    stored); and the switch parse (`enforcement_side()`: an
    unknown `AIAC_ENFORCEMENT_SIDE` value raises `ValueError`).
  - `test/unit/pdp/service/policy/opa/` — the writer: a tool CR (name and namespace from
    `identity_ref`, the label, both request packages), a batch, `PUT /policy` deletes the stale
    labelled CRs and keeps the others, `DELETE /policy/services/{service_id:path}` (a 404 counts as
    success), a body with a wrong or missing tag gives 422; and the Rego with `opa eval`
    (`_assert_opa_allow` / `_opa_verdict`, which skip without `opa`): both renderings for an agent and
    a tool, the tool inbound (D26, with the self-discovery rule), the agent inbound (D26a), no request without identity passes
    (D27), the pass-through outbound (D24), and the changed combiner (D20).
  - `test/unit/agent/` — the start sequence (an unknown side, a failed start check #4, or a failed
    resync stops the Controller before it serves), the onboarding checks #1, #2 and
    #6 (each gives 409, is permanent in the NATS consumer, runs no rollback and no quarantine, and runs
    before the bootstrap, Provision and the PRB, D30), the bootstrap of a tool before Provision, and the
    read-only route `GET /policy/services/{service_id:path}` (D18). For D31: Provision links the
    subject scope before `set_service_type`, keeps it out of the created-manifest, and the rollback
    never deletes it; `test_uc1_subject_scope.py` covers the harness helpers `subject_scope_problems`,
    `subject_scope_link_problems`, `require_subject_scope`, `exchange_token` and `exchanged_subject`.
    For handoff 20 (D33): `test_uc1_commit_race_hint.py` covers the harness race hint
    (`commit_race_hint`, `append_hint`, `controller_commit_race_hint` and the bounded `controller_logs`
    read), with `kubectl` stubbed.
  - `test/unit/idp/` — the subject scope (D31): `POST /services/{service_id}/subject-scope` creates
    `aiac-username-sub` and its mapper with no marker (idempotent, also after a `409` from a
    concurrent onboarding), changes a wrong `username-to-sub` mapper back, gives `409` on a scope that
    has the marker, removes an optional link, and links the scope as a default scope;
    `GET /services/{service_id}/scopes` gives `200` for a client that links the unmarked scope; the
    library method `link_subject_scope`.
- **Stack's realm, leave-in-place; per-rung cleanup.** UC-1 resolves/provisions against the deployed
  stack's `KEYCLOAK_REALM` (default `rossoctl`) and **never deletes** the realm/users/roles. Per rung,
  the workloads are undeployed, and their Keycloak registrations, every `AuthorizationPolicy` CR in the
  namespace, the provisioned agent/tool roles/scopes, and the policy-store SPMs are removed, so
  onboarding runs from a clean slate. `policy-pipeline` (`5.3`) shares this same live stack and the same
  leave-in-place realm.
- **LLM nondeterminism, contained.** PRB LLM pinned `temperature=0`; both cell-level and provisioning
  assertions; `@pytest.mark.system`, out of default CI.
- **Prior art, shared not copied.** Reuses the `5.3` shape (skip gates, scenario-as-oracle, the live
  decision oracle) via `uc1_onboard.py` / `launcher.py` / `scenario_uc1.py`.

## Relationship to other integration tests

- **Onboarding-order sibling of `policy-pipeline`** ([policy-pipeline.md](policy-pipeline.md),
  `testing/5.3-policy-pipeline-integration-test.md`): identical scenario facts/tables and the **same**
  live enforcement loop (onboard through the Controller → real HTTP through AuthBridge → deployed OPA
  plugin's allow/deny). `policy-pipeline` is the **full happy-path matrix + negative controls** over the
  fully onboarded stack; this ladder **isolates onboarding-order properties** across three rungs. Both
  share the same harness and the same live stack (the `rossoctl` realm + the `team1` namespace); the
  former explicit-vs-abstract two-policy equivalence check is **deferred to rung 4** (`testing/5.4.4`),
  since only one `policy.md` is mounted on the live stack.
- Same `@pytest.mark.system` + live-enforcement flavor as `testing/5.1-integration-tests.md`; runs
  outside the default unit run against live dependencies and skips cleanly when the cluster/env is not
  wired. **Status: not built yet** — the `5.1` live-Keycloak pytest suite does not exist under `test/`.

Tracking issues: `testing/5.4-uc1-onboarding-integration-test.md` (epic) + `5.4.1`/`5.4.2`/`5.4.3` (rungs)
+ `5.4.4` (deferred two-policy) + `5.4.5` (failure-path rollback and quarantine). Rungs 6 (resync) and
7 (side switch) have no tracking issue yet.

## Out of Scope

- **Writing the rung tests + `scenario_uc1.py` / harness edits** — this spec *describes* them; they are
  written under the `5.4.x` issues.
- **The UC-1 agent, PRB, PCE, OPA writer, the AuthBridge OPA plugin, and the demo `github-agent`** —
  specified/tested by their own components/issues. UC-1's discovery naming and per-skill operator-role
  behavior are **fixed**; these tests observe and enforce against them.
- **Standing up the platform** — wiring the OPA pipeline (`k8s/opa-kind-enable.sh`), installing the
  Keycloak SPI + enabling the realm listener, and deploying the NATS Event Broker are **preconditions**,
  not test steps. (Loading the demo images, then deploying and tearing down the *workloads*, by contrast,
  **is** a test step — see *[Per-rung flow](#per-rung-flow)*.)
- **Two-policy (rung 4)** — **deferred**. Rung 4's two-stack topology is discarded and the in-cluster
  approach is TBD (`testing/5.4.4-uc1-onboard-two-policies.md`).
- **The agent's CrewAI reasoning flow / real A2A message content** — the probes drive synthetic requests
  through AuthBridge to exercise the enforced gates; they do not run the agent's task graph.
- **Default-CI wiring** — `@pytest.mark.system`; runs on demand.

## Scenario inputs

**Functional** inputs — the PRB reads the descriptions and the `policy.md` to produce the role→scope
mappings. Descriptions are **generic and keyword-free** and stay within Keycloak's 255-char cap (written
verbatim); client `type` is set by UC-1 from the `rossoctl.io/type` label.

### Discovered entities (what UC-1 provisions)

- **`github-tool`** (Tool) → scopes, from MCP `tools/list` (verbatim descriptions):
  - `github-tool.source-read` — "Read source repository contents: file listings and file bodies. Read-only."
  - `github-tool.source-write` — "Create, modify, or delete source repository contents; commit file changes."
  - `github-tool.issues-read` — "Read issues and their comment threads. Read-only."
  - `github-tool.issues-write` — "Create and update issues: open, edit, comment, and close."
- **`github-agent`** (Agent) → **one operator role per skill** (name + description mirror each scope) +
  scopes from the AgentCard skills:
  - `github-agent.source_operations` — "Browse and search code; read, create, and modify repository file contents, branches, and commits."
  - `github-agent.issue_operations` — "Read, search, create, and update issues, comments, sub-issues, and pull requests."

  The operator roles `github-agent.source_operations` / `github-agent.issue_operations` carry the same
  descriptions as the scopes they mirror; those descriptions drive the PRB capability-match. (This
  replaces the prior single generic `github-agent.agent` role.)

### Realm roles (provisioned by the fixture)

- `developer` — "Developer — an engineering user who develops the source codebase (writing and maintaining code) and fixes code defects reported in the issue tracker."
- `tester` — "Tester — a quality-assurance user who verifies software quality and tracks defects through the issue tracker: filing, triaging, and updating issue reports."
- `devops` — "DevOps — an operations user who manages deployment infrastructure and runtime environments."

### `policy.md` — the single (abstract) variant

Phase-1's intent-only prose. The PRB/LLM expands intent into the discovered scopes via the entity/role
descriptions. It stays **user-intent-only** and **does not name the agent's operator roles** — the
agent's capability gate comes from the generic rubric (`generic_policy.md`) matching the operator-role
descriptions to the tool-scope descriptions, not from the policy naming them. Deny by default. Phrased
**purely positively** so absences are conveyed by silence + deny-by-default (keeping the fixture
ALLOW-only; deny-extraction deferred to #142, as in `policy-pipeline`).

```markdown
Grant access on a least-privilege basis: allow only what this policy states; deny by default.

- Developers may read and modify source, and read issues.
- Testers may read and modify issues.
```

> The **explicit** enumerated variant and cross-variant equivalence are deferred to rung 4
> (`testing/5.4.4-uc1-onboard-two-policies.md`); the two-stack topology that served both variants is
> discarded.
