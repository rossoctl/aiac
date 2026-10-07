# Onboarding an agent and a tool, end to end

AIAC discovers a GitHub agent and a GitHub tool running in your cluster, reads a **two-line
plain-English policy**, and generates enforceable least-privilege authorization for both — who may
call the agent, and what the agent may do on the tool on a user's behalf. A real HTTP request
through the live OPA plugin is then allowed or denied by it.

Everything is live: a real cluster, a real Keycloak, a real LLM call, a real RFC 8693 token
exchange. No fixtures, no offline replay.

The demo is built to prove two claims rather than assert them:

- **Deploying the workload is the trigger.** No human runs an onboarding command. The first-ever
  `kubectl apply` of `github-agent`/`github-tool` is what causes AIAC to generate their policy.
- **The generated policy is what enforces.** The allow/deny verdicts come from the deployed
  AuthBridge OPA plugin reading the `AuthorizationPolicy` CR that AIAC wrote — not from evaluating
  a file on the side.

---

## At a glance

Run everything from **this directory** (`demo/use-cases/onboarding/`). `make help` lists every
target.

| Step | Command | What it does |
|---|---|---|
| [1](#step-1--install-aiac) | `make enable` | Install the AIAC stack, NATS broker, Keycloak SPI listener |
| [2](#step-2--wire-opa-into-both-authbridge-legs) | `make opa` | Turn on the OPA plugin in both AuthBridge legs (cluster-level, one-time) |
| [3](#step-3--provision-users-roles-and-the-policy) | `make users` | Create the three demo users + roles, mount `policy.md` |
| [4](#step-4--deploy-the-workloads-this-is-the-trigger) | `make trigger` | Deploy `github-agent`/`github-tool` and verify onboarding fired |
| [5](#step-5--enforce-live) | `make enforce` | Wire the outbound leg, then probe the live OPA plugin |
| [6](#step-6--inspect-what-was-generated-optional) | `make demo` | Optional: walk the same scenario in small steps |

Steps 4 and 5 together: **`make e2e`**.

First run, in full:

```bash
make enable
make opa
make users
make e2e
```

---

## The policy

This is the entire input a human wrote. No YAML, no scope tables, no per-endpoint rules:

```
Grant access on a least-privilege basis: allow only what this policy states; deny by default.

- Developers may read and modify source, and read issues.
- Testers may read and modify issues.
```

## What AIAC generates from it

Two Rego policies per agent — one gating **who may call it**, one gating **who it may call
downstream** — derived from the policy text plus the realm-role descriptions already in Keycloak and
the tool's own discovered capabilities.

Both use the fixed AuthBridge packages the live plugin evaluates
(`authbridge.client.{inbound,outbound}.request`), keyed on the plugin's real input shape
(`input.identity.subject`, `input.identity.service_id`, `input.mcp.params.name`).

## How enforcement works

```
 dev-user / test-user / devops-user
        │  grant_type=password
        ▼
   Keycloak  ──────────────────────────────┐
        │  access_token                    │ RFC 8693 token exchange
        ▼                                  │ (subject token -> tool-audience token)
  [inbound gate: may this user call        │
   the agent? — from policy.md]            │
        │                                  │
        ▼                                  │
   github-agent                            ▼
        └──────────────────────────────────│───────────────────► github-tool
                                           ▲
                         [outbound gate: may the agent reach
                          this tool scope, for this user? —
                          from policy.md + tool capabilities]
```

Both gates are evaluated by the deployed AuthBridge sidecar, in the request path:

```
Inbound:   caller ─► jwt-validation ─► OPA ─► github-agent app
Outbound:  github-agent app ─► token-exchange ─► OPA ─► github-tool
```

Policies reach the plugin via the bundle service every AuthBridge workload polls
(`http://bundle-service.rossoctl-system.svc.cluster.local:8080`). On the outbound leg OPA sits
**after** `token-exchange`, which is what populates `input.identity` and the delegation chain on
that leg.

---

## Before you start

**Cluster.** A Kind cluster named `rossoctl` with the rossoctl platform installed — SPIRE, Keycloak,
and the rossoctl operator. Namespace `team1` must exist; 

**Tools.** `kubectl`, `helm`, `kind`, `curl`, `python3`, and `docker` or `podman` on `PATH`.

**Three sibling repo clones**, needed by step 2. Each is auto-detected from the script's own
location. Override only if a clone lives elsewhere, and then use an **absolute** path
 — a relative one resolves against your shell's cwd, not the script's.

| Variable | Clone | Used for |
|---|---|---|
| `OPERATOR_DIR` | `rossoctl/operator` | builds the operator image from `operator/Dockerfile`; renders the bundle-service manifests from `charts/operator` |
| `ROSSOCTL_DIR` | `rossoctl/rossoctl` | the Helm chart |
| `CORTEX_DIR` | `rossoctl/cortex` | builds the AuthBridge proxy-sidecar image from `cmd/cortex/Dockerfile` (the Go module root is the clone root) |

**`github-agent`/`github-tool` must NOT already be deployed in `team1`.** Step 4's whole point is
that a first-time deploy triggers onboarding. If you have run this demo before, `make restore`
first.

### Two secrets to create first

Neither is created by this demo, and both hard-fail it.

**1. The LLM key**, which `enable.sh` reads from `team1/openai-secret` (data key `apikey`):

```bash
kubectl create secret generic openai-secret -n team1 --from-literal=apikey="$LLM_API_KEY"
```

**2. `aiac-system/keycloak-admin-secret`.** Create the namespace yourself here: `enable.sh` creates
it but then applies a Deployment that mounts this Secret in the same run, leaving no window to add
it in between. Without it, `aiac-interface` never leaves `ContainerCreating` and every
Keycloak-touching `make` target aborts.

```bash
kubectl create namespace aiac-system
kubectl create secret generic keycloak-admin-secret -n aiac-system \
  --from-literal=KEYCLOAK_ADMIN_USERNAME=<admin-user> \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD=<admin-password>
```


### Keycloak credentials are discovered for you

**NO** need to export `KEYCLOAK_URL` / `KEYCLOAK_ADMIN_USERNAME` /
`KEYCLOAK_ADMIN_PASSWORD`. Every Keycloak-touching `make` target self-runs
`init/00-discover-keycloak.sh` first, which port-forwards the in-cluster Keycloak and reads the
admin credentials from the Secret above. The forward is set up once and reused. If you already
export those three variables, your values win.

To tear the forward down afterwards: `pkill -f 'port-forward .*keycloak-service'`.

### One-time Keycloak realm fix-up

If the realm was freshly provisioned, the `rossoctl` client needs Direct Access Grants enabled and a
`username → sub` protocol mapper. Without them, token minting fails with `unauthorized_client` or
yields a token with no `sub`. This is platform state, so the demo does not set it:

```bash
KC=http://keycloak.localtest.me:8080
ADMIN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

CID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/clients?clientId=rossoctl" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/clients/$CID" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);d["directAccessGrantsEnabled"]=True;print(json.dumps(d))' \
  | curl -s -o /dev/null -w "enable DAG HTTP %{http_code}\n" -X PUT -H "Authorization: Bearer $ADMIN" \
    -H "Content-Type: application/json" "$KC/admin/realms/rossoctl/clients/$CID" --data-binary @-
curl -s -o /dev/null -w "add sub mapper HTTP %{http_code}\n" -X POST -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  "$KC/admin/realms/rossoctl/clients/$CID/protocol-mappers/models" \
  -d '{"name":"username-to-sub","protocol":"openid-connect",
       "protocolMapper":"oidc-usermodel-property-mapper",
       "config":{"user.attribute":"username","claim.name":"sub","jsonType.label":"String",
                 "id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}'
```

Step 5 re-asserts the mapper idempotently, so a `409` there is expected and harmless.

---

## Step 1 — Install AIAC

> **`make enable` defaults to `LLM_BASE_URL=https://api.openai.com/v1` and `LLM_MODEL=gpt-4o-mini`.**

```bash
make enable
```

> If your endpoint is anything else, pass them as follow:

```bash
LLM_BASE_URL=https://your-endpoint LLM_MODEL=your-model make enable
```

### What happens

AIAC is not deployed by default. This builds its four images, loads them into Kind, wires the LLM
configuration, applies the manifests, deploys the NATS event broker, and installs the Keycloak
event-listener SPI. It automates
[`k8s/aiac-deployment-guide.md`](../../../k8s/aiac-deployment-guide.md) for Kind; the
[appendix](#appendix--installing-aiac-by-hand) has the manual equivalent.

Three independently runnable sub-steps:

| Sub-step | Flag | What it does |
|---|---|---|
| AIAC stack | `--stack-only` | Builds/loads `aiac-pdp-config`, `aiac-pdp-policy-opa`, `aiac-policy-model-store`, `aiac-agent`; creates `aiac-agent-secret` from your LLM key; provisions the `aiac-policy` ConfigMap from the scenario's policy text; applies the three manifests |
| NATS broker | `--broker-only` | Applies `event-broker-deployment.yaml`, creating `aiac-event-broker-service` |
| Keycloak SPI | `--spi-only` | Builds the shaded jar in a Maven container (no JDK needed locally), derives a Keycloak image carrying it, `kind load`s it, patches the live `keycloak` StatefulSet, and enables the listener on the realm |

Both `github-agent`/`github-tool` — are **NOT** deployed hence step 4 is a genuine first-time trigger.

### Change LLM
> Want to use different values? Patch and restart — these are injected via `envFrom`, so
> they are snapshotted at pod start and a ConfigMap edit alone changes nothing:
>
> ```bash
> kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
>   -p '{"data":{"LLM_BASE_URL":"https://your-endpoint","LLM_MODEL":"your-model"}}'
> kubectl rollout restart deployment/aiac-agent -n aiac-system
> ```

### Verify

```bash
kubectl get deployment aiac-agent aiac-interface aiac-event-broker -n aiac-system
kubectl get statefulset aiac-policy-model-store -n aiac-system
kubectl logs statefulset/keycloak -n keycloak | grep -i "aiac-event-listener\|providers changed"
```

Expect all four workloads `Available`/`Ready`, and at least one SPI line from Keycloak. Confirm the
agent picked up your LLM settings:

```bash
kubectl exec deployment/aiac-agent -n aiac-system -- \
  sh -c 'echo "$LLM_BASE_URL  $LLM_MODEL"'
```

### Re-running after a source change - (For developers only)

The stack sub-step **skips building an image that already exists locally** — right on a re-run,
wrong after editing `src/aiac/`. Force the builds:

```bash
./enable.sh --rebuild                # reinstall, rebuilding all four images
./enable.sh --stack-only --rebuild   # just rebuild + redeploy the stack
```

The Keycloak change is a live, reversible patch rather than a chart edit, so a later `helm upgrade`
of the `rossoctl` release reverts it. Undo it deliberately with `make restore ARGS=--include-infra`.

---

## Step 2 — Wire OPA into both AuthBridge legs

Confirm OPA is **NOT** configured in any authbridge leg  — expect `0`:

```bash
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
```

Now insert opa in both inbound and outbound legs of AuthBridge
```bash
make opa  
```

This is a **cluster-level, one-time** change owned by `k8s/`.

### What happens

Enforcement is an opt-in AuthBridge pipeline plugin. The script rebuilds the AuthBridge
proxy-sidecar image from your `cortex` clone, loads it into Kind, and `helm upgrade`s the chart with
a **temporary overlay** that inserts `opa` — after `token-exchange` on the outbound leg — plus the
parser set into every `team1` agent's pipeline. It does not modify `charts/rossoctl/values.yaml` on
disk.

AuthBridge plugins are opt-in build tags, so the build passes `GO_BUILD_TAGS` resolved from the
`full` profile in `cortex/scripts/profile-tags` — one of only two profiles carrying `opa`. Tags are
resolved in a `golang` container when the host has no `go`; override with `AUTHBRIDGE_PROFILE` or an
explicit `GO_BUILD_TAGS`.

Expect two container image builds, so give it a few minutes.

### Verify

Confirm OPA landed in **both** legs — expect `2`:

```bash
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
```

`driver.sh`'s preflight checks this and refuses to run without it, so steps 4–5 cannot silently
proceed unwired. Full background, including the exact `input` document the plugin builds on each
leg, is in [`k8s/opa-kind-runbook.md`](../../../k8s/opa-kind-runbook.md). Revert with
`make opa-restore` (wraps `k8s/opa-kind-restore.sh`).

---

## Step 3 — Provision users, roles and the policy

```bash
make users
```

### What happens

Creates the three demo users with their realm roles, including the role **descriptions** the Policy
Rules Builder reads and the `email`/`firstName`/`lastName` that Keycloak 26's declarative user
profile requires before `grant_type=password` will succeed. It also mounts `policy.md` on the
Controller.

| User | Realm role | Expected outcome |
|---|---|---|
| `dev-user` | `developer` | reaches the agent; read/write source, read issues |
| `test-user` | `tester` | reaches the agent; read/write issues only |
| `devops-user` | `devops` | denied at the inbound gate — the policy grants it nothing |

### Why this must come before step 4

`make users` is `make setup` minus the two sub-steps that resolve the workloads' Keycloak client
UUIDs — those abort when the workloads aren't deployed, and deploying them is exactly what step 4
does as the trigger.

So the realm must hold the users, roles and policy **before** the deploy fires onboarding, or the
Policy Rules Builder has no role descriptions to reason about. Step 6 runs the full `make setup`
later, once the clients exist.

### Verify

```bash
make show
```

Expect three users with roles, and no `github-*` roles, scopes or generated policy yet — nothing has
been onboarded.

---

## Step 4 — Deploy the workloads: this is the trigger

```bash
make trigger
```

### What happens

Two phases. **DEPLOY** loads the workload images and applies their manifests. **VERIFY-TRIGGER**
proves the apply is what caused onboarding.

The split is what makes the claim checkable:
[`kind-load.sh`](../../assets/kind-load.sh) builds and loads images and **applies nothing** — it
cannot register a Keycloak client. [`deploy.sh`](../../assets/deploy.sh) then does the `kubectl
apply` + `rollout status`. So the trigger is isolated to that second call. Both scripts are used
unmodified, exactly as the `-m system` suite uses them.

**The causal chain.** The operator's `AgentRuntimeReconciler` stamps `rossoctl.io/type=agent|tool`
onto a Deployment's pod-template labels the first time its `AgentRuntime` CR resolves. That label is
what `ClientRegistrationReconciler`'s watch predicate keys on, and that calls
`RegisterOrFetchClientWithToken` — producing a genuine Keycloak `CLIENT_CREATE` admin event. The SPI
listener from step 1 publishes it on NATS as `aiac.apply.service.<uuid>`, and `aiac-agent`'s
consumer runs `onboard_service`. There is no `POST /apply/service/{id}` call anywhere in this path.

VERIFY-TRIGGER polls until each of these is true, in order:

1. `team1/github-agent` and `team1/github-tool` appear as Keycloak clients.
2. `aiac-agent`'s logs show it consumed `aiac.apply.service.<uuid>` for both, over NATS.
3. The `authorizationpolicies.agent.rossoctl.dev/github-agent` CR exists.
4. That CR's **outbound gate is populated** — `target_allow_scopes` carries the tool's scopes — then
   prints its content.

Check 4 matters because check 3 alone would pass a half-onboarded state whose outbound maps are all
empty, deferring the failure to step 5 where the cause is much harder to see.

> **Expect a few minutes.** The agent publishes its A2A AgentCard skills only *after* the deploy, so
> onboarding redelivers over JetStream until `source_operations`/`issue_operations` resolve.
> `POLL_SECS` (default 720) bounds it, and each phase breaks the instant its condition is met, so a
> healthy run is well under the ceiling. Keep `POLL_SECS` above 600 — the consumer's `ACK_WAIT` —
> or a failed first attempt can never be rescued by the redelivery that would have fixed it.

### Verify

VERIFY-TRIGGER already asserts all of the above and fails loudly. To check by hand:

```bash
kubectl get authorizationpolicy github-agent -n team1 \
  -o jsonpath='{range .spec.policies[*]}{.path}{"\n"}{end}'
```

Expect `inbound/request.rego` and `outbound/request.rego`.

---

## Step 5 — Enforce live

```bash
make enforce
```

### What happens

**WIRE** configures AuthBridge's own outbound leg — the two things AIAC's onboarding does not do:

1. Adds the `github-tool` route to the `authproxy-routes` ConfigMap. Its `host` decides whether
   token-exchange fires at all, and its `target_audience` becomes `input.identity.service_id`, which
   is the key the generated policy looks up in `target_allow_scopes`.
2. Ensures `github-agent`'s Keycloak client may request the `agent-team1-github-tool-aud` audience.
3. Restarts the agent pod, because the route is read at sidecar start.

> The demo's own `configmaps.yaml` ships a route for the **production** tool
> (`host: github-tool-mcp`), which this install path deliberately does not deploy. WIRE retargets it
> at the demo's stand-in tool (`host: github-tool`). That is why the deployed ConfigMap differs from
> the file on disk, and why anything that re-applies the file needs WIRE re-run after it.

**ENFORCE** then drives real HTTP probes through the live plugin:

| Request | Inbound | Outbound (via the agent) |
|---|---|---|
| `dev-user` → `github-agent` | allowed | `source-read`, `source-write`, `issues-read` allowed; `issues-write` denied |
| `test-user` → `github-agent` | allowed | `issues-read`, `issues-write` allowed; `source-read`, `source-write` denied |
| `devops-user` → `github-agent` | **denied (403)** | never reached |

`devops-user`'s denial is the intended story, not a failure — nothing in the policy grants it access
to the agent at all.

The driver hard-fails on the two decisive outbound checks (`dev-user`→`source-read` must be allowed,
`test-user`→`source-read` must not be), reports the rest of the matrix, then prints the matching OPA
decision-log lines.

### Reading the verdicts

Inbound and outbound denials look different, because the outbound pipeline includes `mcp-parser`:

| Leg | A denial looks like |
|---|---|
| Inbound | **HTTP 403**, body `{"error":"policy.forbidden","plugin":"opa"}` |
| Outbound | **HTTP 200** with a JSON-RPC error frame — `error.code: -32000`, `error.data.plugin: "opa"` |

So on the outbound leg, classify by the response **body**: an `error` frame is denied, a `result`
frame is allowed. The request never reaches `github-tool`. The driver reports these as
`DENIED_JSONRPC` and `ALLOWED_RESULT`.

An inbound allow is also an HTTP 200 carrying a JSON-RPC `Method not found` error — the probe calls
a deliberately nonexistent method, so reaching the app at all *is* the allow signal.

### Verify

The matrix above is the verification, and the driver fails the run if the decisive cells are wrong.
To confirm the verdicts came from the generated policy rather than a fallback, look for `client_ok`
in the decision log — that term only exists in the AIAC-generated package:

```bash
kubectl logs deployment/github-agent -n team1 -c authbridge-proxy --tail=200 \
  | grep "Decision Log" | tail -2
```

Expect `result="map[allow:true client_ok:true ns_ok:true]"` on an allow.

---

## Step 6 — Inspect what was generated (optional)

Steps 1–5 are automated and fail loudly. This part is the opposite: it walks the same scenario in
small steps so you can watch what AIAC generates and when. It needs the workloads deployed and
registered — true now, after step 4.

It differs from steps 4–5 in two deliberate ways: onboarding is invoked **manually**
(`POST /apply/service/{id}`), and verdicts come from evaluating the generated Rego with `opa eval`
rather than from the live plugin. Same policy, same generated files — inspected instead of enforced.

```bash
make setup    # the full version: adds client-UUID resolution + direct token-exchange config
make clear    # reset to a clean baseline — deletes the AuthorizationPolicy CR and generated/
make show
```

**Pause 1 — baseline.** Three users with roles, no `github-*` roles or scopes, no generated `.rego`.

```bash
make agent    # AIAC discovers github-agent, reads policy.md, generates the inbound gate
make show
```

**Pause 2 — the agent alone.** The inbound gate is populated: developers and testers can reach the
agent's discovered scopes. The outbound gate exists but every map in it is empty — there is no tool
yet to act on.

```bash
make tool     # AIAC discovers github-tool's capabilities and completes the outbound gate
make diff PRIOR=01-after-agent
```

**Pause 3 — both onboarded.** The diff shows the outbound maps filling in: `target_allow_scopes`
keyed by the tool's SPIFFE identity, plus per-role grants for every discovered tool scope. This is
the moment least-privilege access to a downstream tool exists — generated, not hand-written.

Now drive real users through it:

```bash
make dev      # dev-user: read a file, commit a fix, read an issue (allowed) / close an issue (denied)
make test     # test-user: read/file issues (allowed) / read source (denied)
make devops   # devops-user: blocked at the inbound gate
```

Each target performs a real `grant_type=password` login, checks the inbound gate, performs a real
RFC 8693 token exchange for the tool's audience, and checks the outbound gate per intent — printing
a result table. **The verdicts should match step 5's live ones.** That agreement is the point.

Phase aggregates: `make init` (steps 00–03), `make onboard` (04–05), `make run` (all three users),
and `make demo` chaining all three without pauses.

### Where the Rego comes from

The PDP Policy Writer is **CR-backed**: for each onboarded agent it server-side-applies one
`AuthorizationPolicy` custom resource (`agent.rossoctl.dev/v1alpha1`, named `<name>` in namespace
`<ns>` — here `github-agent` in `team1`) whose `spec.policies[]` carry the inbound and outbound Rego
as `content`. In production it writes **CRs only**, no `.rego` files on disk.

So this demo reads its Rego straight from the CR — the same artifact the live enforcement point
consumes:

```bash
kubectl get authorizationpolicies.agent.rossoctl.dev github-agent -n team1 -o json
```

`onboard/04`/`05` fetch that CR and write each `spec.policies[].content` into
`generated/<snapshot>/team1/github-agent/{inbound,outbound}/request.rego`, mirroring the CR's
`policies[].path`, then `opa eval` those files. `make clear` deletes the CR; a re-onboard
server-side-applies a fresh one.

> The committed snapshots under `generated/` come from the real generator against a hand-built model
> of this scenario, so they match what the live writer emits. A live `make onboard` overwrites them
> and is the authoritative source.

---

## Did it work?

| Signal | Where | Expected |
|---|---|---|
| AIAC stack is up | `kubectl get deploy,statefulset -n aiac-system` | 3 deployments + 1 statefulset ready |
| OPA is wired into both legs | `grep -c 'name: opa'` on `authbridge-runtime-config` | `2` |
| Onboarding was event-driven | `make trigger` output | VERIFY-TRIGGER passes all four checks |
| A policy was generated | `kubectl get authorizationpolicy github-agent -n team1` | exists, with two `spec.policies[]` |
| The outbound gate is populated | the CR's `target_allow_scopes` | keyed by the tool's SPIFFE ID, non-empty |
| The generated policy enforces | `make enforce` output | full matrix matches, both decisive checks pass |
| Verdicts came from AIAC's policy | OPA decision log | `client_ok:true` present on an allow |
| Offline and live agree | `make dev` / `make test` vs step 5 | same verdicts |

---

## When something fails

> **First move on any driver failure:** re-run with `--collect-logs`. On a failure it dumps every
> component's logs — including the AuthBridge OPA decision log — into one directory, so you can
> diagnose from captured output instead of racing the live logs.

| Symptom | Cause / fix |
|---|---|
| **Every outbound probe denies, for every user** | Usually the outbound route is missing — run `make enforce`, which includes WIRE, rather than the enforce half alone. Otherwise the agent onboarded but the tool did not, leaving `target_allow_scopes` empty: `kubectl logs deployment/aiac-agent -n aiac-system \| grep -iE 'label missing\|MCP tools/list'`. JetStream redelivers after `ACK_WAIT` (600 s) and usually succeeds, so waiting then re-running `make enforce` often cures it. |
| **Onboarding fails with a `401` from the LLM** | `enable.sh` defaulted to OpenAI. Patch `aiac-agent-config` and `rollout restart` — see [step 1](#point-it-at-your-llm). The values come in via `envFrom`, so a patch without a restart does nothing. |
| **`driver.sh` refuses DEPLOY: workloads already exist** | The guard preventing a silent degrade into a replay. `make restore` first, or use `make replay` if you meant the replay. |
| **`make replay` refuses: workloads aren't deployed** | Mirror of the same guard. Run `make e2e` — its DEPLOY phase is the real trigger. |
| **Keycloak never registers the new clients** | Check the operator reconciled the `AgentRuntime` CRs (`kubectl logs deployment/rossoctl-controller-manager -n rossoctl-system`) and that the label landed: `kubectl get deployment github-agent -n team1 -o jsonpath='{.spec.template.metadata.labels}'`. |
| **`aiac-agent` never logs the consumed event** | Check the SPI attached (`kubectl logs statefulset/keycloak -n keycloak \| grep -i aiac-event-listener`) and that the realm's admin-events config still lists it. A `helm upgrade` or Keycloak restart since step 1 needs `./enable.sh --spi-only` re-run. |
| **An inbound probe is denied that should be allowed** | The generated inbound gate admits the `rossoctl` platform client as a source. `driver.sh` logs users in through `ROPC_CLIENT_ID` (default `rossoctl`) for that reason; `aiac-demo-cli`, used by step 6's `run-*.py`, is not an accepted source, so probing through it is denied on `azp`. |
| **An outbound probe returns a stale verdict** | The OPA SDK's bundle poller can take ~120 s to pick up a fresh CR write. The driver retries within `POLL_SECS`; by hand, wait and retry before concluding anything. |
| **`make agent` / `make tool` times out** | Onboarding drives real LLM calls and can take minutes. Raise `AIAC_ONBOARD_TIMEOUT`. |
| **`make setup` / `make dev` fails on a Keycloak profile error** | Keycloak 26 requires `email`/`firstName`/`lastName` before `grant_type=password`. `03-setup.py` sets these, so this points at a realm provisioned another way. |
| **A `run-*` target aborts with "no policy found"** | Those drivers always read `generated/02-after-tool/`. Run `make agent && make tool` first. |
| **`kubectl` reports `connection refused`** | The Kind node restarted and reassigned its API-server port: `kind export kubeconfig --name rossoctl`. `driver.sh` does this in preflight. |

### Capturing every operation

The driver narrates to stdout, but the operations play out across several in-cluster components.
`--collect-logs` dumps all of them into one per-run directory, and composes with any phase flag:

```bash
./driver.sh --collect-logs
./driver.sh --only-enforce --collect-logs
```

Logs are written at the end of a successful run **and on any failure** — the most useful time to
have them. The directory is printed at the end; by default `/tmp/onboarding-logs-<timestamp>/`.

| File | What it shows |
|---|---|
| `github-agent-authbridge-proxy.log` | **the OPA inbound/outbound allow/deny decisions** |
| `operator-controller-manager.log` | client registration, `rossoctl.io/type` labelling |
| `aiac-agent.log` | the onboarding pipeline consuming `aiac.apply.service.<uuid>` |
| `aiac-event-broker.log`, `keycloak.log` | the event bus; the SPI emitting events |
| `github-agent-app.log`, `github-tool.log` | app-side behaviour |
| `authorizationpolicy-github-agent.yaml` | the generated Rego, as written |
| `cm-authproxy-routes.yaml`, `cm-authbridge-runtime-config.yaml`, `pods-*.txt` | routing/runtime config, pod listings |

Component logs are time-scoped to the run. When collecting after a `--only-*` run whose interesting
history predates the invocation, widen the window with `COLLECT_SINCE` (RFC3339). `COLLECT_ROOT`
changes the parent directory.

### Re-proving the trigger without a teardown

Steps 4–5 prove the trigger by onboarding something genuinely new, which needs the workloads
undeployed. Where you can't afford that, force a replay:

```bash
make replay
```

This records both clients' Keycloak UUIDs, deletes the clients, deletes both pods, and polls until
the operator re-registers **new** UUIDs — then checks `aiac-agent` consumed the fresh events and
rewrote the CR (new `resourceVersion`).

It is **weaker evidence** than step 4, because it replays the path against workloads already
onboarded once. Prefer `make restore` then `make e2e` when you can afford the teardown.

---

## Cleanup

Four levels, narrowest first. Each is idempotent and safe to re-run.

| Want | Command | Keeps |
|---|---|---|
| Re-run step 6 from a clean baseline | `make clear` | everything deployed; resets generated roles/scopes, the Policy Store, the CR, and `generated/` |
| Re-run the live path so DEPLOY is a genuine first trigger again | `make restore` | the AIAC stack, NATS broker, Keycloak SPI, demo users/roles |
| Uninstall **just AIAC** — the inverse of step 1 | `make uninstall-aiac` | everything except `aiac-system` |
| Remove the demo entirely — back to the **post-install state** | `make teardown` | only platform state (see below) |

Preview any teardown first: `make teardown ARGS=--dry-run` surveys what is actually present and
lists every deletion without performing one.

### `make restore`

Removes `github-agent`/`github-tool` **completely** — Deployments, Services, ServiceAccounts,
`AgentRuntime` CRs, their Keycloak clients, credentials Secrets, leftover client-scopes and realm
roles, and the `AuthorizationPolicy` CR — and reverts step 5's outbound wiring. That completeness is
the point: the next DEPLOY must be a genuine first-time trigger, not a no-op against clients that
are still registered.

To also reverse step 1's Keycloak-side changes (the realm's `aiac-event-listener` config and the
Keycloak StatefulSet image):

```bash
make restore ARGS=--include-infra
```

### `make teardown`

`make restore` deliberately keeps the AIAC stack, the NATS broker and the demo's Keycloak
users/roles, because re-running the demo needs them. `teardown` closes that gap — it delegates the
overlapping surface to `restore.sh --include-infra`, then additionally removes:

- the `team1` ConfigMaps the demo's manifest created (`authbridge-config`, `authproxy-routes`)
- the whole `aiac-system` namespace — stack, broker, the Policy Model Store PVC, `aiac-agent-secret`,
  `aiac-policy`
- the demo's Keycloak users, the three realm roles, and the `aiac-demo-cli` client

```bash
make teardown ARGS=--dry-run       # list everything; change nothing
make teardown                      # tear down (prompts; ARGS=--yes skips)
make teardown ARGS=--include-opa   # also revert step 2's overlay (needs the chart clone)
```

**What it deliberately leaves**, because the demo does not own it:

- **the `team1` namespace itself** — the installer owns it
  ([`INSTALL.md`](../../assets/INSTALL.md): "a precondition, not an output"). A fresh install gives
  you an *empty* `team1`, so emptying it *is* the post-install state.
- **the realm fix-up** (Direct Access Grants, the `username → sub` mapper) — one-time cluster state
  that `k8s/opa-kind-runbook.md`'s probes and the `-m system` suite both depend on.
- **the operator's `*-aud` audience client scopes**, which it owns and recreates.
- **step 2's OPA overlay**, unless you pass `--include-opa`.
- **container images already in the Kind node.** Inert; the script prints the `docker image rm` line.

> **One caveat on `authproxy-routes`.** The demo declares that ConfigMap in `team1`, so `teardown`
> deletes it as the symmetric inverse of `deploy.sh`. If your platform also seeds one there, the
> demo overwrote it at deploy time and there is no saved copy — re-apply the installer's version
> afterwards.

### `make uninstall-aiac`

Deletes the `aiac-system` namespace and everything in it — the Agent, Interface Pod, NATS broker,
the Policy Model Store **and its PVC**, `aiac-agent-secret`, `aiac-policy` — and touches nothing
else. Needs no Keycloak credentials. Reinstall with `make enable`.

It is **not** a route back to the post-install state: the workloads stay deployed and registered,
the demo's Keycloak state stays, the SPI stays installed, and the OPA overlay stays wired. Use
`make teardown` for that. (`--aiac-only` and `--include-opa` are rejected together — the overlay
lives in `team1`, not `aiac-system`.)

> Deleting the namespace destroys the Policy Model Store's PVC and its SQLite with it. `make clear`
> is the non-destructive way to reset that store's contents while leaving the stack running.

---

## Known gaps

- **"Direct user → tool" is not enforced by the generated policy.** A fourth acceptance row —
  `dev-user` calling `github-tool` **directly**, bypassing the agent — is not covered by anything
  AIAC generates, and the driver does not probe it rather than report a fabricated result.

  What guards that path depends on your cluster, so check rather than assume. `github-tool` is a
  bare FastMCP stub with **no authentication of its own**. Whether it gets an AuthBridge sidecar is
  the operator's decision:

  ```bash
  kubectl get pod -n team1 -l app=github-tool -o jsonpath='{.items[*].spec.containers[*].name}'
  ```

  - **Sidecar injected** (two containers): the tool inherits `team1`'s shared
    `authbridge-runtime-config`, whose inbound pipeline carries `jwt-validation` and `opa`, so an
    unauthenticated direct call is rejected with **401**. But AIAC writes a CR for **`github-agent`
    only**, so that inbound OPA has no tool-specific generated policy and falls back to the
    cluster-wide `default` CR. Nothing derived from `policy.md` constrains it.
  - **No sidecar** (one container): the endpoint is open, and a direct in-cluster call succeeds
    unconditionally.

  Closing this properly means AIAC generating a tool-inbound policy, not merely having a sidecar
  present.
- **Step 6 does not sit in the request path.** Its verdicts come from `opa eval` against the
  generated Rego. Steps 4–5 are the in-path proof.
- **Step 6's token exchange stops short of a call.** `run-*.py` performs a real RFC 8693 exchange to
  prove the flow, but does not feed the exchanged token into a live call against `github-tool`.
- **The agent's own `MCP_URL` targets the production tool** (`github-tool-mcp`), which this install
  path does not deploy. The demo probes the tool directly through the sidecar's forward proxy, so
  enforcement is proven, but the agent autonomously calling a tool is not exercised here.

---

## Appendix — installing AIAC by hand

What `make enable` automates, from
[`k8s/aiac-deployment-guide.md`](../../../k8s/aiac-deployment-guide.md). Use this when `enable.sh`'s
assumptions don't hold — a non-Kind cluster, a remote registry, or an LLM key that isn't already in
`team1/openai-secret`. Run from the **repo root**.

| Manifest | Contents | Port(s) |
|---|---|---|
| `pdp-interface-deployment.yaml` | Interface Pod (IdP Configuration Service + PDP Policy Writer) + 2 ClusterIP Services | 7071, 7072 |
| `policy-model-store-statefulset.yaml` | Policy Model Store StatefulSet + 1 Gi PVC + headless + ClusterIP Service | 7074 |
| `event-broker-deployment.yaml` | NATS JetStream Event Broker + ClusterIP Service | 4222 |
| `agent-deployment.yaml` | Agent Pod (`aiac-init` init container + AIAC Agent) + ClusterIP Service | 7070 |

**1 — Build the images.** Note the differing build contexts: `aiac-pdp-config` builds from its own
component directory, the other three from `src/`.

```bash
docker build -f src/aiac/idp/service/configuration/keycloak/Dockerfile \
  -t localhost/aiac-pdp-config:local src/aiac/idp/service/configuration/keycloak/
docker build -f src/aiac/pdp/service/policy/opa/Dockerfile \
  -t localhost/aiac-pdp-policy-opa:local src/
docker build -f src/aiac/policy/model_store/service/Dockerfile \
  -t localhost/aiac-policy-model-store:local src/
docker build -f src/aiac/agent/controller/Dockerfile \
  -t localhost/aiac-agent:local src/
```

Because three of these share the `src/` context, a change to shared code under `src/aiac/` affects
all of them — rebuild all three rather than guessing which one owns the file. The Event Broker uses
stock `nats:2.14-alpine`, with no build step.

**2 — Load them into the cluster.**

```bash
for i in aiac-pdp-config aiac-pdp-policy-opa aiac-policy-model-store aiac-agent; do
  kind load docker-image "localhost/$i:local" --name rossoctl
done
```

For a fully air-gapped Kind cluster also `docker pull nats:2.14-alpine` and `kind load` it;
`event-broker-deployment.yaml` uses `imagePullPolicy: IfNotPresent`, so a networked cluster pulls it
directly. For a remote registry: tag, push, and update the `image:` fields in the manifests.

**3 — Create the namespace and secrets.**

```bash
kubectl create namespace aiac-system

kubectl create secret generic keycloak-admin-secret -n aiac-system \
  --from-literal=KEYCLOAK_ADMIN_USERNAME=<admin-user> \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD=<admin-password>

# The LLM key. agent-deployment.yaml only *references* this Secret — create it before step 5.
kubectl create secret generic aiac-agent-secret -n aiac-system \
  --from-literal=LLM_API_KEY=<your-api-key>
```

> `pdp-interface-deployment.yaml` carries placeholder credentials for reference only. For any
> non-local environment create the secret manually and remove the `stringData` block.

**4 — Review the environment.** `aiac-pdp-config` in `pdp-interface-deployment.yaml` holds the
service URLs (`KEYCLOAK_URL`, `KEYCLOAK_REALM`, `AIAC_PDP_CONFIG_URL`, `AIAC_PDP_POLICY_URL`,
`AIAC_POLICY_MODEL_STORE_URL`, `SERVICEPOLICY_DB_PATH`, `NATS_URL`); the defaults match the
in-cluster Service names used here. `aiac-init` treats `AIAC_RAG_INGEST_URL` as optional and skips
the RAG health check when unset, which is correct for the current phase.

**5 — Apply, in dependency order.**

```bash
kubectl apply -f k8s/pdp-interface-deployment.yaml          # namespace, ConfigMap, Services
kubectl apply -f k8s/event-broker-deployment.yaml           # no dependencies
kubectl apply -f k8s/policy-model-store-statefulset.yaml
kubectl apply -f k8s/agent-deployment.yaml                  # aiac-init waits for NATS + Interface

kubectl wait deployment/aiac-interface    -n aiac-system --for=condition=Available --timeout=120s
kubectl wait deployment/aiac-event-broker -n aiac-system --for=condition=Available --timeout=120s
kubectl wait statefulset/aiac-policy-model-store -n aiac-system \
  --for=jsonpath='{.status.readyReplicas}'=1 --timeout=120s
kubectl wait deployment/aiac-agent        -n aiac-system --for=condition=Available --timeout=120s
```

**6 — Point the Agent at your LLM.** `agent-deployment.yaml` ships placeholders on purpose, so patch
the live ConfigMap after applying it.

```bash
kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
  -p '{"data":{"LLM_BASE_URL":"https://<your-endpoint>","LLM_MODEL":"<model>"}}'
kubectl rollout restart deployment/aiac-agent -n aiac-system
```

> The restart is **required**, not hygiene. Both values reach the pod via `envFrom`, which snapshots
> ConfigMap and Secret values at container start and never reloads them. A patched ConfigMap with no
> restart leaves the old values live — which surfaces much later as an LLM `401`/`403` that looks
> like a bad key. The same applies to any edit of `aiac-agent-secret`.
>
> Confirm what the pod actually has:
>
> ```bash
> kubectl exec deployment/aiac-agent -n aiac-system -- sh -c 'echo "$LLM_BASE_URL  $LLM_MODEL"'
> ```
>
> If your endpoint is an OpenAI-compatible proxy, check the model name it accepts — a proxy's
> allow-list often rejects provider-prefixed names, and the resulting `403` names the models it will
> take.

**7 — Mount the scenario policy.** The Policy Rules Builder reads `policy.md` from the `aiac-policy`
ConfigMap. Generate it from this demo's own constant so the two cannot drift:

```bash
python3 -c 'import sys; sys.path.insert(0, "demo/use-cases/onboarding/lib"); import scenario; sys.stdout.write(scenario.POLICY_ABSTRACT)' > /tmp/policy.md
kubectl create configmap aiac-policy -n aiac-system --from-file=policy.md=/tmp/policy.md \
  --dry-run=client -o yaml | kubectl apply -f -
```

**8 — Install the Keycloak SPI listener.** The one part with no concise manual equivalent — it
builds a shaded jar, derives a Keycloak image from it, and enables the listener on the realm. See
[`keycloak-spi/README.md`](../../../keycloak-spi/README.md) for the build, and prefer
`./enable.sh --spi-only`.

**9 — Verify.** Each service exposes `/health` returning `{"status":"ok"}`:

```bash
for p in 7071 7072 7074 7070; do
  case $p in
    7071) svc=aiac-pdp-config-service ;;
    7072) svc=aiac-pdp-policy-service ;;
    7074) svc=aiac-policy-model-store-service ;;
    7070) svc=aiac-agent-service ;;
  esac
  kubectl port-forward "svc/$svc" "$p:$p" -n aiac-system >/dev/null 2>&1 &
  pf=$!; sleep 2; printf '%s: ' "$svc"; curl -s "http://localhost:$p/health"; echo
  kill $pf
done
```

Then continue from [step 2](#step-2--wire-opa-into-both-authbridge-legs).
