# UC-1 — Onboarding an agent and a tool, end to end

**Nobody wrote these access rules.** AIAC discovers a GitHub agent and a GitHub tool running in the
cluster, reads a two-line plain-English policy, and generates enforceable least-privilege
authorization for both — who may call the agent, and what the agent may do on the tool on their
behalf. Then a real HTTP request through the live OPA plugin is allowed or denied by it.

This is one runbook for the whole thing: installing AIAC, wiring enforcement, onboarding, and
proving the result. Everything is live — a real cluster, a real Keycloak, a real LLM call, a real
RFC 8693 token exchange. There is no offline mode and no fixtures.

Two claims are worth stating up front, because the demo is built to prove them rather than assert
them:

- **Deploying the workload is the trigger.** No human runs an onboarding command. The first-ever
  `kubectl apply` of `github-agent`/`github-tool` is what causes AIAC to generate their policy.
- **The generated policy is what enforces.** The allow/deny verdicts in Part 5 come from the
  deployed AuthBridge OPA plugin reading the `AuthorizationPolicy` CR AIAC wrote — not from
  evaluating a file on the side.

| Part | What happens | Command |
|---|---|---|
| [1](#part-1--install-the-aiac-stack) | Install AIAC (stack, NATS broker, Keycloak SPI) | `./enable.sh` |
| [2](#part-2--wire-opa-into-both-authbridge-legs) | Wire OPA into both AuthBridge legs | `k8s/opa-kind-enable.sh` |
| [3](#part-3--provision-the-scenario) | Provision users/roles/policy | `make keycloak && make users` |
| [4](#part-4--onboard-by-deploying) | Deploy the workloads — **the trigger** | `./driver.sh --only-deploy` |
| [5](#part-5--enforce-live) | Probe the live OPA plugin | `./driver.sh --only-wire-outbound && ./driver.sh --only-enforce` |
| [6](#part-6--the-narrated-walkthrough-optional) | Inspect what was generated, step by step | `make setup && make agent && make tool` |

Parts 4–5 in one go: `./driver.sh` (or `make e2e`).

---

## The policy

This is the entire input a human wrote. No YAML, no scope tables, no per-endpoint rules:

```
Grant access on a least-privilege basis: allow only what this policy states; deny by default.

- Developers may read and modify source, and read issues.
- Testers may read and modify issues.
```

## What comes out the other side

AIAC turns that into two Rego policies per agent — one gating who may call it, one gating what it
may do downstream — derived from the policy text plus the realm-role descriptions already in
Keycloak and the tool's own discovered capabilities. Both use the fixed AuthBridge packages
(`authbridge.client.{inbound,outbound}.request`) the live OPA plugin evaluates, keyed on the
plugin's real input shape (`input.identity.subject`, `input.identity.service_id`,
`input.mcp.params.name`). The generated outbound gate, in full:

```rego
package authbridge.client.outbound.request
import rego.v1

subject_roles := {
    "dev-user": ["developer"],
    "test-user": ["tester"],
}
subject_role_allow_scopes := {
    "developer": ["source-write", "source-read", "issues-read"],
    "tester": ["issues-write", "issues-read"],
}
subject_role_deny_scopes := {}
target_allow_scopes := {
    "spiffe://localtest.me/ns/team1/sa/github-tool": ["source-write", "source-read", "issues-write", "issues-read"],
}
target_deny_scopes := {}

subject_allow_ok if {
    some role in subject_roles[input.identity.subject]
    input.mcp.params.name in subject_role_allow_scopes[role]
}
target_allow_ok if {
    input.mcp.params.name in target_allow_scopes[input.identity.service_id]
}
# ... subject_deny_ok / target_deny_ok, same shape against the *_deny_scopes maps

default allow := false
allow if { subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }
```

Every access decision is a two-gate AND on the same invoked tool (`input.mcp.params.name`, the
**bare** MCP tool name such as `source-read`), with the deny maps as overrides: the calling user's
role must be granted the scope (`subject_allow_ok`), *and* the target service the exchanged token
was minted for must expose it (`target_allow_ok`, keyed by the full `input.identity.service_id`
SPIFFE id), *and* neither deny map may claim it. A developer can read and write source and read
issues; a tester can read and write issues but never touches source — exactly the two-line policy,
and nothing it didn't say.

`agent_role_scopes` also appears in the generated file, commented as informational only; `allow`
does not reference it.

## Architecture

```
 dev-user / test-user / devops-user
        │  grant_type=password
        ▼
   Keycloak  ──────────────────────────────┐
        │  access_token                    │ RFC 8693 token exchange
        ▼                                  │ (subject token -> tool-audience token)
  [inbound gate: may this user call        │
   the agent? — generated from policy.md]  ▼
        │                            [outbound gate: may the agent reach
        ▼                             this tool scope, for this user? —
   github-agent                       generated from policy.md + tool capabilities]
        │                                  │
        └──────────────────────────────────┴──► github-tool
```

In Parts 4–5 both gates are evaluated by the **deployed AuthBridge OPA plugin**, in the request
path:

```
Inbound:   caller ─► jwt-validation ─► OPA ─► github-agent app
Outbound:  github-agent app ─► token-exchange ─► OPA ─► github-tool
```

Policies reach the plugin via the bundle service every AuthBridge workload polls
(`http://bundle-service.rossoctl-system.svc.cluster.local:8080`). On the outbound leg OPA sits
**after** `token-exchange`, so policies can read the delegation chain and the synthesized
`input.identity`. Part 6 instead evaluates the same Rego with `opa eval`, for inspection.

---

## Prerequisites

- **A Kind cluster named `rossoctl`** with the rossoctl platform installed — SPIRE, Keycloak, and
  the rossoctl operator. Namespace `team1` must exist; the Rossoctl installer owns it, nothing here
  creates it.
- **Two sibling repo clones** the OPA wiring scripts need:
  - `OPERATOR_DIR` → `rossoctl/operator` clone (default `../operator`)
  - `ROSSOCTL_DIR` → `rossoctl/rossoctl` clone, i.e. the Helm chart (default `../rossoctl`)
- **`kubectl`, `helm`, `kind`, `curl`, `python3`**, and `docker` or `podman` on `PATH`.
- **An OpenAI-compatible LLM endpoint + API key** for AIAC's Policy Rules Builder. `enable.sh`
  defaults to reusing the key already in `team1/openai-secret` (see its `OPENAI_SECRET_NS` /
  `OPENAI_SECRET_NAME` / `LLM_BASE_URL` / `LLM_MODEL` env vars).
- **`github-agent`/`github-tool` NOT already deployed in `team1`.** Part 4's whole point is that a
  first-time deploy triggers onboarding, so it needs a clean slate. If you have run this demo
  before, `./restore.sh` first.
- **A one-time Keycloak realm fix-up**, if the realm was freshly provisioned: the `rossoctl` client
  needs Direct Access Grants enabled and a `username → sub` protocol mapper, or token minting fails
  with `unauthorized_client` (grants disabled) or yields a token with no `sub` (mapper missing).
  `make users` (Part 3) sets the demo users' passwords and login profile; the client-level change is
  platform state:

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

Run every command below from **this directory** (`demo/use-cases/onboarding/`) unless a path
says otherwise; `k8s/…` paths are relative to the repo root.

You do **not** need to export the Keycloak variables by hand. `make keycloak`
(`init/00-discover-keycloak.sh`) port-forwards the in-cluster Keycloak to a local port and reads the
admin credentials from `keycloak-admin-secret`, exporting `KEYCLOAK_URL` /
`KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` for the step that runs it. Every
Keycloak-touching target self-runs it first, so you rarely call it directly — the forward is set up
once and reused. If you already export those three variables, your values win. To tear the forward
down afterwards: `pkill -f 'port-forward .*keycloak-service'`.

---

## Part 1 — Install the AIAC stack

AIAC is not deployed by default. One command builds its four images, wires the LLM configuration,
applies the manifests, deploys the NATS event broker, and installs the Keycloak event-listener SPI:

```bash
OPENAI_SECRET_NS=team1 OPENAI_SECRET_NAME=openai-secret ./enable.sh
```

Or `make enable`. This automates [`k8s/aiac-deployment-guide.md`](../../../k8s/aiac-deployment-guide.md)
for a Kind cluster; the [appendix](#appendix--installing-aiac-by-hand) has the equivalent
copy-paste commands for environments it doesn't fit. Three independently runnable steps:

| Step | Flag | What it does |
|---|---|---|
| AIAC stack | `--stack-only` | Builds/loads `aiac-pdp-config`, `aiac-pdp-policy-opa`, `aiac-policy-model-store`, `aiac-agent`; creates `aiac-agent-secret` from the OpenAI key; provisions the `aiac-policy` ConfigMap from `lib/scenario.py`'s policy text; applies `pdp-interface-deployment.yaml`, `policy-model-store-statefulset.yaml`, `agent-deployment.yaml`; points `aiac-agent-config` at your LLM endpoint |
| NATS broker | `--broker-only` | Applies `event-broker-deployment.yaml`. The SPI's default `NATS_URL` (`nats://aiac-event-broker-service:4222`) already matches this Service, so nothing needs configuring on either side |
| Keycloak SPI | `--spi-only` | Builds the shaded jar in a Maven container (no JDK needed on your machine), builds a derived Keycloak image with the jar in `/opt/keycloak/providers/` + `kc.sh build`, `kind load`s it, `kubectl set image`s the live `keycloak` StatefulSet, and enables the listener on the realm's admin-events config |

The Keycloak change is a **live, reversible patch**, not a chart edit — a later `helm upgrade` of the
`rossoctl` release would revert it (same spirit as `opa-kind-enable.sh`'s overlay). Undo it
deliberately with `./restore.sh --include-infra`.

`enable.sh` deliberately does **not** deploy `github-agent`/`github-tool`. They stay undeployed so
Part 4 is a genuine first-time trigger.

Verify:

```bash
kubectl get deployment aiac-agent aiac-interface aiac-event-broker -n aiac-system
kubectl get statefulset aiac-policy-model-store -n aiac-system
kubectl logs statefulset/keycloak -n keycloak | grep -i "aiac-event-listener\|providers changed"
```

## Part 2 — Wire OPA into both AuthBridge legs

Enforcement is an opt-in AuthBridge pipeline plugin. This rebuilds `localhost/authbridge:local` from
the current tree, loads it into Kind, and `helm upgrade`s the chart with a temporary overlay
inserting `opa` (after `token-exchange` on the outbound leg) plus the parser set into every `team1`
agent's pipeline. It does **not** modify `charts/rossoctl/values.yaml` on disk.

```bash
OPERATOR_DIR=../operator ROSSOCTL_DIR=../rossoctl ../../../k8s/opa-kind-enable.sh
```

Confirm OPA is in **both** legs — expect `2`:

```bash
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
```

`driver.sh`'s preflight checks this and refuses to run without it. Full background, including the
exact `input` document the plugin builds on each leg, is in
[`k8s/opa-kind-runbook.md`](../../../k8s/opa-kind-runbook.md).

## Part 3 — Provision the scenario

```bash
make keycloak && make users
```

`make users` provisions the three demo users and their realm roles — with the role **descriptions**
the Policy Rules Builder reads, and the `email`/`firstName`/`lastName` Keycloak 26's declarative
user profile requires before `grant_type=password` will succeed — and mounts `policy.md` on the
Controller.

| User | Realm role |
|---|---|
| `dev-user` | `developer` |
| `test-user` | `tester` |
| `devops-user` | `devops` |

**Order matters here, and it is the one non-obvious thing about this runbook.** `make users` is
`make setup` minus the two steps that resolve the workloads' Keycloak client UUIDs — those abort if
the workloads aren't deployed, and deploying them is exactly what Part 4 does as the trigger. So the
realm must hold the users, roles and policy *before* the deploy fires onboarding, or the Policy
Rules Builder has no role descriptions to reason about. Part 6 runs the full `make setup` later, once
the clients exist.

## Part 4 — Onboard by deploying

```bash
./driver.sh --only-deploy      # or: make trigger
```

This runs two phases. **DEPLOY** loads the workload images and applies their manifests;
**VERIFY-TRIGGER** proves the apply caused onboarding.

The split matters for the claim. [`demo/assets/kind-load.sh`](../../assets/kind-load.sh) builds and
`kind load`s the images and **applies nothing** — it cannot register a Keycloak client.
[`demo/assets/deploy.sh`](../../assets/deploy.sh) then does the `kubectl apply` + `rollout status`.
So the trigger is isolated to that second call. Both scripts are used unmodified, exactly as the
UC-1 system suite uses them.

### Why deploying is the trigger

The operator's `AgentRuntimeReconciler` stamps `rossoctl.io/type=agent|tool` onto a Deployment's
pod-template labels the first time its `AgentRuntime` CR resolves. That label is precisely what the
`ClientRegistrationReconciler`'s watch predicate keys on, and *that* is what calls
`RegisterOrFetchClientWithToken` — producing a genuine Keycloak `CLIENT_CREATE` admin event. The
SPI listener from Part 1 publishes it on NATS as `aiac.apply.service.<uuid>`, and `aiac-agent`'s
consumer runs `onboard_service`. So the first-ever apply of the workload plus its `AgentRuntime` CR
— both already checked into `demo/assets/` — *is* the trigger. Nothing else creates it.

VERIFY-TRIGGER polls, in order, until each is true:

1. `team1/github-agent` and `team1/github-tool` appear as Keycloak clients (first registration
   ever — no before/after diffing needed).
2. `aiac-agent`'s logs show it consumed `aiac.apply.service.<uuid>` for both, over NATS.
3. The `authorizationpolicies.agent.rossoctl.dev/github-agent` CR exists — printing its content.

There is no `POST /apply/service/{id}` call anywhere in this path.

> Expect this to take a few minutes. The agent publishes its A2A AgentCard skills only *after* the
> deploy, so onboarding redelivers over JetStream until `source_operations`/`issue_operations`
> resolve and AIAC writes the CR. `POLL_SECS` (default 420) bounds it; each phase breaks the instant
> its condition is met, so a healthy run is faster than the ceiling.

## Part 5 — Enforce live

```bash
./driver.sh --only-wire-outbound
./driver.sh --only-enforce
```

Or both with `make enforce`. **WIRE** configures AuthBridge's own outbound leg — the `github-tool`
route in the `authproxy-routes` ConfigMap, and the `agent-team1-github-tool-aud` client scope as an
*optional* scope on `github-agent`'s client, which is what makes AuthBridge's `client_credentials`
exchange work. AIAC's onboarding does not configure this; it is the same two sub-steps as
`k8s/opa-kind-runbook.md` Part B.1/B.2, and it is a different exchange path from the direct RFC 8693
proof Part 6 uses.

**ENFORCE** then drives real HTTP probes through the live plugin:

| Request | Inbound | Outbound (via the agent) |
|---|---|---|
| `dev-user` → `github-agent` | ✅ allowed | `source-read`, `source-write`, `issues-read` allowed; `issues-write` denied |
| `test-user` → `github-agent` | ✅ allowed | `issues-read`, `issues-write` allowed; `source-read`/`source-write` denied |
| `devops-user` → `github-agent` | ❌ denied (403) | never reached |

`devops-user`'s denial is the intended story, not a failure: nothing in the policy grants it access
to the agent at all. The driver hard-fails on the two decisive outbound checks
(`dev-user`→`source-read` must be allowed, `test-user`→`source-read` must not be) and reports the
rest of the matrix, then prints the matching OPA decision-log lines.

> **Reading outbound verdicts.** Because the outbound pipeline includes `mcp-parser`, a denial comes
> back the MCP-correct way: a JSON-RPC 2.0 error frame at **HTTP 200** (`error.code: -32000`,
> `error.data.plugin: "opa"`), not an HTTP error status. Classify by the response **body** — an
> `error` frame is denied, a `result` frame is allowed. The request never reaches `github-tool`.

The whole of Parts 4–5 in one command: `./driver.sh` (or `make e2e`).

## Part 6 — The narrated walkthrough (optional)

Everything above is automated and fails loudly. This part is the opposite: it walks the same
scenario in small steps so you can watch what AIAC generates and when. It needs the workloads
deployed and registered — true now, after Part 4.

It differs from Parts 4–5 in two ways, both deliberate: onboarding is invoked **manually**
(`POST /apply/service/{id}`), and the verdicts come from evaluating the generated Rego with
`opa eval` rather than from the live plugin. Same policy, same generated files, inspected instead of
enforced.

```bash
make setup    # the full version: adds client-UUID resolution + direct token-exchange config
make clear    # reset to a clean slate — deletes the AuthorizationPolicy CR and generated/
make show
```

**Pause 1 — baseline.** `make show` reports three users with roles, no `github-*` roles or scopes
yet, and no generated `.rego` at all. Nothing has been onboarded; there is nothing to enforce.

```bash
make agent    # AIAC discovers github-agent, reads policy.md, generates the inbound gate
make show
```

**Pause 2 — the agent alone.** The inbound gate is populated: developers and testers can reach the
agent's discovered scopes. The outbound gate exists but every map in it is still empty — there is no
tool yet for the agent to act on.

```bash
make tool     # AIAC discovers github-tool's capabilities and completes the outbound gate
make diff PRIOR=01-after-agent
```

**Pause 3 — both onboarded.** The diff shows the outbound gate's maps filling in:
`target_allow_scopes` keyed by the tool's SPIFFE identity, and per-role grants for every discovered
tool scope. This is the moment least-privilege access to a downstream tool exists — generated, not
hand-written.

Now drive real users through it:

```bash
make dev      # dev-user: read a file, commit a fix, read an issue (allowed) / close an issue (denied)
make test     # test-user: read/file issues (allowed) / read source (denied)
make devops   # devops-user: blocked at the inbound gate — no role sources any agent scope
```

Each target performs a real `grant_type=password` login, checks the inbound gate, performs a real
RFC 8693 token exchange for the tool's audience, and checks the outbound gate per intent — printing
a result table. The verdicts should match Part 5's live ones.

Phase aggregates: `make init` (steps 00–03), `make onboard` (04–05), `make run` (all three users),
and `make demo` chaining all three with no pauses.

### How this sources the generated Rego

The PDP Policy Writer is **CR-backed**: for each onboarded agent it server-side-applies a single
`AuthorizationPolicy` custom resource (`agent.rossoctl.dev/v1alpha1`, named `<name>` in namespace
`<ns>` — here `github-agent` in `team1`) whose `spec.policies[]` carry the inbound and outbound Rego
as `content`. In production it writes **CRs only** — no `.rego` files on disk
(`k8s/pdp-interface-deployment.yaml` keeps `POLICY_WRITER_DUMP_REGO` off and mounts no `/rego`).

So this demo reads its Rego **straight from the CR** — the same artifact the live enforcement point
consumes — rather than from a debug file dump:

```bash
kubectl get authorizationpolicies.agent.rossoctl.dev github-agent -n team1 -o json
```

`onboard/04`/`05` fetch that CR and write each `spec.policies[].content` into
`generated/<snapshot>/team1/github-agent/{inbound,outbound}/request.rego` (mirroring the CR's
`policies[].path`), then `opa eval` those files. `make clear` deletes the CR; a re-onboard
server-side-applies a fresh one.

> The committed snapshots under `generated/` come from the real generator
> (`src/aiac/pdp/service/policy/opa/rego.py`) against a hand-built model of this scenario, so they
> match the CR content the live writer emits (byte-for-byte with `docs/examples/opa-team1-policy.yaml`
> for the after-tool state, modulo the cluster's actual trust domain). A live `make onboard`
> overwrites them and is the authoritative source of truth.

## Optional — re-prove the trigger without a teardown

Parts 4–5 prove the trigger by onboarding something genuinely new, which needs the workloads
undeployed first. On a cluster where they are already deployed and you don't want to tear them down,
you can force a replay instead:

```bash
./driver.sh --only-replay-trigger      # or: make replay
```

This records both clients' current Keycloak UUIDs, deletes the clients via the Admin API, deletes
both pods, and polls until the operator re-registers **new** UUIDs — then checks that `aiac-agent`
consumed the fresh events and rewrote the CR (new `resourceVersion`). It works because
`ClientRegistrationReconciler` calls `RegisterOrFetchClientWithToken` unconditionally on every
reconcile; it does not skip because a credentials Secret already exists. If a pod restart doesn't
wake the reconciler within half the timeout, the driver restarts the operator, which re-lists every
`AgentRuntime`.

This is **weaker evidence** than Part 4 — it replays the path against workloads that were already
onboarded once — which is why it is opt-in and never part of a default run. Prefer
`./restore.sh` followed by a normal `./driver.sh` when you can afford the teardown.

## Capturing every operation

The driver narrates to stdout, but the operations play out across several in-cluster components. Add
`--collect-logs` to dump all of them into one per-run directory. It composes with any phase flag:

```bash
./driver.sh --collect-logs
./driver.sh --only-enforce --collect-logs
```

Logs are written at the end of a successful run **and on any `die()` failure** — the most useful
time to have them, since a failed run becomes debuggable without re-running. The directory is
printed at the end; by default it lands under `/tmp/uc1-logs-<timestamp>/`:

| File | Component | What it shows |
|---|---|---|
| `operator-controller-manager.log` | `rossoctl-controller-manager` (`rossoctl-system`) | client registration, `rossoctl.io/type` labelling |
| `aiac-agent.log` | `aiac-agent` (`aiac-system`) | the onboarding pipeline consuming `aiac.apply.service.<uuid>` |
| `aiac-event-broker.log` | NATS broker (`aiac-system`) | the event bus |
| `keycloak.log` | `keycloak` (`keycloak`) | the `aiac-event-listener` SPI emitting events |
| `github-agent-authbridge-proxy.log` | AuthBridge sidecar (`team1`) | **the OPA inbound/outbound allow/deny decisions** |
| `github-agent-app.log`, `github-tool.log` | workload app containers (`team1`) | app-side behaviour |
| `authorizationpolicy-github-agent.yaml` | the CR AIAC wrote | the generated Rego (snapshot) |
| `cm-authproxy-routes.yaml`, `cm-authbridge-runtime-config.yaml`, `pods-*.txt` | routing/runtime config + pod listings | current desired/observed state |

Component logs are time-scoped to the run, so log volume can't push evidence out of view. When
collecting after a `--only-*` run whose interesting history predates the invocation, widen the
window with `COLLECT_SINCE` (an RFC3339 timestamp). `COLLECT_ROOT` changes the parent directory and
`KC_NS` the Keycloak namespace.

---

## Cleanup

```bash
./restore.sh                    # or: make restore
```

Removes `github-agent`/`github-tool` **completely** — Deployments, Services, ServiceAccounts,
`AgentRuntime` CRs, their Keycloak clients, credentials Secrets, leftover client-scopes and realm
roles, and the `AuthorizationPolicy` CR AIAC wrote — and reverts Part 5's outbound wiring. That
completeness is the point: the next `./driver.sh` DEPLOY phase must be a genuine first-time trigger
again, not a no-op against clients that are still registered.

By default the AIAC stack, NATS broker and Keycloak SPI stay in place, since re-running the demo
needs them. To also reverse Part 1's Keycloak-side changes (the realm's `aiac-event-listener` config
and the Keycloak StatefulSet image):

```bash
./restore.sh --include-infra    # or: make restore ARGS=--include-infra
```

For a fully clean slate, drop the namespace and revert the OPA pipeline:

```bash
kubectl delete namespace aiac-system
ROSSOCTL_DIR=../rossoctl ../../../k8s/opa-kind-restore.sh
```

The Keycloak realm/user changes from the Prerequisites are shared, cluster-wide state and are
harmless to leave in place.

## Troubleshooting

> **First move on any driver failure:** re-run it with `--collect-logs`. On a `die()` it dumps every
> component's logs — including the AuthBridge OPA decision log — into one directory, so you can
> diagnose from captured output instead of racing the live logs.

- **`driver.sh` refuses to run DEPLOY, saying the workloads already exist.** That guard exists so
  this demo can never silently degrade into a forced replay. Run `./restore.sh` first, or use
  `--only-replay-trigger` if you meant the replay.
- **`--only-replay-trigger` refuses, saying the workloads aren't deployed.** The mirror image of the
  same guard. Run a normal `./driver.sh` — its DEPLOY phase is the real trigger.
- **Keycloak never registers the new clients.** Check the operator reconciled the `AgentRuntime`
  CRs (`kubectl logs deployment/rossoctl-controller-manager -n rossoctl-system`) and that the
  pod-template picked up the label:
  `kubectl get deployment github-agent -n team1 -o jsonpath='{.spec.template.metadata.labels}'`.
- **`aiac-agent` never logs the consumed event.** Check the SPI provider actually attached
  (`kubectl logs statefulset/keycloak -n keycloak | grep -i aiac-event-listener`) and that the
  realm's admin-events config still lists it
  (`GET .../admin/realms/rossoctl/events/config`). A `helm upgrade` or Keycloak restart between
  Part 1 and here needs `./enable.sh --spi-only` re-run.
- **An inbound probe is denied when it should be allowed.** The generated inbound gate's
  `source_allow_ok` admits the `rossoctl` platform client. `driver.sh` logs users in through
  `ROPC_CLIENT_ID` (default `rossoctl`) for exactly that reason — `aiac-demo-cli`, which Part 6's
  `run-*.py` use, is not accepted as a source, so probing through it is denied on the `azp`.
- **An outbound probe returns the wrong verdict.** The OPA SDK's bundle poller can take up to ~120 s
  to pick up a fresh CR write. The driver's probes already retry within `POLL_SECS` (default 420);
  if you are probing by hand, wait and retry before concluding anything.
- **`make prereqs` hangs waiting on client registration.** Registration is asynchronous after the
  operator injects a workload; give it a couple of minutes, then check the operator's webhook logs.
- **`make agent`/`make tool` times out.** Onboarding drives the Policy Rules Builder's LLM calls and
  can genuinely take minutes; re-run with a larger `AIAC_ONBOARD_TIMEOUT` if your endpoint is slow.
- **`make setup`/`make dev` fails with a Keycloak profile error.** Keycloak 26's declarative user
  profile requires `email`/`firstName`/`lastName` before `grant_type=password` succeeds;
  `03-setup.py` sets these, so this points at a realm provisioned some other way.
- **A `run-*` target aborts with "no policy found".** Those drivers always read
  `generated/02-after-tool/`; run `make agent && make tool` first.
- **`kubectl` reports `connection refused`.** The Kind node was probably restarted and reassigned
  its API-server host port, leaving the kubeconfig stale: `kind export kubeconfig --name rossoctl`.
  `driver.sh` does this automatically in preflight.

## Known gaps

- **"Direct user → tool" is not enforced.** A fourth acceptance row — `dev-user` calling
  `github-tool` **directly**, bypassing the agent — should be denied, and is not.
  `github-tool` (`demo/assets/tools/github_tool/server.py`) is a bare FastMCP stub with no
  authentication of its own: no AuthBridge sidecar (deliberately — see
  [`demo/assets/INSTALL.md`](../../assets/INSTALL.md)'s "do not add sidecars to this tool"
  invariant) and no audience check in its own code. A direct in-cluster call to
  `github-tool.team1.svc.cluster.local:9090` succeeds unconditionally today. Enforcing it would need
  either an inbound AuthBridge+OPA leg on the tool or the tool doing its own audience check, both
  out of scope for this stub. The driver does not probe this row rather than report a fabricated
  result.
- **Part 6 does not sit in the request path.** Its verdicts come from `opa eval` against the
  generated Rego, mirroring how a gateway would query it. Parts 4–5 are the in-path proof.
- **Part 6's token exchange stops short of a call.** `run-*.py` performs a real RFC 8693 exchange to
  prove the flow, but does not feed the exchanged token into a live call against `github-tool`; the
  outbound verdict is read from the generated Rego, not an intercepted request.

---

## Appendix — installing AIAC by hand

What `./enable.sh` automates, from
[`k8s/aiac-deployment-guide.md`](../../../k8s/aiac-deployment-guide.md). Use this when `enable.sh`'s
assumptions don't hold — a non-Kind cluster, a remote registry, or an LLM key that isn't already in
`team1/openai-secret`. Run from the **repo root**.

| Manifest | Contents | Port(s) |
|---|---|---|
| `pdp-interface-deployment.yaml` | Interface Pod (IdP Configuration Service + PDP Policy Writer) + 2 ClusterIP Services | 7071, 7072 |
| `policy-model-store-statefulset.yaml` | Policy Model Store StatefulSet + 1 Gi PVC + headless + ClusterIP Service | 7074 |
| `event-broker-deployment.yaml` | NATS JetStream Event Broker + ClusterIP Service | 4222 |
| `agent-deployment.yaml` | Agent Pod (`aiac-init` init container + AIAC Agent) + ClusterIP Service | 7070 |

**1 — Build the images.** Note the differing build contexts.

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

The Event Broker uses stock `nats:2.14-alpine` — no build step.

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
the live ConfigMap after applying it. Both values are read at startup, so a change needs a restart.

```bash
kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
  -p '{"data":{"LLM_BASE_URL":"https://<your-endpoint>/v1","LLM_MODEL":"<model>"}}'
kubectl rollout restart deployment/aiac-agent -n aiac-system
```

**7 — Mount the scenario policy.** The Policy Rules Builder reads `policy.md` from the `aiac-policy`
ConfigMap. Generate it from this demo's own constant so the two cannot drift:

```bash
python3 -c 'import sys; sys.path.insert(0, "demo/use-cases/onboarding/lib"); import scenario; sys.stdout.write(scenario.POLICY_ABSTRACT)' > /tmp/policy.md
kubectl create configmap aiac-policy -n aiac-system --from-file=policy.md=/tmp/policy.md \
  --dry-run=client -o yaml | kubectl apply -f -
```

**8 — Install the Keycloak SPI listener.** This is the one part with no concise manual equivalent —
it builds a shaded jar, derives a Keycloak image from it, and enables the listener on the realm. See
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
