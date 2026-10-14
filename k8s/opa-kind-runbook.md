# OPA on Kind — AuthBridge pipeline and bundle service

This runbook wires OPA into the AuthBridge pipeline of a local Kind cluster and
deploys the `bundle-service` that distributes policy to it. It is
**platform setup**: it needs no agent, tool, user, or policy CR, and it is the
same whatever you run on the cluster afterwards.

The OPA plugin itself lives in the cortex repository (`core/plugins/opa/`, see
its `README.md`). Policy is distributed by `bundle-service` and authored as
`AuthorizationPolicy` CRs.

Three scripts in this directory:

| Script | What it does |
|---|---|
| [`opa-kind-enable.sh`](opa-kind-enable.sh) | Builds the operator image and deploys `bundle-service` from the operator clone. Applies the changed combiner of AIAC (D20) in place of the stock one: a pod that has no client CR is denied. Builds the AuthBridge proxy-sidecar image from the cortex clone. Loads both images into Kind. `helm upgrade`s the rossoctl chart with a temporary overlay that adds `opa` and the parser set to **both** pipeline legs, and with `injectTools=true`, so tools get the sidecar too. Restarts the agent and tool pods. Finishes by running verify. |
| [`opa-kind-restore.sh`](opa-kind-restore.sh) | Reverts the pipeline to the chart's shipped `values.yaml` (no overlay, no `injectTools=true`). Puts back the stock global combiner. Restarts the agent and tool pods. Leaves `bundle-service` in place. |
| [`opa-kind-verify.sh`](opa-kind-verify.sh) | Read-only. Runs every check in [Verify](#verify) and fails with a specific message at the first mismatch. Enable runs it as its last step; run it on its own to check an already-enabled cluster. |

**Workloads are not involved.** The pipeline lives in the
`authbridge-runtime-config` ConfigMap of the agent namespace. The operator
webhook copies it into each AuthBridge sidecar when a pod is created. So:

- a workload deployed **after** enable gets the OPA pipeline automatically;
- a workload already running is restarted by enable/restore so it picks up the
  change (a no-op when there is none).

**In an AIAC setup**, AIAC writes one client-scoped CR for each managed service,
agent and tool. The **enforcement side** selects where a tool call is checked.
Under **target side** (the default), the tool's own inbound OPA checks it, and
the outbound of every service is a pass-through. Under **agent side**, the
agent's outbound OPA checks it, and the tool gets a pass-through CR. See
[Set the enforcement side](#set-the-enforcement-side).

To see OPA **enforce** a real policy for real users, run a use case on top of
this setup. For example, the onboarding use case
([`demo/use-cases/onboarding/demo.md`](../demo/use-cases/onboarding/demo.md))
deploys its own workloads, users, outbound routes and policy. The onboarding use
case's system tests list their extra platform prerequisites (event broker,
Keycloak SPI) in
[`docs/testing/uc1-onboarding-pipeline.md`](../docs/testing/uc1-onboarding-pipeline.md#preconditions-the-wired-platform--not-stood-up-by-the-tests).
The example CR pair [`opa-team1-policy.yaml`](../docs/examples/opa-team1-policy.yaml)
shows what AIAC writes under target side for `github-agent` and `github-tool`.

## Architecture

```
Inbound:   caller ─► parsers ─► jwt-validation ─► opa ─► app
Outbound:  app ─► parsers ─► token-exchange ─► opa ─► destination
                                                │
                    bundle-service ◄────────────┘  (polls its bundle)
```

- The parsers (`a2a-parser`, `mcp-parser`, `inference-parser`) run first, so
  `input.a2a` / `input.mcp` / `input.inference` are populated whenever the body
  matches that protocol.
- Inbound, `opa` runs after `jwt-validation`, so `input.identity` comes from the
  validated JWT.
- Outbound, `opa` runs after `token-exchange`, so policies can read the
  delegation chain and a synthesized `input.identity`
  (see [What OPA sees](#what-opa-sees-on-each-leg)).
- Every sidecar polls its bundle from
  `http://bundle-service.rossoctl-system.svc.cluster.local:8080`.
- The pipeline is the same for an agent pod and a tool pod. Each AuthBridge
  sidecar runs one OPA instance for both directions. So a call from an agent to
  a tool crosses two OPA checks: the agent's outbound and the tool's inbound.
  The enforcement side selects which of the two has the rules; the other one is
  a pass-through.

---

## Prerequisites

- A Kind cluster named `rossoctl` with the rossoctl platform installed
  (operator, Keycloak, SPIRE). Nothing needs to be deployed in the agent
  namespace (`team1`).
- Three sibling repo clones:
  - `OPERATOR_DIR` → `rossoctl/operator` (default: `../operator`). Enable
    builds the operator image from `operator/Dockerfile` and renders the
    bundle-service manifests from `charts/operator/templates/bundleservice/`.
    The operator image carries `/manager`, `/bundle-service` and
    `/token-broker`; each Deployment selects its binary with `command:`. It
    needs a clone at or after operator commit `5e4c991`, which puts the bundle
    service in the operator image. Restore renders the stock global combiner
    from the same chart to put it back, and stops if the chart is missing.
  - `ROSSOCTL_DIR` → `rossoctl/rossoctl`, the Helm chart (default:
    `../rossoctl`).
  - `CORTEX_DIR` → `rossoctl/cortex` (default: `../cortex`). Enable builds the
    AuthBridge proxy-sidecar image from `cmd/cortex/Dockerfile`
    (`cmd/authbridge-proxy/Dockerfile` in a clone before cortex `a86e6708`),
    with the clone root as build context. Override `AUTHBRIDGE_DIR` if your Go
    module root is elsewhere. An untracked `authbridge/` directory left over in
    an older clone is stale and can be ignored. Restore does not need this
    clone.

  These paths are resolved against **your current directory**, not the script.
  Pass absolute paths unless you run from the repo root.
- `kubectl`, `helm`, `kind`, and `docker` (or `podman`) on `PATH`.
- If `kubectl` reports `connection refused`, the Kind node was probably
  restarted and got a new API-server host port. Re-export the kubeconfig:
  `kind export kubeconfig --name rossoctl`. The verify script does this for you
  in preflight.

All commands below are run from the repo root.

---

## Enable

```bash
OPERATOR_DIR=../operator ROSSOCTL_DIR=../rossoctl CORTEX_DIR=../cortex ./k8s/opa-kind-enable.sh
```

Expect two image builds, so allow a few minutes. The script runs six steps:

1. **Bundle service + the changed combiner (D20).** The rossoctl chart's
   operator subchart does not ship the bundle-service templates, so the script
   renders them from the local operator clone:
   - Builds the operator image (`OPERATOR_IMAGE`, default
     `localhost/operator:local`) and loads it into Kind.
   - Applies the `AuthorizationPolicy` CRD and waits for it to be
     `established`.
   - Deletes an existing `bundle-service` Deployment whose selector does not
     match `$RELEASE_NAME`, because a Deployment selector is immutable.
   - Renders `serviceaccount`, `rbac`, `service` and `deployment` with
     `helm template --show-only` and applies them, with
     `bundleService.enabled=true` and `imagePullPolicy: Never` so Kind runs the
     image it just loaded.
   - Does **not** apply the chart's stock global combiner
     (`default-policy.yaml`). In its place, it applies the changed combiner
     [`aiac-combiner-default.yaml`](aiac-combiner-default.yaml) as the `default`
     CR in `rossoctl-system`, and checks it. So the cluster never has the stock
     combiner, also on a re-run. See
     [The changed combiner (D20)](#the-changed-combiner-d20).

   It uses `helm template --show-only`, not a second `helm install`. The
   operator chart's manager and ClusterRole templates have no `enabled` flag, so
   a second release would start a duplicate controller-manager. It also skips
   `networkpolicy.yaml`: that policy admits only pods labelled
   `rossoctl.dev/authbridge=true`, which nothing sets today. Kind's default CNI
   does not enforce NetworkPolicy anyway.
2. **AuthBridge image.** Builds `localhost/authbridge:local` (`IMAGE_TAG`) and
   loads it into Kind. AuthBridge plugins are opt-in build tags. The build uses
   the cortex profile `AUTHBRIDGE_PROFILE` (default `full`, one of the profiles
   that includes `opa`), resolved by `scripts/profile-tags` with a local `go`, or
   in a `golang` container when `go` is missing. Set `GO_BUILD_TAGS` to bypass
   the profile.
3. **Overlay.** Writes a temporary values overlay under
   `authBridge.pipeline` with the pipeline shown in
   [Architecture](#architecture). Every injected pod in the namespace uses it,
   agent and tool. The inbound leg is `a2a-parser`, `mcp-parser`,
   `inference-parser`, `jwt-validation`, `opa`: a tool needs `mcp-parser` and
   `opa` there (onboarding check #2, D30). `charts/rossoctl/values.yaml` is
   never modified.
4. **Helm upgrade.** Applies the chart's `values.yaml` plus the overlay, with
   the sidecar image pointed at the locally built one.
   - It sets `operator-chart.featureGates.injectTools=true`. So the operator
     webhook also injects the AuthBridge sidecar into tool pods
     (`rossoctl.io/type=tool`). The default is `false`. Without it a tool pod
     gets no sidecar and no operator-registered Keycloak client, and the
     onboarding check #1 (D30) fails for the tool.
   - After the `helm upgrade`, it checks the combiner again. If the chart
     brought back the stock combiner, the script stops before the restart.
5. **Restart.** Deletes the pods labelled `rossoctl.io/type=agent` **and**
   `rossoctl.io/type=tool` in `AGENT_NAMESPACE` (default `team1`). The webhook
   injects the sidecar and the pipeline only at pod CREATE, so a pod that exists
   already keeps its old pipeline until it restarts. With no such pods, this
   does nothing.
6. **Verify.** Runs [`opa-kind-verify.sh`](opa-kind-verify.sh). The script
   exits non-zero if any check fails, so success means the wiring was checked,
   not just applied.

---

## Verify

Enable runs this for you. To check a cluster later (it changes nothing):

```bash
./k8s/opa-kind-verify.sh
```

It runs these checks. Each one can also be run by hand:

```bash
# 1. OPA is in both legs of the namespace pipeline — expect 2
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'

# 2. The CRD is served and the global combiner exists — expect 'default', scope global
kubectl get crd authorizationpolicies.agent.rossoctl.dev
kubectl get authorizationpolicy -n rossoctl-system
#    ... and it is the changed combiner (D20): expect 0 request and 2 response fallback rules
kubectl get authorizationpolicy default -n rossoctl-system \
  -o jsonpath='{.spec.policies[*].content}' \
  | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.request'
kubectl get authorizationpolicy default -n rossoctl-system \
  -o jsonpath='{.spec.policies[*].content}' \
  | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.response'

# 3. bundle-service is Running
kubectl get pods -n rossoctl-system -l app=bundle-service

# 4. bundle-service is ready and serves a bundle — expect 'readyz 200' then 'bundle 200'
kubectl run "opa-probe-$RANDOM" --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
  -n team1 -- sh -c '
    BS=http://bundle-service.rossoctl-system.svc.cluster.local:8080
    curl -s -o /dev/null -w "readyz %{http_code}\n" "$BS/readyz"
    curl -s -o /dev/null -w "bundle %{http_code}\n" "$BS/bundles?spiffe=localtest.me/ns/team1/sa/opa-probe"'
```

Check 4 runs from inside the agent namespace, so it also shows that sidecars
there can reach `bundle-service`. The `sa/opa-probe` identity is arbitrary: with
no client-scope CR for it, the service still builds a bundle from the global
(and any namespace) policy. A `503` means the service's informer has not synced
yet. Retry after a few seconds.

If agent or tool pods exist in the namespace, the verify script also checks that
each pod's `authbridge-proxy` container runs `IMAGE_TAG` and is Ready. With no
such pods, it skips this check.

---

## Direct Access Grants on the login client

A manual probe that mints a user token with the password grant through the
login client `rossoctl` needs Direct Access Grants on that client. In a fresh
realm it is off, and the mint fails with `unauthorized_client`. The system
tests do not need this step: their fixture enables the grant itself
(`ensure_direct_access_grants` in `test/system/uc1_onboard.py`). To enable it by
hand (a partial update: only this field changes):

```bash
KC=http://keycloak.localtest.me:8080
ADMIN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
CID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/clients?clientId=rossoctl" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
curl -s -o /dev/null -w "enable DAG HTTP %{http_code}\n" -X PUT \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  "$KC/admin/realms/rossoctl/clients/$CID" -d '{"directAccessGrantsEnabled": true}'
```

Expect `enable DAG HTTP 204`. The grant stays on; set the field to `false` the
same way to turn it off again.

---

## Restore

```bash
OPERATOR_DIR=../operator ROSSOCTL_DIR=../rossoctl ./k8s/opa-kind-restore.sh
```

This re-runs `helm upgrade` against the chart's own `values.yaml`, with no
overlay. It keeps the Kind-specific `--set` flags (`openshift=false`, the local
sidecar image), because the chart defaults assume OpenShift. It does not set
`injectTools=true`, so the restarted tool pods have no sidecar. Then:

- it puts back the stock global combiner: it renders `default-policy.yaml` from
  the operator chart (the one bundle-service template that enable skips) and
  applies it. With the stock combiner a pod that has no client CR is allowed
  again;
- it restarts the agent and tool pods.

Check 1 above should now print `0`, or whatever count the shipped `values.yaml`
carries. The request fallback rules of check 2 should now count `2`.

Restore does **not** remove `bundle-service`, the CRD, or the client
`AuthorizationPolicy` CRs. They do nothing without `opa` in the pipeline. The
AIAC Controller start check #4 (D30) fails with the stock combiner, so the
Controller does not start again until `opa-kind-enable.sh` runs again.

---

## Set the enforcement side

AIAC writes the CRs of one **enforcement side** for every managed service (D16).
The setting is `AIAC_ENFORCEMENT_SIDE` in the `aiac-agent-config` ConfigMap
(`aiac-system`): `target-side` (the default) or `agent-side` (D29). The
Controller reads it at start. An unknown value stops the Controller.

| Side | agent CR (`github-agent`) | tool CR (`github-tool`) | Who checks a tool call |
|------|---------------------------|-------------------------|------------------------|
| `target-side` | agent inbound + pass-through outbound | tool inbound (the per-tool check) + pass-through outbound | the tool's inbound OPA |
| `agent-side` | agent inbound + agent outbound (the per-tool check) | pass-through inbound + pass-through outbound | the agent's outbound OPA |

The packages are described in
[`pdp-policy-writer-opa.md` → What each side renders](../docs/specs/components/pdp-policy-writer-opa.md#what-each-side-renders).

**The side is set at deploy time. A live switch is not supported.** Do not
patch the side on a running AIAC and restart the Controller. To change the
side, do a clean redeploy of AIAC. A clean redeploy deletes the Policy Model
Store and every AIAC CR, so no CR or stored SPM of the old side stays. After it,
no service is managed: onboard each service again.

> **Do not change the side by hand-editing the CRs.** A partial change is open.
> For example, a pass-through outbound on `github-agent` and a pass-through
> inbound on `github-tool` check nothing.

The clean redeploy (Kind; `enable.sh` automates
[`aiac-deployment-guide.md`](aiac-deployment-guide.md)).

Precondition: the LLM key Secret `team1/openai-secret` (data key `apikey`)
exists. `enable.sh` reads it, and stops if it is missing. The teardown does not
delete it. To make it:
`kubectl create secret generic openai-secret -n team1 --from-literal=apikey="$LLM_API_KEY"`
(see [`demo.md` → Two secrets to create first](../demo/use-cases/onboarding/demo.md#two-secrets-to-create-first)).

```bash
SIDE=agent-side    # or target-side

# 1. Delete every AIAC CR. The combiner (D20) then denies each managed pod
#    until it is onboarded again.
kubectl delete authorizationpolicy -A -l app.kubernetes.io/managed-by=aiac-pdp-policy-writer

# 2. Delete AIAC: the aiac-system namespace, with the Policy Model Store PVC
#    and the keycloak-admin-secret.
demo/use-cases/onboarding/teardown.sh --aiac-only --yes

# 3. Make the namespace and the Keycloak admin Secret again. `enable.sh` does
#    not make the Secret, and without it aiac-interface stays in
#    ContainerCreating.
set -a; . .env; set +a
kubectl create namespace aiac-system
kubectl create secret generic keycloak-admin-secret -n aiac-system \
  --from-literal=KEYCLOAK_ADMIN_USERNAME="$KEYCLOAK_ADMIN_USERNAME" \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD"

# 4. Deploy AIAC again: the stack, then the broker. The Controller init
#    container waits for the broker.
demo/use-cases/onboarding/enable.sh --stack-only
demo/use-cases/onboarding/enable.sh --broker-only

# 5. Set the side. `k8s/agent-deployment.yaml` sets `target-side`, so set the
#    side after step 4. The store is empty, so the Controller start writes no CR.
kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
  -p "{\"data\":{\"AIAC_ENFORCEMENT_SIDE\":\"${SIDE}\"}}"
kubectl rollout restart deployment/aiac-agent -n aiac-system
kubectl rollout status deployment/aiac-agent -n aiac-system --timeout=300s
```

At start, the Controller checks the combiner (check #4, D30). Under agent side,
the onboarding checks (D30) run for agents only, and check #2 also needs
`mcp-parser` and `opa` in the outbound pipeline. The overlay of
[Enable](#enable) has them.

Then onboard each service again. A service whose Keycloak client exists gets no
new registration event, so start its onboarding by hand
(`POST /apply/service/{uuid}` on the AIAC Agent), or deploy it again. The system
tests onboard their own services, so they need no extra step.

Check the result:

```bash
# the live side
kubectl get configmap aiac-agent-config -n aiac-system \
  -o jsonpath='{.data.AIAC_ENFORCEMENT_SIDE}'

# every AIAC CR (one per managed service)
kubectl get authorizationpolicy -A -l app.kubernetes.io/managed-by=aiac-pdp-policy-writer

# github-tool's inbound package: `allow := true` under agent side;
# the per-tool check (tool_ok) under target side
kubectl get authorizationpolicy github-tool -n team1 \
  -o jsonpath='{.spec.policies[?(@.path=="inbound/request.rego")].content}'
```

---

## Reference — how OPA behaves once wired

### Policy tiers and targeting

`bundle-service` builds each sidecar's bundle from up to three tiers of
`AuthorizationPolicy` CRs:

- **global** (`spec.scope: global`, in `rossoctl-system`): the `default` CR. It
  defines how the other tiers combine. Enable applies the changed combiner
  (D20) as this CR, see [below](#the-changed-combiner-d20).
- **namespace**: applies to every workload in a namespace.
- **client** (`spec.scope: client`): applies to one workload. It is looked up
  by **`metadata.name` + `metadata.namespace`**, matched against the
  ServiceAccount segment of the sidecar's SPIFFE ID
  (`spiffe://<trust-domain>/ns/<namespace>/sa/<name>`). `spec.clientID` is not
  used by the lookup. It is a display field and must be a DNS label (no
  `spiffe://`, no `/`).

A workload's SPIFFE ID is in its sidecar:

```bash
kubectl exec -n <ns> deploy/<workload> -c authbridge-proxy -- cat /shared/client-id.txt
```

After a CR changes, `bundle-service` rebuilds the bundle right away, but each
sidecar polls on its own schedule (10–120 s backoff). Allow up to about two
minutes before you expect a new decision.

### The changed combiner (D20)

The bundle service adds a global combiner to every bundle: the `default` CR
(`scope: global`) in `rossoctl-system`. The stock combiner from the operator
chart (`charts/operator/templates/bundleservice/default-policy.yaml`) has the
rule `client_ok if not <client package>` in each of its four packages. With it,
a pod that has no client CR is **allowed**.

In an AIAC setup, the two request packages do not have this rule:

- `client_ok if not data.authbridge.client.inbound.request` is removed from
  `authbridge.inbound.request`;
- `client_ok if not data.authbridge.client.outbound.request` is removed from
  `authbridge.outbound.request`.

So a pod that has no client CR is **denied** on both request legs. The two
response packages keep the stock rule. A deleted CR is then lockdown, not
off-boarding. That is why every managed service has a CR (a pass-through where
AIAC has no rules), and why the AIAC quarantine and decommission delete the CR.

The operator chart has no value for this yet. The upstream value is
`bundleService.defaultPolicy.requireClientPolicy` (opt-in, default `false`).
Until it exists, `opa-kind-enable.sh` applies the changed `default` CR in its
Step 1, in place of the stock one. A later install or upgrade of the operator
chart's bundle service (without the value) brings back the stock combiner. The
AIAC Controller checks the combiner at every start (check #4, D30), and it stops
if the combiner still allows a pod that has no client CR. The Controller check
is an allowlist: each `client_ok` rule of the two request packages must be
`client_ok if data.authbridge.client.<direction>.request.allow` or
`default client_ok := false`. Check 2 of [Verify](#verify) is a manual check:
it finds only the stock fallback rule.

### What OPA sees on each leg

The OPA plugin turns on console decision logs (`decision_logs.console: true`),
so the sidecar logs every decision, including its `input` and `result`:

```bash
kubectl logs -n <ns> <pod> -c authbridge-proxy --tail=500 \
  | grep 'path=authbridge/inbound/request' | tail -1     # or .../outbound/request
```

**Inbound** — `identity` comes from the validated inbound JWT:

```json
{
  "direction": "inbound",
  "method": "POST",
  "path": "/",
  "host": "<workload>.<ns>.svc.cluster.local:8080",
  "headers": { "content-type": "application/json", "...": "..." },
  "identity": {
    "subject": "<JWT sub>",
    "client_id": "<client the token was issued to>",
    "scopes": ["openid", "..."]
  }
}
```

- `subject` is the JWT `sub` claim. In an AIAC setup it is the username on
  every leg (D31): the client scope `aiac-username-sub` (the `username → sub`
  mapping) is the one source of it. AIAC links that scope as a default scope to
  each platform login client (`PLATFORM_SOURCE_CLIENTS`, default `rossoctl`) and
  to each client that it onboards. Do not add a `sub` mapper by hand.
- `client_id` is the client the token was issued to. On a tool's inbound leg
  the JWT is the exchanged token, so `client_id` is the calling agent's client
  (its SPIFFE ID). The tool inbound package of target side keys its
  calling-agent gate on it.
- Credential headers (`authorization`, `cookie`, …) are **redacted** from
  `headers`. Use `identity` for auth decisions.

**Outbound** — there is no validated JWT on this leg. When `token-exchange`
mints the downstream token, it records a delegation hop, and OPA builds
`input.identity` **in the same shape as inbound**:

```json
{
  "direction": "outbound",
  "method": "POST",
  "path": "/",
  "host": "<destination>:<port>",
  "identity": {
    "subject": "<delegating user>",
    "client_id": "spiffe://<td>/ns/<ns>/sa/<calling workload>",
    "scopes": ["openid", "<exchanged scopes>"],
    "service_id": "spiffe://<td>/ns/<ns>/sa/<destination>"
  },
  "delegation": {
    "origin": "<delegating user>",
    "actor": "<delegating user>",
    "depth": 1,
    "chain": [
      {
        "subject_id": "<delegating user>",
        "audience": "spiffe://<td>/ns/<ns>/sa/<destination>",
        "scopes": ["openid", "<exchanged scopes>"],
        "strategy": "token-exchange",
        "from_cache": false,
        "timestamp": "..."
      }
    ]
  },
  "mcp": { "method": "tools/call", "params": { "name": "<tool>" } }
}
```

- `subject` is the delegated caller, decoded on a best-effort basis from the
  incoming bearer's `sub`.
- `client_id` is the **calling workload's own client**
  (`/shared/client-id.txt`), the party doing the exchange, not the target.
- `scopes` are the scopes the downstream token was minted with (the last hop).
- `service_id` is the exchange target (the last hop's `audience`). It is the
  outbound counterpart of the inbound token audience. The agent-side outbound
  package keys on it; the target-side pass-through does not read it.
- `token-exchange` only runs for hosts that have a route in the namespace's
  `authproxy-routes` ConfigMap. Routes are read once at sidecar startup.
  Traffic to a host with no route is passed through with **no** `identity` and
  no `delegation`, so a policy keyed on them falls to its default.
- Parser sections (`mcp` / `a2a` / `inference`) appear **only** when the body
  matches that protocol.

### Reading a decision

| What the caller sees | Meaning |
|---|---|
| HTTP `403`, body `{"error":"policy.forbidden","plugin":"opa",...}` | OPA denied a plain HTTP or A2A request, or an inbound OPA denied an MCP request. Under target side, a tool call that the tool's inbound OPA denies comes back this way: the tool's reverse proxy sends the `403`, and the agent's forward proxy relays it. |
| HTTP `200`, JSON-RPC `error` frame with `error.code: -32000`, `error.data.plugin: "opa"` | An **outbound** OPA denied an **MCP** request (one with a `method` and an `id`). Under agent side, this is a tool call that the agent's outbound OPA denies. The forward proxy returns the deny as a JSON-RPC error, so the MCP client sees one failed call instead of a broken transport (`writeMCPRejection` in cortex `core/listener/httpx/render.go`). The request never reaches the destination. |
| HTTP `200`, JSON-RPC `result` frame | Allowed. |
| HTTP `503` (outbound) | `token-exchange` failed. OPA was never consulted. |

For MCP traffic, classify by the response **body**, not the status code: a
`result` frame is allowed; an `error` frame or a `403` body that names `opa` is
denied. A JSON-RPC *notification* (no `id`) gets a plain HTTP `403` on a deny.

Two pitfalls when probing by hand:

- `jwt-validation` bypasses `/.well-known/*`, `/healthz`, `/readyz`, `/livez`
  and `/metrics`. Requests to those carry **no identity** to OPA. Under the
  changed combiner (D20) a pod with no client CR denies them, and a rules-based
  inbound package denies a request with no identity (D27). So they never show
  the effect of a user's roles.
- A real task (for example A2A `message/send`) runs the workload's own logic
  and can be slow. A JSON-RPC method the app does not implement (for example
  `ping/nonexistent`) reaches OPA and returns at once: `200` with a `-32601`
  body when allowed, `403` when denied.
