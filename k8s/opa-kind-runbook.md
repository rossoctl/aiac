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
agent and tool. The tool's own inbound OPA checks each tool call, and the
outbound of every service is a pass-through (D24). See
[The AIAC CRs](#the-aiac-crs).

To see OPA **enforce** a real policy for real users, run a use case on top of
this setup. For example, the onboarding use case
([`demo/use-cases/onboarding/demo.md`](../demo/use-cases/onboarding/demo.md))
deploys its own workloads, users, Keycloak grants and policy. The onboarding use
case's system tests list their extra platform prerequisites (event broker,
Keycloak SPI) in
[`docs/testing/uc1-onboarding-pipeline.md`](../docs/testing/uc1-onboarding-pipeline.md#preconditions-the-wired-platform--not-stood-up-by-the-tests).
The example CR pair [`opa-team1-policy.yaml`](../docs/examples/opa-team1-policy.yaml)
shows what AIAC writes for `github-agent` and `github-tool`.

## Architecture

```
Inbound:   caller ─► parsers ─► jwt-validation ─► opa ─► app
Outbound:  app ─► parsers ─► discovery-exchange ─► opa ─► destination
                                                    │
                    bundle-service ◄────────────────┘  (polls its bundle)
```

- The parsers (`a2a-parser`, `mcp-parser`, `inference-parser`) run first, so
  `input.a2a` / `input.mcp` / `input.inference` are populated whenever the body
  matches that protocol.
- Inbound, `opa` runs after `jwt-validation`, so `input.identity` comes from the
  validated JWT.
- Outbound, token exchange is **on by default**. `discovery-exchange` needs no
  routes: it derives the target audience from the destination host and lets
  Keycloak decide whether the destination is a target
  (see [Outbound token exchange](#outbound-token-exchange)).
- Outbound, `opa` runs after `discovery-exchange`, so policies can read the
  delegation chain and a synthesized `input.identity`
  (see [What OPA sees](#what-opa-sees-on-each-leg)).
- Every sidecar polls its bundle from
  `http://bundle-service.rossoctl-system.svc.cluster.local:8080`.
- The pipeline is the same for an agent pod and a tool pod. Each AuthBridge
  sidecar runs one OPA instance for both directions. So a call from an agent to
  a tool crosses two OPA checks: the agent's outbound and the tool's inbound.
  The agent's outbound package is a pass-through (D24), and the tool's inbound
  package decides the call.

### The AIAC CRs

In an AIAC setup, AIAC writes one client CR for each managed service. Each CR
has the two request packages:

| CR | Inbound package | Outbound package |
|----|-----------------|------------------|
| agent (`github-agent`) | the agent-level check (D26a) | pass-through (D24) |
| tool (`github-tool`) | the per-tool check (D26) | pass-through (D24) |

So the tool's inbound OPA decides each tool call. The packages are described in
[`pdp-policy-writer-opa.md` → Rego package structure](../docs/specs/components/pdp-policy-writer-opa.md#rego-package-structure).

To see the CRs on a cluster:

```bash
# every AIAC CR (one per managed service)
kubectl get authorizationpolicy -A -l app.kubernetes.io/managed-by=aiac-pdp-policy-writer

# github-tool's inbound package: the per-tool check (tool_ok)
kubectl get authorizationpolicy github-tool -n team1 \
  -o jsonpath='{.spec.policies[?(@.path=="inbound/request.rego")].content}'
```

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
    The checkout must contain the `discovery-exchange` plugin
    (`core/plugins/discoveryexchange/`, including its delegation-hop
    recording). Until it is merged to `main`, check out the
    `feat/discovery-exchange` branch. An older checkout fails at sidecar start
    with an unknown-plugin error.

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
   `inference-parser`, `jwt-validation`, `opa`: every service needs
   `jwt-validation` and `opa` there, and a tool also needs `mcp-parser`
   (onboarding check #2, D30). Each of them must keep the default
   `on_error: enforce`. Check #2 does not check the outbound leg. The overlay
   keeps `opa` there for the pass-through outbound package (D24) and the
   changed combiner (D20). `charts/rossoctl/values.yaml` is never modified.
   The outbound `discovery-exchange` entry is configured with
   `audience_template: spiffe://$TRUST_DOMAIN/ns/{namespace}/sa/{service}`
   (`TRUST_DOMAIN`, default `localtest.me`), `namespace: $AGENT_NAMESPACE` for
   short host names, and `no_token_policy: client-credentials`.
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
# 1b. Outbound exchange is discovery-exchange — expect 1, then 0
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: discovery-exchange'
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: token-exchange'

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
tests do not need this step: their fixture enables the grant itself, once per
session (`hold_direct_access_grants` in `test/system/uc1_onboard.py`), and
turns it off again at session end if it turned it on and no other run still
holds it. The client attribute `aiac.test.direct-access-grants-by-harness`
records which harness runs hold the grant, each with an expiry
(`AIAC_DAG_HOLD_TTL_SECONDS`, default 6 h). So two runs at the same time do not
turn the grant off under each other, and a later run undoes a run that was
killed.

To enable it by hand, source the repo-root `.env` first. The snippet uses the
same variables as the harness. It is a partial update: only the grant changes,
and it removes the harness marker. So a system run that is in progress, or a
later one, does not turn your grant off:

```bash
( set -e  # a subshell: a failed check stops the snippet, not your shell
set -a; . .env; set +a
KC=${KEYCLOAK_URL:?}; REALM=${AIAC_TEST_REALM:-rossoctl}; ADMIN_REALM=${KEYCLOAK_ADMIN_REALM:-master}
# Print the value at a key path (for example "0 id") of an admin API response; when the response has
# another shape, print "" and show the raw response on stderr.
pick() { python3 -c 'import sys,json
raw=sys.stdin.read()
try:
    v=json.loads(raw)
    for k in sys.argv[1:]: v=v[int(k)] if k.isdigit() else v[k]
except Exception:
    v=""
print(v or "")
v or print("unexpected admin API response:", raw[:300], file=sys.stderr)' "$@"; }
ADMIN=$(curl -s -X POST "$KC/realms/$ADMIN_REALM/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  --data-urlencode "username=${KEYCLOAK_ADMIN_USERNAME:?}" \
  --data-urlencode "password=${KEYCLOAK_ADMIN_PASSWORD:?}" | pick access_token)
[ -n "$ADMIN" ] || { echo "admin login at realm $ADMIN_REALM failed: check KEYCLOAK_ADMIN_*"; exit 1; }
CID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/$REALM/clients?clientId=rossoctl" \
  | pick 0 id)
[ -n "$CID" ] || { echo "login client rossoctl not found in realm $REALM (or the admin cannot view clients)"; exit 1; }
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  "$KC/admin/realms/$REALM/clients/$CID" \
  -d '{"directAccessGrantsEnabled": true, "attributes": {"aiac.test.direct-access-grants-by-harness": ""}}')
[ "$CODE" = 204 ] || { echo "enable DAG failed: HTTP $CODE"; exit 1; }
echo "enable DAG HTTP 204"
)
```

Expect `enable DAG HTTP 204`. The grant stays on; set the field
to `false` the same way to turn it off again.

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
off-boarding. That is why every managed service has a CR, and why the AIAC quarantine and decommission delete the CR.

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
  (its SPIFFE ID). The tool inbound package keys its calling-agent gate
  on it.
- Credential headers (`authorization`, `cookie`, …) are **redacted** from
  `headers`. Use `identity` for auth decisions.

**Outbound** — there is no validated JWT on this leg. When `discovery-exchange`
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
        "strategy": "discovery-exchange",
        "from_cache": false,
        "timestamp": "..."
      }
    ]
  },
  "mcp": { "method": "tools/call", "params": { "name": "<tool>" } }
}
```

- `subject` is the `sub` of the token Keycloak issued: the delegating user, or
  the calling workload's service account when the request carried no bearer
  (`no_token_policy: client-credentials`). The workload cannot choose it,
  because it comes from the IdP's answer and not from the caller's bearer.
- `client_id` is the **calling workload's own client**
  (`/shared/client-id.txt`), the party doing the exchange, not the target.
- `scopes` is the issued token's `scope` claim. With default-scope grants
  Keycloak lists **all** of the caller's scope names there, even though `aud`
  names one target. So don't treat `scopes` as per-target.
- `service_id` is the exchange target (the last hop's `audience`, the derived
  `spiffe://…/sa/<service>`). It is the outbound counterpart of the inbound
  token audience. No AIAC package reads it: the outbound package is a
  pass-through (D24).
- Only an **exchanged** request (`token_exchanged` or `cache_hit`) carries
  `identity` and `delegation`. A destination that is passed through (out of
  cluster, or no Keycloak client) has neither, so a policy keyed on them falls
  to its default (deny, for AIAC's generated policy).
- Parser sections (`mcp` / `a2a` / `inference`) appear **only** when the body
  matches that protocol.

### Outbound token exchange

`discovery-exchange` runs on every outbound request and has no routes and no
`authproxy-routes` ConfigMap. Adding a target is a Keycloak change only, with no
restart. Exchange is the default; passthrough happens in exactly two cases:

| Destination | Result | Session event |
|---|---|---|
| Outside the cluster (external host, IP literal, `svc.namespace` without `.svc`) | forwarded unchanged, Keycloak not asked | `skip / host_not_in_cluster` |
| In-cluster, audience granted to the caller | `Authorization` replaced with a token narrowed to that audience | `modify / token_exchanged` (or `cache_hit`) |
| In-cluster, Keycloak has **no client** for the derived audience | forwarded unchanged; remembered for 5 min | `skip / audience_unknown` |
| In-cluster, client exists but is **not granted** to the caller | **403**, OPA not consulted | `deny / audience_not_granted` |
| Keycloak down, timeout, bad credentials, any other error | **503**, OPA not consulted | `deny / exchange_failed` |
| Sidecar credentials not yet in `/shared/` | **503** (pod held not-ready) | `deny / credentials_not_ready` |

A request with **no** bearer is still exchanged, using the workload's own
`client_credentials` token as the subject (`no_token_policy:
client-credentials`). It is never sent un-narrowed.

The audience is derived from the Host header as
`spiffe://<TRUST_DOMAIN>/ns/<namespace>/sa/<service>`. The namespace comes from
the host (`github-tool.team1.svc[.cluster.local]`), or from `AGENT_NAMESPACE`
for a short name (`github-tool:9090`). This makes two demands on workloads and
Keycloak, which a use case (not this runbook) sets up:

1. **Service name = ServiceAccount name.** The Host header carries the Service
   name. If it differs from the ServiceAccount, the derived audience names no
   client and the request **passes through un-exchanged**. For example, the
   demo agent's default `MCP_URL` host is `github-tool-mcp`, but the client is
   `…/sa/github-tool`.
2. **Keycloak grants**, on the caller's client:
   - standard token exchange enabled (`standard.token.exchange.enabled=true`);
   - each target granted through a client scope with an audience mapper for
     it, attached as a **default** scope. The plugin requests no `scope`, so an
     *optional* scope is never applied and the target answers 403. A **realm**
     default scope would grant every target to every caller.

`AGENT_NAMESPACE` is baked into the pipeline at enable time. The chart renders
one pipeline for every agent namespace, and the sidecar has no
`POD_NAMESPACE` env to expand. A workload in another agent namespace must
therefore call its targets by `service.namespace.svc` name. Otherwise its short
names derive the wrong namespace and pass through.

The full plugin reference is cortex `docs/discovery-exchange-plugin.md`.

### Reading a decision

| What the caller sees | Meaning |
|---|---|
| HTTP `403`, body `{"error":"policy.forbidden","plugin":"opa",...}` | OPA denied a plain HTTP or A2A request, or an inbound OPA denied an MCP request. A tool call that the tool's inbound OPA denies comes back this way: the tool's reverse proxy sends the `403`, and the agent's forward proxy relays it. |
| HTTP `200`, JSON-RPC `error` frame with `error.code: -32000`, `error.data.plugin: "opa"` | An **outbound** OPA denied an **MCP** request (one with a `method` and an `id`). In an AIAC setup, the outbound package of a managed service is a pass-through (D24), so this is a call from a pod that has no client CR (D20). The forward proxy returns the deny as a JSON-RPC error, so the MCP client sees one failed call instead of a broken transport (`writeMCPRejection` in cortex `core/listener/httpx/render.go`). The request never reaches the destination. |
| HTTP `200`, JSON-RPC `result` frame | Allowed. |
| HTTP `403` (outbound), or an MCP error frame, with `plugin: "discovery-exchange"` | Keycloak has a client for the destination, but it is not granted to the caller as a default scope (`audience_not_granted`). OPA was never consulted. |
| HTTP `503` (outbound), `error: "upstream.token-exchange-failed"` | `discovery-exchange` could not get a token (Keycloak error, timeout, credentials not loaded). OPA was never consulted. |
| Allowed or denied by OPA as if no exchange ran, with no `identity` in the decision log | The destination passed through (`audience_unknown` / `host_not_in_cluster`). Check the Service/ServiceAccount naming and the Keycloak client. |

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
