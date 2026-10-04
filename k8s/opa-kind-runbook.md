# OPA Kind Cluster Runbook — AIAC github-agent (inbound + outbound)

> **Pre-release:** This document shows how OPA can be experimented with prior
> to its release as part of the Rossoctl system. On release, this document
> should be updated accordingly.

The OPA plugin itself lives in the separate cortex repository
(`core/plugins/opa/`, see its `README.md`).
The underlying mechanism — OPA as an AuthBridge pipeline plugin, policy
distributed via `bundle-service`, enforcement via the `AuthorizationPolicy`
CRD — is identical. This document gives the **exact, copy-paste** steps to run
the AIAC scenario end-to-end on a local Kind cluster, using the two helper
scripts that wire OPA in and out:

- [`opa-kind-enable.sh`](opa-kind-enable.sh) — builds the
  operator image from the operator clone and deploys the bundle service from
  the operator chart, builds the `authbridge-proxy` image from the cortex clone,
  loads both images into Kind, and wires the `opa` plugin (plus the parser set)
  into **both** the inbound and outbound pipeline of every `team1` agent and
  tool. It also applies the changed combiner (D20): a pod that has no client CR
  is denied.
- [`opa-kind-restore.sh`](opa-kind-restore.sh) — reverts
  the pipeline to its shipped state (no OPA overlay), puts back the stock global
  combiner, and restarts the agent and tool pods. The restore does not set
  `injectTools=true`, so the restarted tool pods have no sidecar.

The scenario itself uses one agent (`github-agent` in namespace `team1`) and
its downstream tool (`github-tool`):

- **`dev-user` is the allowed user, `alice` is the blocked user.** `dev-user`
  is the canonical scenario username from
  [`docs/testing/policy-pipeline.md`](../docs/testing/policy-pipeline.md).
- **Inbound** authorization of `github-agent` is enforced by its
  **client-scoped** `AuthorizationPolicy`, which targets `github-agent` alone.
- **Outbound** shows the token-exchange → OPA leg: the agent's call to
  `github-tool` is exchanged for a `github-tool`-audience token, and OPA sees a
  delegation chain plus a synthesized `input.identity`.
- **In an AIAC setup**, AIAC writes one client-scoped CR for each managed
  service, agent and tool. The **enforcement side** selects where a tool call
  is checked. Under **target side** (the default), `github-tool`'s own inbound
  OPA checks it, and the outbound of every service is a pass-through. Under
  **agent side**, `github-agent`'s outbound OPA checks it, and `github-tool`
  gets a pass-through CR. See [Part C](#part-c--switch-the-enforcement-side).
  Parts A and B apply the example CRs by hand
  ([`opa-team1-policy.yaml`](../docs/examples/opa-team1-policy.yaml)). The
  example is the **target-side** CR pair: one CR for `github-agent` (the agent
  inbound + a pass-through outbound) and one CR for `github-tool` (the tool
  inbound + a pass-through outbound).

## Architecture

```
Inbound:   caller ─► jwt-validation ─► OPA ─► github-agent app
Outbound:  github-agent app ─► token-exchange ─► OPA ─► github-tool
Tool:      github-agent (outbound) ─► jwt-validation ─► OPA ─► github-tool app
```

Each AuthBridge sidecar runs one OPA instance for both directions. A call from
`github-agent` to `github-tool` crosses two OPA checks: the agent's outbound and
the tool's inbound. The enforcement side selects which of the two has the rules;
the other one is a pass-through.

Policies are distributed via the bundle service used by every AuthBridge
workload: `http://bundle-service.rossoctl-system.svc.cluster.local:8080`.
On the outbound leg OPA is placed **after** `token-exchange` so policies can
read the delegation chain (see [Part B](#part-b--outbound-token-exchange--opa)).

---

## Prerequisites

- A Kind cluster named `rossoctl` with the `rossoctl` platform installed and
  `github-agent` + `github-tool` deployed in namespace `team1`.
- The three sibling repo clones the enable/restore scripts need:
  - `OPERATOR_DIR` → `rossoctl/operator` clone (default: `../operator`). The
    enable script builds the operator image from `operator/Dockerfile` and
    renders the bundle-service templates from `charts/operator`. It needs a
    clone at or after operator commit `5e4c991`, which puts the bundle service
    in the operator image. The restore script renders the stock global combiner
    from the same chart to put it back, and stops if the chart is missing.
  - `ROSSOCTL_DIR` → `rossoctl/rossoctl` clone, i.e. the Helm chart
    (default: `../rossoctl`)
  - `CORTEX_DIR` → `rossoctl/cortex` clone (default: `../cortex`). The enable
    script builds the `authbridge-proxy` image from
    `cmd/authbridge-proxy/Dockerfile` at the cortex repo root. This clone is
    required: the enable script stops if it is missing. The restore script does
    not need it.
- `kubectl`, `helm`, `kind`, and `docker` (or `podman`) on `PATH`.
  - If `kubectl` reports `connection refused` reaching the API server, the Kind
    node was likely restarted and reassigned its API-server host port, leaving
    the exported kubeconfig stale. Re-export it:
    `kind export kubeconfig --name rossoctl`. (The
    [`opa-kind-driver.sh`](opa-kind-driver.sh) driver does
    this automatically in preflight.)
- The `rossoctl` Keycloak realm has `dev-user` and `alice` users with
  **password == username**, and the `rossoctl` client has Direct Access Grants
  enabled plus a `username → sub` protocol mapper. This is a one-time Keycloak
  change, not per-agent — but a freshly (re)provisioned realm may not have it,
  in which case token minting fails with `unauthorized_client` (grants disabled),
  `invalid_grant` (wrong/unset password), or a token whose `sub` is absent
  (mapper missing). To establish it:

  ```bash
  KC=http://keycloak.localtest.me:8080
  ADMIN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

  # 1. rossoctl client: enable Direct Access Grants + add username->sub mapper
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

  # 2. set each user's password == username (non-temporary)
  for u in dev-user alice; do
    UID_=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/users?username=$u&exact=true" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
    curl -s -o /dev/null -w "reset $u HTTP %{http_code}\n" -X PUT -H "Authorization: Bearer $ADMIN" \
      -H "Content-Type: application/json" \
      "$KC/admin/realms/rossoctl/users/$UID_/reset-password" \
      -d "{\"type\":\"password\",\"value\":\"$u\",\"temporary\":false}"
  done
  ```

  Verify with A.1 below — a good token decodes to `sub = dev-user`.

### Event-driven onboarding path (required by the UC-1 system suite)

The manual probes in Parts A/B assume `github-agent` + `github-tool` are already deployed. The UC-1
onboarding **system tests** (`test/system/`, `-m system`) instead drive onboarding through the
**event-driven** path and deploy/undeploy the workloads themselves — deploying a workload is the
trigger (deploy → the rossoctl operator registers a Keycloak client → Keycloak emits
`CLIENT_CREATED` → the AIAC SPI `aiac-event-listener` publishes on NATS → the agent's consumer runs
`onboard_service`). That path needs three additional one-time platform facts, on top of the OPA
wiring above:

- **NATS event broker** running in `aiac-system` — deploy
  [`event-broker-deployment.yaml`](event-broker-deployment.yaml) (pod labelled
  `app=aiac-event-broker`, phase `Running`).
- **Keycloak SPI installed + the realm listener enabled**: `aiac-event-listener` present in the
  realm's `eventsListeners`, and `adminEventsEnabled: true` (`CLIENT_CREATED` is an *admin* event).
  See [`keycloak-spi/README.md`](../keycloak-spi/README.md).
- **Both demo images built + `kind load`ed** — `localhost/github-tool:latest` and
  `localhost/github-agent:latest`, produced by [`demo/assets/kind-load.sh`](../demo/assets/kind-load.sh).
  The suite deploys the manifests itself (it does **not** call `deploy.sh`), so the images must
  already be in the Kind node.

Failure modes are deliberately asymmetric, so the suite never false-passes:

- **Broker or SPI listener absent → the suite skips cleanly** (`require_event_path` detects it and
  `pytest.skip`s). The harness never stands the broker/SPI up — that is one-time platform setup.
- **Images absent → the suite fails loudly.** There is no cheap pre-check; the fixture `kubectl
  apply`s and waits, so a missing image makes the pod never go Ready (`ImagePullBackOff`) and the
  deploy/registration wait times out into a hard failure — never a skip, never a pass.

All commands below are run from the repo root.

---

## Step 1 — Enable OPA in both legs

```bash
OPERATOR_DIR=../operator ROSSOCTL_DIR=../rossoctl CORTEX_DIR=../cortex ./k8s/opa-kind-enable.sh
```

The script does these 4 steps:

1. **Bundle service + the changed combiner (D20).** No released operator chart
   carries the bundle service yet, so the script deploys it from the operator
   clone:
   - It builds the operator image from `$OPERATOR_DIR/operator/Dockerfile`
     (`OPERATOR_IMAGE`, default `localhost/rossoctl-operator:<operator HEAD short sha>`)
     and loads it into Kind. The bundle service runs from this image.
   - It applies the `AuthorizationPolicy` CRD from the operator clone.
   - It deletes a legacy `bundle-service` Deployment whose selector is only
     `app: bundle-service` (from the removed `operator/hack/bundle-service-kind.sh`).
     The chart selector adds `app.kubernetes.io` labels, and a Deployment
     selector is immutable.
   - It renders and applies only the bundle-service templates from
     `$OPERATOR_DIR/charts/operator` (`bundleService.enabled=true`, the local
     image, `pullPolicy: Never`). The rest of the operator stays as installed.
   - It does **not** apply the chart's bundle-service NetworkPolicy. That policy
     admits only pods labelled `rossoctl.dev/authbridge=true`, and nothing sets
     that label today. On a CNI that enforces NetworkPolicy it would block every
     AuthBridge bundle fetch.
   - It does **not** apply the chart's stock global combiner
     (`default-policy.yaml`). In its place, it applies the changed combiner
     [`aiac-combiner-default.yaml`](aiac-combiner-default.yaml) as the `default`
     CR in `rossoctl-system`, and checks it. So the cluster never has the stock
     combiner, also on a re-run. See
     [The changed combiner (D20)](#the-changed-combiner-d20).
2. **AuthBridge image.** It builds `localhost/authbridge:local` from
   `$CORTEX_DIR/cmd/authbridge-proxy/Dockerfile` (build context: the cortex repo
   root) and loads it into the `rossoctl` Kind cluster. AuthBridge plugins are
   opt-in build tags, so the build passes `GO_BUILD_TAGS` with the cortex `full`
   profile (`scripts/profile-tags`, as the cortex CI does). The script derives it
   with a local `go`, or in a `golang` container when `go` is not installed. Set
   `GO_BUILD_TAGS` to override it.
3. **Pipeline.** It `helm upgrade`s the chart with a temporary overlay that
   inserts `opa` (after `token-exchange` on the outbound leg) and the parser set
   into the `team1` namespace pipeline (the `authbridge-runtime-config`
   ConfigMap). Every injected pod in the namespace uses it, agent and tool. The
   inbound leg is `a2a-parser`, `mcp-parser`, `inference-parser`,
   `jwt-validation`, `opa`: a tool needs `mcp-parser` and `opa` there (onboarding
   check #2, D30). It does **not** modify `charts/rossoctl/values.yaml` on disk.
   - It sets `operator-chart.featureGates.injectTools=true`. So the operator
     webhook also injects the AuthBridge sidecar into tool pods
     (`rossoctl.io/type=tool`). The default is `false`. Without it a tool pod
     gets no sidecar and no operator-registered Keycloak client, and the
     onboarding check #1 (D30) fails for the tool.
   - After the `helm upgrade`, it checks the combiner again. If the chart
     brought back the stock combiner, the script stops before the restart.
4. **Restart.** It deletes the `rossoctl.io/type=agent` **and** the
   `rossoctl.io/type=tool` pods in `team1`. The webhook injects the sidecar and
   the pipeline only at pod CREATE, so a pod that exists already keeps its old
   pipeline until it restarts.

Confirm OPA is wired into **both** legs (expect **2**):

```bash
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
# 2
```

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
if the combiner still allows a pod that has no client CR.

Check the combiner (expect **0** request fallback rules and **2** response
fallback rules):

```bash
kubectl get authorizationpolicy default -n rossoctl-system \
  -o jsonpath='{.spec.policies[*].content}' \
  | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.request'
# 0
kubectl get authorizationpolicy default -n rossoctl-system \
  -o jsonpath='{.spec.policies[*].content}' \
  | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.response'
# 2
```

---

## Step 2 — Verify the starting point

```bash
# github-agent is 2/2 (app + authbridge-proxy sidecar)
kubectl get pods -n team1 -l app.kubernetes.io/name=github-agent

# github-tool is 2/2 too (app + authbridge-proxy sidecar; needs injectTools=true)
kubectl get pods -n team1 -l app=github-tool

# bundle-service is up and serving the global combiner (the changed one, see Step 1)
kubectl get pods -n rossoctl-system -l app=bundle-service   # 1/1 Running
kubectl get authorizationpolicy -n rossoctl-system          # 'default', scope global

# the AIAC CRs: one per managed service (none before the first onboarding)
kubectl get authorizationpolicy -A -l app.kubernetes.io/managed-by=aiac-pdp-policy-writer

# github-agent's SPIFFE ID — this is what the client-scoped policy targets
kubectl exec -n team1 deploy/github-agent -c authbridge-proxy -- cat /shared/client-id.txt
# spiffe://localtest.me/ns/team1/sa/github-agent
```

---

# Part A — Inbound authorization

Proves inbound OPA authorization for `github-agent` using a **client-scoped**
policy (`spec.scope: client`) so the rule affects only this one agent. A.3
applies both example CRs (`team1/github-agent` and `team1/github-tool`). Part A
uses the `github-agent` CR. Part B uses the `github-tool` CR.

> **The changed combiner and the AIAC CRs.** Under the changed combiner (D20),
> a pod that has no client CR is denied. If AIAC has already onboarded
> `github-agent` or `github-tool`, its AIAC CR is in place, and A.3 replaces it
> by hand. AIAC writes its own CR again at the next deploy of that service, or
> at the next Controller start (the resync, D28).

> **How client-scope targeting works.** `bundle-service` looks up a
> client-scope CR by **`metadata.name` + `metadata.namespace`**, matched
> against the ServiceAccount segment of the caller's SPIFFE ID
> (`spiffe://<trust-domain>/ns/<namespace>/sa/<name>`). `spec.clientID` is
> **not** consulted by that lookup — it's a print-column convenience field. So
> the example CRs are named `github-agent` and `github-tool` (matching
> `sa/github-agent` and `sa/github-tool`), and each `clientID` is the short name
> (`"github-agent"`, `"github-tool"`; the CRD validates it against a DNS-label
> regex that rejects `spiffe://` and `/`).

## A.1 — Verify the dev-user token carries the right `sub`

```bash
curl -s -X POST "http://keycloak.localtest.me:8080/realms/rossoctl/protocol/openid-connect/token" \
     -d client_id=rossoctl -d username=dev-user -d password=dev-user -d grant_type=password -d scope=openid \
  | python3 -c 'import sys,json,base64;t=json.load(sys.stdin)["access_token"].split(".")[1];t+="="*(-len(t)%4);print("sub =",json.loads(base64.urlsafe_b64decode(t)).get("sub"))'
# sub = dev-user
```

## A.2 — Probe helper

`github-agent` is only reachable in-cluster, so probe from a throwaway pod. The
helper mints a user token and posts a JSON-RPC method the agent doesn't
implement — enough to reach the app and get a fast response without triggering
the CrewAI/tool flow:

```bash
probe_as() {   # usage: probe_as dev-user | probe_as alice
  local user="$1"
  local KC=http://keycloak.localtest.me:8080
  local TOK
  TOK=$(curl -s -X POST "$KC/realms/rossoctl/protocol/openid-connect/token" \
         -d client_id=rossoctl -d "username=$user" -d "password=$user" \
         -d grant_type=password -d scope=openid \
       | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  kubectl run "probe-$user-$RANDOM" --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
    -n team1 --env="TOK=$TOK" -- sh -c \
    'curl -s -m 15 -w "\nHTTP_CODE:%{http_code}\n" \
       -X POST http://github-agent.team1.svc.cluster.local:8080/ \
       -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" \
       -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping/nonexistent\",\"params\":{}}"'
}
```

Baseline — before any client CR, the changed combiner (D20) denies both users:

```bash
probe_as dev-user
# {"error":"policy.forbidden","message":"policy denied","plugin":"opa"}
# HTTP_CODE:403

probe_as alice
# {"error":"policy.forbidden","message":"policy denied","plugin":"opa"}
# HTTP_CODE:403
```

If AIAC has already onboarded `github-agent`, its AIAC CR decides instead, and
the result is the same as in A.4.

In A.4, `HTTP_CODE:200` with a JSON-RPC `-32601` body means the request passed
`jwt-validation` and OPA and reached the app — the app rejected the unknown
method, which is expected and irrelevant to authorization.

> **Don't test with `/.well-known/agent-card.json`** — it matches
> `jwt-validation`'s bypass list (`/.well-known/*`, `/healthz`, `/readyz`,
> `/livez`, `/metrics`), which passes it on with **no identity**. OPA then
> denies it: with no client CR the changed combiner denies it (D20), and a
> rules-based inbound package denies a request with no identity (D27). So it
> never shows the effect of a user's roles. **Don't test with a real
> `message/send` task** either — it drives the CrewAI flow and can hang for minutes if `github-tool` is unhealthy. The
> `ping/nonexistent` probe above reaches OPA and returns instantly.

## A.3 — Apply the client-scoped policy

```bash
kubectl apply -f docs/examples/opa-team1-policy.yaml
```

This applies the two target-side CRs: `github-agent` and `github-tool`.
`bundle-service` rebuilds the `team1` bundle on the CR change; `github-agent`'s
OPA polls the bundle on its own interval (10 s min, up to 120 s), so allow
**~20–30 s** before testing.

## A.4 — Test: dev-user allowed, alice blocked

```bash
probe_as dev-user
# {"error":{"code":-32601,"message":"Method not found"},"id":"1","jsonrpc":"2.0"}
# HTTP_CODE:200            — reaches the app: allowed

probe_as alice
# {"error":"policy.forbidden","message":"policy denied","plugin":"opa"}
# HTTP_CODE:403            — blocked by OPA, never reaches the app
```

> If `alice` still returns `200` right after applying, OPA hasn't polled the
> new bundle yet — wait a few seconds and retry.

## A.5 — The inbound OPA input, exactly

With `decision_logs.console: true` (set by the enable overlay), every decision
is logged by the `authbridge-proxy` sidecar. Capture the inbound input:

```bash
POD=$(kubectl get pod -n team1 -l app.kubernetes.io/name=github-agent -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n team1 "$POD" -c authbridge-proxy --tail=500 \
  | grep 'path=authbridge/inbound/request' | tail -1
```

For the `dev-user` probe the plugin builds this `input` document (rendered as
JSON; the log prints it in Go `map[...]` form):

```json
{
  "direction": "inbound",
  "method": "POST",
  "path": "/",
  "host": "github-agent.team1.svc.cluster.local:8080",
  "headers": {
    "accept": "*/*",
    "content-length": "66",
    "content-type": "application/json",
    "user-agent": "curl/8.10.1"
  },
  "identity": {
    "subject": "dev-user",
    "client_id": "rossoctl",
    "scopes": [
      "agent-team1-weather-service-advanced-aud",
      "agent-team1-github-tool-aud",
      "openid",
      "agent-team1-github-agent-aud",
      "agent-team1-weather-tool-advanced-aud",
      "profile",
      "email"
    ]
  }
}
```

- `identity` comes from the **validated inbound JWT** (`jwt-validation` runs
  before OPA). `subject` is the JWT `sub` claim — here `dev-user`, via the
  realm's `username → sub` mapper. `client_id` is the token's client (`rossoctl`
  in this probe). `scopes` are the token's granted scopes.
- Credential headers (`authorization`, `cookie`, …) are **redacted** from
  `headers` — use `identity` for auth decisions.

The inbound package of the `github-agent` CR
([`opa-team1-policy.yaml`](../docs/examples/opa-team1-policy.yaml)) keys on
`input.identity.subject`: `dev-user` maps to a role whose scopes are allowed →
`allow: true`; `alice` has no role → `allow: false`. Its source gate passes
`client_id: "rossoctl"` (the platform client). The decision appears in
the same log line as `result`:

```
result="map[allow:true client_ok:true ns_ok:true]"     # dev-user
result="map[allow:false ns_ok:true]"                    # alice (client_ok never set → denied)
```

---

# Part B — Outbound token-exchange + OPA

The agent's outbound call to `github-tool` is intercepted by the forward proxy.
`token-exchange` matches the route, mints a `github-tool`-audience token, and
records a **delegation hop**; OPA (placed after it) then sees both
`input.delegation` and a synthesized `input.identity`.

The call then crosses `github-tool`'s own inbound OPA. The example is target
side, so the callee decides:

- `github-agent`'s outbound package is a pass-through (`allow := true`, D24). It
  lets the call through.
- `github-tool`'s inbound package (the `github-tool` CR that A.3 applied) checks
  the call: the user gate, the calling-agent gate, and the MCP session rule
  (D26). Under the changed combiner (D20), `github-tool` must have a CR, or its
  inbound denies the call. A.3 gave it one, so Part B applies no other CR.

> **Agent side.** Under agent side (`AIAC_ENFORCEMENT_SIDE=agent-side`, see
> [Part C](#part-c--switch-the-enforcement-side)), the `github-agent` CR has the
> per-tool checks in its outbound package (`generate_outbound_rego`), and
> `github-tool` gets a pass-through CR (both request packages allow every
> request; D24). The example has no agent-side CRs: let AIAC write them
> (Part C).

## B.1 — Add the github-tool outbound route

Add a route for `github-tool` to the `authproxy-routes` ConfigMap (this keeps
the existing weather route):

```bash
kubectl patch configmap authproxy-routes -n team1 --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml":
"""- host: \"weather-tool-advanced-mcp\"
  target_audience: \"spiffe://localtest.me/ns/team1/sa/weather-tool-advanced\"
  token_scopes: \"openid weather-tool-exchange-aud\"
- host: \"github-tool\"
  target_audience: \"spiffe://localtest.me/ns/team1/sa/github-tool\"
  token_scopes: \"openid agent-team1-github-tool-aud\"
"""}}))')"
```

- `target_audience` is the RFC 8693 `audience` — the `github-tool` SPIFFE ID.
- `token_scopes` is the requested `scope`; `agent-team1-github-tool-aud` is the
  realm client-scope whose audience mapper stamps the `github-tool` audience.

## B.2 — Grant github-agent the exchange scope

For the `client_credentials` exchange to succeed, the github-agent Keycloak
client must have `agent-team1-github-tool-aud` as an **optional** client scope:

```bash
KC=http://keycloak.localtest.me:8080
ADMIN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# github-agent's registered client UUID (its clientId is its SPIFFE ID)
CID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/clients" \
  | python3 -c 'import sys,json;print(next(c["id"] for c in json.load(sys.stdin) if c["clientId"].endswith("/sa/github-agent")))')

# the client-scope that stamps the github-tool audience
SID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/client-scopes" \
  | python3 -c 'import sys,json;print(next(s["id"] for s in json.load(sys.stdin) if s["name"]=="agent-team1-github-tool-aud"))')

curl -s -o /dev/null -w "assign scope HTTP %{http_code}\n" -X PUT -H "Authorization: Bearer $ADMIN" \
  "$KC/admin/realms/rossoctl/clients/$CID/optional-client-scopes/$SID"
# assign scope HTTP 204
```

## B.3 — Restart github-agent to load the route

Routes are read once at startup, so restart the pod:

```bash
kubectl delete pod -n team1 -l app.kubernetes.io/name=github-agent
kubectl wait --for=condition=ready pod -n team1 -l app.kubernetes.io/name=github-agent --timeout=120s
```

## B.4 — Probe the outbound leg as dev-user

The github-agent app container (`agent`) is configured with
`HTTP_PROXY=127.0.0.1:8081` (the AuthBridge forward proxy) and has `python3`.
Drive an outbound MCP call through it, carrying a `dev-user` bearer — the token
`token-exchange` uses as the RFC 8693 `subject_token`. The github-tool app is a
FastMCP server: it serves MCP on `/mcp`, and it needs the header
`Accept: application/json, text/event-stream`. It is stateless and sends JSON
replies, so one `tools/list` request gets its reply with no MCP session ID.

```bash
POD=$(kubectl get pod -n team1 -l app.kubernetes.io/name=github-agent -o jsonpath='{.items[0].metadata.name}')
TOK=$(curl -s -X POST "http://keycloak.localtest.me:8080/realms/rossoctl/protocol/openid-connect/token" \
  -d client_id=rossoctl -d username=dev-user -d password=dev-user -d grant_type=password -d scope=openid \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

cat > /tmp/probe.py <<PY
import urllib.request, urllib.error, json
tok = """$TOK"""
op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://127.0.0.1:8081"}))
body = json.dumps({"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}).encode()
req = urllib.request.Request("http://github-tool:9090/mcp", data=body,
    headers={"Content-Type":"application/json",
             "Accept":"application/json, text/event-stream",
             "Authorization":"Bearer "+tok})
try:
    r = op.open(req, timeout=15); print("HTTP", r.status); print(r.read().decode())
except urllib.error.HTTPError as e: print("HTTPError", e.code); print(e.read().decode())
PY
kubectl exec -i -n team1 "$POD" -c agent -- python3 - < /tmp/probe.py
# HTTP 200
# {"jsonrpc":"2.0","id":"1","result":{"tools":[{"name":"source-read",...},{"name":"source-write",...},{"name":"issues-read",...},{"name":"issues-write",...}]}}
```

> **Expected result: allowed.** The reply is a JSON-RPC **`result` frame** at
> HTTP 200 that lists the four tools of `github-tool`. The call passes two OPA
> checks:
>
> 1. `github-agent`'s outbound OPA: the `github-agent` CR's outbound package is
>    a pass-through (`allow := true`).
> 2. `github-tool`'s inbound OPA: the `github-tool` CR's inbound package. There,
>    `jwt-validation` builds `input.identity` from the exchanged token
>    (`subject` = `dev-user`; `client_id` = `github-agent`'s SPIFFE ID, the
>    calling agent). `tools/list` is an MCP session message: it carries no tool
>    name. The session rule allows it when at least one tool of `owned_tools`
>    passes `tool_ok`. `source-read` passes: `dev-user` has the role
>    `developer`, and the calling agent has the role
>    `github-agent.source_operations`. Both roles grant `source-read`.
>
> The example CRs are generator output (`render_target_side`, see
> [`pdp-policy-writer-opa.md` → Tool inbound package](../docs/specs/components/pdp-policy-writer-opa.md#tool-inbound-package-target-side-authbridgeclientinboundrequest)).
> The tool inbound allows a `tools/call` when `tool_ok(input.mcp.params.name)`
> holds, and it denies every other request.
>
> **The deny shapes.** The same probe as a user with no grant on a
> `github-tool` tool (for example `alice`) is **denied** by `github-tool`'s
> inbound OPA. The tool's reverse proxy sends **HTTP `403`** with a plain JSON
> body (`{"error":"policy.forbidden","message":"policy denied","plugin":"opa"}`),
> and the agent's forward proxy relays it. Under agent side, the agent's outbound
> OPA decides instead. Because the outbound pipeline includes `mcp-parser`, the
> forward proxy sends a deny of an MCP request (one with a `method` and an `id`)
> as a **JSON-RPC 2.0 error frame at HTTP 200** (`error.code: -32000`,
> `error.data.plugin: "opa"`), so the MCP client of the caller sees one failed
> tool call and not a transport break (`writeMCPRejection` in
> `core/listener/httpx/render.go` in the cortex repo). So classify the outcome
> by the response **body**: a `result` frame = allowed; an `error` frame or a
> `403` body that names `opa` = denied. A JSON-RPC *notification* (no `id`) gets
> a plain HTTP `403` on a deny. A `token-exchange` failure comes before OPA (a
> `503`, or an error frame with `plugin: "token-exchange"`).

## B.5 — The outbound OPA input, exactly

```bash
kubectl logs -n team1 "$POD" -c authbridge-proxy --tail=200 \
  | grep 'path=authbridge/outbound/request' | tail -1
```

The plugin builds this `input` document:

```json
{
  "direction": "outbound",
  "method": "POST",
  "path": "/mcp",
  "host": "github-tool:9090",
  "headers": {
    "accept": "application/json, text/event-stream",
    "accept-encoding": "identity",
    "connection": "close",
    "content-length": "67",
    "content-type": "application/json",
    "user-agent": "Python-urllib/3.12"
  },
  "identity": {
    "subject": "dev-user",
    "client_id": "spiffe://localtest.me/ns/team1/sa/github-agent",
    "scopes": ["openid", "agent-team1-github-tool-aud"],
    "service_id": "spiffe://localtest.me/ns/team1/sa/github-tool"
  },
  "delegation": {
    "origin": "dev-user",
    "actor": "dev-user",
    "depth": 1,
    "chain": [
      {
        "subject_id": "dev-user",
        "audience": "spiffe://localtest.me/ns/team1/sa/github-tool",
        "scopes": ["openid", "agent-team1-github-tool-aud"],
        "strategy": "token-exchange",
        "from_cache": false,
        "timestamp": "2026-08-04T07:56:56Z"
      }
    ]
  },
  "mcp": {
    "method": "tools/list"
  }
}
```

Key differences from the inbound input, and how the outbound `identity` is
built:

- There is **no validated JWT** on the outbound leg. Instead, when
  `token-exchange` mints the downstream token it records a delegation hop, and
  OPA synthesizes `input.identity` **in the same shape as inbound** so policies
  can branch on `input.identity` uniformly on both legs:
  - `subject` = the delegated caller (`delegation.origin`), decoded
    best-effort from the incoming bearer's `sub` — here `dev-user`.
  - `client_id` = the **agent's own client** (`/shared/client-id.txt`), i.e.
    the party performing the exchange — **not** the target audience.
  - `scopes` = the scopes the downstream token was minted with (the last hop).
  - `service_id` = the **downstream service** the token was minted for (the last
    hop's target `audience` — here the `github-tool` SPIFFE ID). This mirrors the
    inbound identity, where `jwt-validation` surfaces the validated JWT's
    audience; on the outbound leg the equivalent "who is this token for" signal
    is the exchange target, exposed as `service_id`. The agent-side outbound
    package keys on it via `target_allow_scopes[input.identity.service_id]`;
    the target-side pass-through does not read it. Omitted when the last hop is
    a non-exchange hop that recorded no audience.
- `input.delegation` carries the full RFC 8693 chain for policies that need
  per-hop detail (`audience`, `strategy`, `from_cache`, `depth`).
- `input.mcp` is present because the probe sent a real MCP body (`tools/list`).
  Parser sections (`mcp` / `a2a` / `inference`) appear **only** when the body
  matches that parser's protocol — a non-MCP body carries no `input.mcp`.

Under target side (the example,
[`opa-team1-policy.yaml`](../docs/examples/opa-team1-policy.yaml)), the
`github-agent` CR's `outbound/request.rego` is a pass-through: it reads no field
of this input, and it allows the call. The per-tool check is in the
`github-tool` CR's `inbound/request.rego`, on `github-tool`'s inbound leg. There
the input comes from the validated exchanged JWT, not from a delegation hop:

- `input.identity.subject` = the delegated user (`dev-user`);
- `input.identity.client_id` = the calling agent
  (`spiffe://localtest.me/ns/team1/sa/github-agent`);
- `input.mcp.method` and `input.mcp.params.name` (the invoked tool), from
  `mcp-parser`.

The tool inbound gates **per tool**, with two gates: the user gate
(`subject_roles` → `subject_role_allow_scopes`) and the calling-agent gate
(`source_roles` → `source_role_allow_scopes`). `tool_ok(tool)` holds when both
gates allow the tool and neither denies it. The maps are keyed by the bare MCP
tool names of the deployed github-tool (`demo/assets/tools/github_tool`):
`source-read`, `source-write`, `issues-read`, `issues-write`. A `tools/call` is
allowed when `tool_ok(input.mcp.params.name)` holds. The session messages
(`initialize`, `notifications/initialized`, `ping`, `tools/list`) are allowed
when at least one tool of `owned_tools` passes `tool_ok`, or when the caller is
the tool's own client (`self_client_id`, the UC-1 discovery token). Every other
request is denied.

To see the decision of `github-tool`'s inbound OPA:

```bash
TOOL_POD=$(kubectl get pod -n team1 -l app=github-tool -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n team1 "$TOOL_POD" -c authbridge-proxy --tail=200 \
  | grep 'path=authbridge/inbound/request' | tail -1
```

Under agent side, the `github-agent` CR's outbound package does the per-tool
check on this outbound input. It keys on `input.identity.subject`,
`input.identity.service_id` (the exchange target), and `input.mcp.params.name`.
See
[`pdp-policy-writer-opa.md` → Agent outbound package](../docs/specs/components/pdp-policy-writer-opa.md#agent-outbound-package-agent-side-authbridgeclientoutboundrequest).

---

# Part C — Switch the enforcement side

AIAC writes the CRs of one **enforcement side** for every managed service (D16).
The switch is `AIAC_ENFORCEMENT_SIDE` in the `aiac-agent-config` ConfigMap
(`aiac-system`): `target-side` (the default) or `agent-side` (D29). The
Controller reads it at start. An unknown value stops the Controller.

| Side | `github-agent` CR | `github-tool` CR | Who checks a tool call |
|------|-------------------|------------------|------------------------|
| `target-side` | agent inbound + pass-through outbound | tool inbound (the per-tool check) + pass-through outbound | `github-tool`'s inbound OPA |
| `agent-side` | agent inbound + agent outbound (the per-tool check) | pass-through inbound + pass-through outbound | `github-agent`'s outbound OPA |

The packages are described in
[`pdp-policy-writer-opa.md` → What each side renders](../docs/specs/components/pdp-policy-writer-opa.md#what-each-side-renders).

To switch, patch the ConfigMap and restart the Controller:

```bash
kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
  -p '{"data":{"AIAC_ENFORCEMENT_SIDE":"agent-side"}}'    # or "target-side"
kubectl rollout restart deployment/aiac-agent -n aiac-system
kubectl rollout status deployment/aiac-agent -n aiac-system --timeout=300s
```

At start, the Controller checks the combiner (check #4, D30). Then it runs the
resync under the PCE lock (D28): `PUT /policy` writes the CR of every live
managed service (in the IdP catalog and not disabled) in the new side, and
deletes each other AIAC CR.
Then it quarantines each disabled service that still has an SPM. Onboardings
wait for the resync. So no CR of the old side stays.

> **Do not change the side by hand-editing the CRs.** A partial change is open.
> For example, a pass-through outbound on `github-agent` and a pass-through
> inbound on `github-tool` check nothing.

Under agent side, the onboarding checks (D30) run for agents only, and check #2
also needs `opa` in the outbound pipeline. The Kind overlay of Step 1 has it.

Check the result:

```bash
# every AIAC CR (one per managed service)
kubectl get authorizationpolicy -A -l app.kubernetes.io/managed-by=aiac-pdp-policy-writer

# github-tool's inbound package: `allow := true` under agent side;
# the per-tool check (tool_ok) under target side
kubectl get authorizationpolicy github-tool -n team1 \
  -o jsonpath='{.spec.policies[?(@.path=="inbound/request.rego")].content}'
```

The pods load the new bundles at their next poll (10 s min, up to 120 s). Until
every pod has polled, a pod can still use the bundle of the old side.

---

## Cleanup

Undo everything, in reverse order:

```bash
# 1. delete the two example CRs (github-agent and github-tool)
kubectl delete -f docs/examples/opa-team1-policy.yaml

# 2. revert authproxy-routes to weather-only
kubectl patch configmap authproxy-routes -n team1 --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml":
"""- host: \"weather-tool-advanced-mcp\"
  target_audience: \"spiffe://localtest.me/ns/team1/sa/weather-tool-advanced\"
  token_scopes: \"openid weather-tool-exchange-aud\"
"""}}))')"

# 3. remove the temporary optional client scope from github-agent
KC=http://keycloak.localtest.me:8080
ADMIN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
CID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/clients" \
  | python3 -c 'import sys,json;print(next(c["id"] for c in json.load(sys.stdin) if c["clientId"].endswith("/sa/github-agent")))')
SID=$(curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/rossoctl/client-scopes" \
  | python3 -c 'import sys,json;print(next(s["id"] for s in json.load(sys.stdin) if s["name"]=="agent-team1-github-tool-aud"))')
curl -s -o /dev/null -w "remove scope HTTP %{http_code}\n" -X DELETE -H "Authorization: Bearer $ADMIN" \
  "$KC/admin/realms/rossoctl/clients/$CID/optional-client-scopes/$SID"

# 4. revert the pipeline (removes the OPA overlay, puts back the stock
#    combiner, restarts the agent and tool pods)
OPERATOR_DIR=../operator ROSSOCTL_DIR=../rossoctl ./k8s/opa-kind-restore.sh
```

Under the changed combiner (D20), a deleted CR denies its pod. So after step 1,
`github-agent` and `github-tool` are denied until step 4 removes `opa`
from the pipeline, or until AIAC writes their CRs again. The restore puts back
the stock combiner. After that, the AIAC Controller does not start (start
check #4) until `opa-kind-enable.sh` runs again.

Confirm OPA is gone from the pipeline (expect **0**):

```bash
kubectl get configmap authbridge-runtime-config -n team1 \
  -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
# 0
```

The Keycloak realm/user changes from the Prerequisites are shared, cluster-wide
state and are harmless to leave in place for future runs.
