# AIAC — Kubernetes Installation Guide

This guide covers the full AIAC deployment in the `aiac-system` namespace.

## Components deployed

| Manifest | Contents | Port(s) |
|---|---|---|
| `pdp-interface-deployment.yaml` | Rossoctl Interface Pod (IdP Configuration Service + PDP Policy Writer **Phase 1 rego-file mock** `aiac-pdp-policy-opa`) + 2 ClusterIP Services | 7071, 7072 |
| `policy-model-store-statefulset.yaml` | Policy Model Store StatefulSet + 1 Gi PVC + headless Service + ClusterIP Service | 7074 |
| `event-broker-deployment.yaml` | NATS JetStream Event Broker Deployment + ClusterIP Service | 4222 |
| `agent-deployment.yaml` | Agent Pod Deployment (`aiac-init` init container + AIAC Agent) + ClusterIP Service | 7070 |

## Prerequisites

- Kubernetes cluster with `kubectl` configured for the target cluster.
- Keycloak reachable from within the cluster (default: `http://keycloak-service.keycloak.svc:8080`).
- For local Kind clusters: `kind` CLI and `docker`.

## Platform preconditions

Two platform preconditions apply to every deploy of an AIAC unit in `aiac-system`, also to a
deploy that changes only a parameter. Check both before you deploy, in this order. If a check
fails, install that precondition, then deploy.

### OPA on the Kind platform

AIAC needs OPA in the AuthBridge pipeline, `bundle-service`, and the changed global combiner
(D20). Without them the AIAC Controller does not start.

| | |
|---|---|
| Check | `./k8s/opa-kind-verify.sh` (read-only, exits non-zero on the first failed check) |
| Install | `OPERATOR_DIR=… ROSSOCTL_DIR=… CORTEX_DIR=… ./k8s/opa-kind-enable.sh`, from the repo root. Details: [`opa-kind-runbook.md` → Enable](opa-kind-runbook.md#enable) |
| Install warning | Two image builds (a few minutes). It runs `helm upgrade` on the rossoctl chart and restarts the agent and tool pods in `team1`. |
| Inputs | Sibling clones `operator`, `rossoctl`, `cortex`. Defaults are `../operator`, `../rossoctl`, `../cortex`, relative to the repo root. If one is missing, stop and ask for its path. |
| Re-check | After any `kubectl apply` of a platform manifest or an operator-chart upgrade. The check also fails when the stock combiner is back. |

The install runs the verify script as its last step, so after an install the check has already
passed once.

`k8s/opa-kind-enable.sh` and `k8s/opa-kind-restore.sh` run `helm upgrade` on the rossoctl chart.
This can put the stock Keycloak image back. After either script, do the Keycloak SPI check below.

### Keycloak event-listener SPI

AIAC learns of a new Keycloak client from the `aiac-event-listener` SPI, which publishes to the
NATS broker. Without it no registration event reaches the Controller, and the onboarding path
(and the system test lane) does not work.

| | |
|---|---|
| Check | `./k8s/keycloak-spi-verify.sh` (read-only, exits non-zero on the first failed check) |
| Install | `./k8s/keycloak-spi-install.sh`, from the repo root |
| Install warning | One image build (maven container, then a derived Keycloak image). It restarts the Keycloak StatefulSet once, so Keycloak is down for a short time. On the realm it adds `aiac-event-listener` to the event listeners and turns on admin events. The other event settings stay. |
| Inputs | The OPA precondition above first (the platform must be on Kind). A broker in `aiac-system` is not needed to install, but the listener drops events until `aiac-event-broker` runs. Both scripts read `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` from the environment, else from `.env`, else from secret `aiac-system/keycloak-admin-secret`, else use `admin`. |
| Re-install | The install records the stock Keycloak image in the StatefulSet annotation `aiac.rossoctl.dev/keycloak-base-image`, so a re-run derives from the same image. If the live image is the derived one and the annotation is missing (an install by an older script), the install stops: set `KEYCLOAK_IMAGE_BASE` to the stock image. |
| Re-check | After any change of the Keycloak StatefulSet. It can put the stock Keycloak image back. |

The install runs the verify script as its last step, so after an install the check has already
passed once.

## 1 — Build the images

Run from the repo root:

```bash
# IdP Configuration Service (Interface Pod container 1)
# Build context is the component directory (Dockerfile copies requirements.txt + main.py from there)
docker build -f src/aiac/idp/service/configuration/keycloak/Dockerfile \
  -t localhost/aiac-pdp-config:local \
  src/aiac/idp/service/configuration/keycloak/

# PDP Policy Writer — Phase 1 OPA rego-file mock (Interface Pod container 2, writes .rego to filesystem)
# Build context is src/ (the OPA Dockerfile COPYs the whole tree and sets PYTHONPATH)
docker build -f src/aiac/pdp/service/policy/opa/Dockerfile \
  -t localhost/aiac-pdp-policy-opa:local \
  src/

# Policy Model Store
docker build -f src/aiac/policy/model_store/service/Dockerfile \
  -t localhost/aiac-policy-model-store:local src/

# AIAC Agent (also used as the aiac-init init container, via a command override) — context: src/
docker build -f src/aiac/agent/controller/Dockerfile \
  -t localhost/aiac-agent:local src/
```

The Event Broker uses the stock `nats:2.14-alpine` image (pinned in
`event-broker-deployment.yaml`) — no build step.

## 2 — Load images into the cluster

**Kind (local development)**

```bash
kind load docker-image localhost/aiac-pdp-config:local       --name <cluster-name>
kind load docker-image localhost/aiac-pdp-policy-opa:local    --name <cluster-name>
kind load docker-image localhost/aiac-policy-model-store:local     --name <cluster-name>
kind load docker-image localhost/aiac-agent:local            --name <cluster-name>
```

For a fully air-gapped Kind cluster (no outbound network access), also pull and load the
NATS image; `event-broker-deployment.yaml` uses `imagePullPolicy: IfNotPresent`, so a
networked cluster can skip this and pull it directly:

```bash
docker pull nats:2.14-alpine
kind load docker-image nats:2.14-alpine --name <cluster-name>
```

**Remote registry** — tag, push, then update the `image:` fields in the manifests to match.

## 3 — Create the secrets

Two Secrets must exist in `aiac-system` before applying the manifests. Create the namespace first, then both secrets.

```bash
kubectl create namespace aiac-system
```

**`keycloak-admin-secret`** — required by the Interface Pod:

```bash
kubectl create secret generic keycloak-admin-secret \
  -n aiac-system \
  --from-literal=KEYCLOAK_ADMIN_USERNAME=<admin-user> \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD=<admin-password>
```

> `pdp-interface-deployment.yaml` contains placeholder credentials for reference only.
> For any non-local environment, create the secret manually and remove the `stringData` block.

## 3b — Configure the Agent LLM (ConfigMap + Secret)

The AIAC Agent's Policy Rules Builder calls an **OpenAI-compatible** LLM endpoint
(`ChatOpenAI(base_url=LLM_BASE_URL, model=LLM_MODEL, api_key=LLM_API_KEY)`). This configuration is
split across two objects the Agent consumes via `envFrom`, and `agent-deployment.yaml` ships only
**placeholders** — you must supply the real values per environment. The real values live in the
repo-root `.env` (gitignored); source it (`set -a; . .env; set +a`) and use those `$LLM_BASE_URL` /
`$LLM_MODEL` / `$LLM_API_KEY` in the commands below.

| Key | Object | Notes |
|-----|--------|-------|
| `LLM_BASE_URL` | `aiac-agent-config` ConfigMap | OpenAI-compatible base URL (e.g. a litellm proxy). Placeholder in the manifest. |
| `LLM_MODEL` | `aiac-agent-config` ConfigMap | Model the endpoint serves. Placeholder in the manifest. |
| `LLM_API_KEY` | `aiac-agent-secret` Secret | **Not** defined in any manifest — the Deployment only references it. |

```bash
# API key — create the Secret BEFORE applying agent-deployment.yaml (step 5); the manifest only
# references it. (To update an existing one, append: --dry-run=client -o yaml | kubectl apply -f -)
kubectl create secret generic aiac-agent-secret -n aiac-system \
  --from-literal=LLM_API_KEY=<your-api-key>

# Endpoint + model — patch the LIVE ConfigMap AFTER step 5 (agent-deployment.yaml creates it with
# placeholders). Do not commit real endpoints/keys to the manifest.
kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
  -p '{"data":{"LLM_BASE_URL":"https://<your-openai-compatible-endpoint>/v1","LLM_MODEL":"<model>"}}'
```

Both are read by the Agent at startup, so a change to either takes effect on the next (re)start:
`kubectl rollout restart deployment/aiac-agent -n aiac-system`.

### Check or change the API key

The Agent reads the key only from the Secret `aiac-agent-secret`. It does not read `.env`. Thus a new
key in `.env` (for example after a rotation) does not reach the Agent until you update the Secret.
The rebuild flow ("Rebuilding the AIAC Agent: always reload its LLM configuration") updates it
from `.env` together with the endpoint and the model. Use the commands below to change only the
key, without a rebuild.

Check that the endpoint accepts the key. HTTP `200` means that it accepts the key:

```bash
set -a; . .env; set +a
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $LLM_API_KEY" "$LLM_BASE_URL/models"
```

Change the key, then restart the Agent:

```bash
kubectl create secret generic aiac-agent-secret -n aiac-system \
  --from-literal=LLM_API_KEY="$LLM_API_KEY" --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/aiac-agent -n aiac-system
kubectl rollout status deployment/aiac-agent -n aiac-system
```

If the endpoint refuses the key (HTTP `401` or `403`), each onboarding fails. The Agent logs
`LLMCredentialsError` (logger `aiac.onboarding.llm_credentials`), rolls the onboarding back,
quarantines the service and moves the event to `aiac.apply.dlq`. The service has no CR, so the
combiner denies it (D20). After you fix the key, onboard each failed service again (see
[UC1 → Failure & Rollback](../docs/specs/components/aiac-agent/uc1-service-onboarding.md#failure--rollback)).

## 4 — Configure the environment

Edit the `aiac-pdp-config` ConfigMap in `pdp-interface-deployment.yaml` to match your environment:

| Key | Default | Used by |
|-----|---------|---------|
| `KEYCLOAK_URL` | `http://keycloak-service.keycloak.svc:8080` | IdP Configuration Service |
| `KEYCLOAK_REALM` | `rossoctl` | IdP Configuration Service |
| `KEYCLOAK_ADMIN_REALM` | `master` | IdP Configuration Service |
| `AIAC_PDP_CONFIG_URL` | `http://aiac-pdp-config-service:7071` | Agent |
| `AIAC_PDP_POLICY_URL` | `http://aiac-pdp-policy-service:7072` | Agent |
| `AIAC_POLICY_MODEL_STORE_URL` | `http://aiac-policy-model-store-service:7074` | Agent |
| `SERVICEPOLICY_DB_PATH` | `/data/policy_model.db` | Policy Model Store |
| `NATS_URL` | `nats://aiac-event-broker-service:4222` | Agent, `aiac-init` — Event Broker ClusterIP address |
| `AIAC_RAG_INGEST_URL` | `http://aiac-rag-service:7073` | Init container — **added in Phase 3** (RAG Pod, issue 4.20) |
| `AIAC_CHROMADB_URL` | `http://aiac-rag-service:8000` | Agent — **added in Phase 3** (RAG Pod, issue 4.20) |

`aiac-init` treats `AIAC_RAG_INGEST_URL` as optional and skips the RAG Ingest health check
when it is unset (the current phase has no RAG pod deployed yet).

## 5 — Deploy

Apply in dependency order:

```bash
# 1. Interface Pod — creates the namespace, ConfigMap, Secret, and ClusterIP Services
kubectl apply -f k8s/pdp-interface-deployment.yaml

# 2. Event Broker — NATS JetStream, no dependencies
kubectl apply -f k8s/event-broker-deployment.yaml

# 3. Policy Model Store — needs the aiac-system namespace
kubectl apply -f k8s/policy-model-store-statefulset.yaml

# 4. Agent — aiac-init waits for NATS + Interface Pod to be healthy (it does not
#    currently gate on Policy Model Store readiness)
kubectl apply -f k8s/agent-deployment.yaml
```

Wait for all pods to be ready:

```bash
kubectl wait deployment/aiac-interface     -n aiac-system --for=condition=Available --timeout=120s
kubectl wait deployment/aiac-event-broker  -n aiac-system --for=condition=Available --timeout=120s
kubectl wait statefulset/aiac-policy-model-store -n aiac-system --for=jsonpath='{.status.readyReplicas}'=1 --timeout=120s
kubectl wait deployment/aiac-agent         -n aiac-system --for=condition=Available --timeout=120s
```

## 6 — Verify

Port-forward each service and check its health endpoint:

```bash
# IdP Configuration Service
kubectl port-forward svc/aiac-pdp-config-service 7071:7071 -n aiac-system &
pf_pids=$!
curl http://localhost:7071/health
# {"status":"ok"}

# PDP Policy Writer
kubectl port-forward svc/aiac-pdp-policy-service 7072:7072 -n aiac-system &
pf_pids="$pf_pids $!"
curl http://localhost:7072/health
# {"status":"ok"}

# Policy Model Store
kubectl port-forward svc/aiac-policy-model-store-service 7074:7074 -n aiac-system &
pf_pids="$pf_pids $!"
curl http://localhost:7074/health
# {"status":"ok"}

# AIAC Agent
kubectl port-forward svc/aiac-agent-service 7070:7070 -n aiac-system &
pf_pids="$pf_pids $!"
curl http://localhost:7070/health
# {"status":"ok"}

# cleanup only the tunnels started above (not unrelated port-forward sessions)
kill $pf_pids
```

### NATS Event Broker — end-to-end check

Requires the [`nats` CLI](https://github.com/nats-io/natscli).

```bash
kubectl port-forward svc/aiac-event-broker-service 4222:4222 -n aiac-system &
pf_pid=$!

# Wait for the tunnel to accept connections before publishing through it — port-forward
# starts in the background and needs a moment; fail fast if it exits instead of connecting.
for i in $(seq 1 30); do
  if ! kill -0 "$pf_pid" 2>/dev/null; then
    echo "port-forward exited before becoming ready" >&2
    exit 1
  fi
  (exec 3<>/dev/tcp/localhost/4222) 2>/dev/null && exec 3>&- && break
  sleep 0.5
done

nats context save aiac --server nats://localhost:4222
nats context select aiac

# Publish a test service-onboarding event (use a real IdP client UUID to see it
# processed end to end; any string will demonstrate delivery either way):
nats pub aiac.apply.service.<test-uuid> '{"id":"<test-uuid>"}'

# Confirm the Agent processed and acked it (no redelivery):
kubectl logs deployment/aiac-agent -n aiac-system -c aiac-agent --tail=50

kill "$pf_pid"
```

Run the IdP data smoke test:

```bash
kubectl port-forward svc/aiac-pdp-config-service 7071:7071 -n aiac-system &
cd aiac
.venv/bin/python test/idp/configuration/show_keycloak_data.py
pkill -f "port-forward.*7071"
```

## Changing log levels

Every workload reads a `LOG_LEVEL` key from its ConfigMap. The manifests ship `INFO`, and you can
change the level on a running cluster **without rebuilding any image**. `LOG_LEVEL` is read once,
at process start, so after patching a ConfigMap you must restart the workload. The env of a running
pod is fixed when the pod is created, so patching the ConfigMap alone changes nothing.

| Workload | ConfigMap | Restart with |
|---|---|---|
| Agent (`aiac-init` + Controller) | `aiac-agent-config` | `kubectl rollout restart deployment/aiac-agent -n aiac-system` |
| Interface Pod (IdP Configuration Service + PDP Policy Writer) | `aiac-pdp-config` | `kubectl rollout restart deployment/aiac-interface -n aiac-system` |
| Policy Model Store | `aiac-policy-model-store-config` | `kubectl rollout restart statefulset/aiac-policy-model-store -n aiac-system` |
| Event Broker (NATS) | `aiac-event-broker-config` | `kubectl rollout restart deployment/aiac-event-broker -n aiac-system` |
| Isolated IdP dev pod | `aiac-pdp-config-standalone` | delete and re-create the Pod (see below) |

**Accepted values.** The Python services (Agent, Interface Pod, Policy Model Store) accept
`DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL`, case-insensitive, or a numeric level such as
`10`. An unrecognized value falls back to `INFO` instead of stopping the service. NATS has no level
setting below its default, so for the Event Broker only `DEBUG` (`-D`) and `TRACE` (`-DV`, which
adds protocol tracing) change anything. Any other value gives NATS's default output.

**Example: raise the Agent to DEBUG** while diagnosing an onboarding that never lands:

```bash
kubectl patch configmap aiac-agent-config -n aiac-system --type merge \
  -p '{"data":{"LOG_LEVEL":"DEBUG"}}' \
  && kubectl rollout restart deployment/aiac-agent -n aiac-system

kubectl rollout status deployment/aiac-agent -n aiac-system
kubectl logs deployment/aiac-agent -n aiac-system -c aiac-agent -f      # Controller
kubectl logs deployment/aiac-agent -n aiac-system -c aiac-init          # init container
```

Use the same pattern for any other row of the table. Swap in that row's ConfigMap name and
restart command. Set the value back to `INFO` the same way when you are done.

```bash
# e.g. the Interface Pod (both of its containers share the one key)
kubectl patch configmap aiac-pdp-config -n aiac-system --type merge \
  -p '{"data":{"LOG_LEVEL":"DEBUG"}}' \
  && kubectl rollout restart deployment/aiac-interface -n aiac-system
```

Notes:

- **Precedence in the Agent pod.** Both Agent containers load `aiac-pdp-config` first and
  `aiac-agent-config` second, and in `envFrom` the last source wins. So the Agent's level is
  always the one in `aiac-agent-config`, and patching `aiac-pdp-config` changes only the Interface
  Pod.
- **Re-applying a manifest resets the level.** `kubectl apply -f k8s/<manifest>.yaml` writes the
  ConfigMap back to `INFO`. To make a level permanent, edit `LOG_LEVEL` in the manifest itself.
- **Restarting the Event Broker drops its JetStream data**, because the data lives on an
  `emptyDir`. The Agent's `aiac-init` recreates the stream, but in-flight messages are lost.
- **The isolated IdP dev pod** is a bare Pod, so `rollout restart` does not apply to it. Patch
  `aiac-pdp-config-standalone`, then `kubectl delete pod idp-configuration-keycloak-pod -n aiac-system`
  and re-create the Pod. Re-creating it with `kubectl apply -f k8s/idp-configuration-keycloak-pod.yaml`
  also resets the ConfigMap, so for that pod, edit the manifest instead of patching.
- `LOG_LEVEL` sets the **application** (root) logger. It does not change uvicorn's `--log-level`,
  so uvicorn's own access and error lines stay at uvicorn's default.

## Redeploying after a code change

```bash
# Rebuild the changed image, e.g. IdP Configuration Service (context: the service dir):
docker build -f src/aiac/idp/service/configuration/keycloak/Dockerfile \
  -t localhost/aiac-pdp-config:local \
  src/aiac/idp/service/configuration/keycloak/
kind load docker-image localhost/aiac-pdp-config:local --name <cluster-name>

# Restart the affected deployment:
kubectl rollout restart deployment/aiac-interface -n aiac-system
```

### Rebuilding the AIAC Agent: always reload its LLM configuration

Every time you rebuild `localhost/aiac-agent:local`, also reload the LLM configuration: the
endpoint and the model into the `aiac-agent-config` ConfigMap, and the key into the
`aiac-agent-secret` Secret. Do not skip it, also when only code changed. It makes sure the Agent
runs with the LLM endpoint, model **and key** of the repo-root `.env`, as one set. If you swap the
LLM in `.env` (another endpoint with its own key), the next rebuild moves all three together. An
endpoint from `.env` with an older key in the cluster gives HTTP `401` on each onboarding.

```bash
docker build -f src/aiac/agent/controller/Dockerfile -t localhost/aiac-agent:local src/
kind load docker-image localhost/aiac-agent:local --name <cluster-name>

# Reload the LLM configuration: the apply writes the manifest value of each ConfigMap key (the LLM
# keys are placeholders). The patch puts every live key back and then the real LLM values from
# .env (step 3b). The Secret gets the key from the same .env. A subshell: a failed check or step
# stops the rest of the block, not your shell.
( set -eo pipefail
set -a; . .env; set +a
: "${LLM_BASE_URL:?missing in .env}" "${LLM_MODEL:?missing in .env}" "${LLM_API_KEY:?missing in .env}"
# Check the .env set BEFORE any change: the endpoint must accept the key. If not, the block stops
# and the running Agent keeps its configuration.
RESP=$(curl -s -w '\n%{http_code}' -H "Authorization: Bearer $LLM_API_KEY" "$LLM_BASE_URL/models" || true)
CODE=${RESP##*$'\n'}
[ "$CODE" = 200 ] || { echo "ERROR: $LLM_BASE_URL/models answered HTTP $CODE to the .env key. Fix .env first." >&2; exit 1; }
printf '%s' "${RESP%$'\n'*}" | jq -e --arg m "$LLM_MODEL" 'any(.data[]?; .id == $m)' >/dev/null \
  || echo "WARNING: $LLM_MODEL is not in the model list of $LLM_BASE_URL. Check LLM_MODEL in .env." >&2
# Read ALL live keys BEFORE the apply: the apply resets each key to its manifest value.
LIVE=$(kubectl get configmap aiac-agent-config -n aiac-system -o json | jq -c '.data // {}')
kubectl apply -f k8s/agent-deployment.yaml
# Live keys first, the .env LLM values on top. jq builds the JSON, so a quote or a backslash in
# a value cannot break the patch.
kubectl patch configmap aiac-agent-config -n aiac-system --type merge -p "$(jq -n \
  --argjson live "$LIVE" --arg url "$LLM_BASE_URL" --arg model "$LLM_MODEL" \
  '{data: ($live + {LLM_BASE_URL: $url, LLM_MODEL: $model})}')"
# The key, from the same .env. The Secret holds only LLM_API_KEY, so a full replace is safe.
kubectl create secret generic aiac-agent-secret -n aiac-system \
  --from-literal=LLM_API_KEY="$LLM_API_KEY" --dry-run=client -o yaml | kubectl apply -f -

# Restart AFTER the patch and the Secret. The Agent reads both at start only.
kubectl rollout restart deployment/aiac-agent -n aiac-system
kubectl rollout status deployment/aiac-agent -n aiac-system
)
```

- The apply writes the manifest value of each key, for example `AIAC_ENFORCEMENT_SIDE`
  (`target-side`), `LOG_LEVEL` (`INFO`) and `LLM_REQUEST_TIMEOUT` (`120`). The block reads all
  live keys before the apply and patches them back before the restart. Thus an `agent-side`
  deployment stays `agent-side`, and a tuned key (for example `LLM_MAX_RETRIES` or
  `LLM_RETRY_BACKOFF_MAX`) keeps its live value. Only a key that is new in the manifest gets its
  manifest value. To set a key back to its manifest default, patch it by hand. To change the
  side, see `docs/agents/deploy.md`, `ac-side`.
- `.env` must have `LLM_BASE_URL`, `LLM_MODEL` and `LLM_API_KEY`. If one is missing, the `:?`
  check stops the block before the apply. Then stop and ask. Do not leave the placeholder in the
  ConfigMap.
- The block checks the `.env` set before it changes anything: `GET $LLM_BASE_URL/models` with the
  `.env` key must answer HTTP `200`. Any other answer (`401`: the endpoint does not know the key;
  `000`: the endpoint is unreachable) stops the block, and the cluster keeps its configuration.
  If the model list does not contain `LLM_MODEL`, the block only warns, because an endpoint can
  serve a model that it does not list.
- The AIAC procedures write the key only from `.env`: this block, step 3b and the clean redeploy
  in `opa-kind-runbook.md`. A script that writes `aiac-agent-secret` from another source can put
  back a key that does not match the `.env` endpoint. Run this block after such a script.

---

## Phase 2: Upgrading the OPA PDP Policy Writer to the CR-backed implementation

Phase 1 already deploys the OPA PDP Policy Writer (`aiac-pdp-policy-opa`) as a filesystem
stub that writes `.rego` files to `REGO_OUTPUT_DIR`. Phase 2 upgrades that same container
in place to the CR-backed implementation, which writes Rego packages to an
`AuthorizationPolicy` Kubernetes CR instead. The image name, ClusterIP Service name, and
port are unchanged — no image swap and no Agent reconfiguration required.

See issue [#70 — K8s: OPA PDP Policy Writer AuthorizationPolicy CR + RBAC upgrade](https://github.com/rossoctl/aiac/issues/70) for the full procedure (ServiceAccount, ClusterRole, ClusterRoleBinding, CR instance).

```bash
# Rebuild the OPA PDP Policy Writer image with the Phase 2 (CR-backed) implementation
docker build -f src/aiac/pdp/service/policy/opa/Dockerfile \
  -t localhost/aiac-pdp-policy-opa:local src/
kind load docker-image localhost/aiac-pdp-policy-opa:local --name <cluster-name>
```

---

## Isolated dev: IdP Configuration Service only

To test the IdP Configuration Service in isolation without deploying the full stack, use the standalone dev pod manifest:

```bash
kubectl apply -f k8s/idp-configuration-keycloak-pod.yaml
kubectl wait pod/idp-configuration-keycloak-pod -n aiac-system \
  --for=condition=Ready --timeout=60s
```

See [idp-configuration-keycloak-pod.yaml](idp-configuration-keycloak-pod.yaml) for the minimal ConfigMap and pod spec.

---

## IdP Configuration Service API reference

All endpoints accept a `?realm=<realm>` query parameter. `/health` uses `KEYCLOAK_ADMIN_REALM` directly.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/subjects` | List users |
| GET | `/roles` | List realm roles |
| GET | `/services` | List clients |
| GET | `/scopes` | List client scopes |
| GET | `/subjects/{subject_id}/assignments` | Realm and service role mappings for a user |
| GET | `/services/{service_id}/permissions` | Client roles for a service |
| GET | `/roles/{role_name:path}/composites` | Composite roles for a realm role (the role name can contain `/`) |
| GET | `/health` | Readiness probe — `200 ok` or `503 unavailable` |

All list endpoints return a JSON array. `/subjects/{id}/assignments` returns:

```json
{
  "realmMappings": [...],
  "serviceMappings": { "<clientId>": { "mappings": [...] } }
}
```

Errors from Keycloak are returned as `502` with `{"error": "<message>"}`.
