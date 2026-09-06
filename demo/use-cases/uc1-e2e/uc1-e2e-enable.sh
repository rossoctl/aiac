#!/usr/bin/env bash
# uc1-e2e-enable.sh — turn on the infra the uc1-e2e demo needs before the live trigger can fire:
#   1. the AIAC stack itself (aiac-agent, aiac-interface, policy-model-store, pdp-interface)
#   2. the NATS event broker
#   3. the Keycloak Event-Listener SPI (built + installed into the live Keycloak pod)
#
# Deliberately does NOT deploy github-agent/github-tool — those stay undeployed until
# uc1-e2e-driver.sh's DEPLOY phase, so that phase is a genuine first-time Keycloak client
# registration (the live trigger), not a replay against already-registered clients.
#
# This is the uc1-e2e counterpart to aiac/demo/use-cases/uc1-integration/uc1-integration-enable.sh
# (same three steps, same shape) — duplicated rather than invoked, per this repo's own convention
# of self-contained per-demo scripts (opa-kind-* and uc1-integration-* don't source each other
# either). uc1-integration's files are untouched by this demo.
#
# Usage:
#   ./uc1-e2e-enable.sh                # do all three steps
#   ./uc1-e2e-enable.sh --stack-only   # just the AIAC stack
#   ./uc1-e2e-enable.sh --broker-only  # just the NATS broker
#   ./uc1-e2e-enable.sh --spi-only     # just the Keycloak SPI listener
#
# Env vars:
#   CLUSTER_NAME        kind cluster name                          (default: rossoctl)
#   AIAC_NAMESPACE       namespace for the AIAC stack + broker       (default: aiac-system)
#   CONTAINER_RUNTIME    docker | podman                             (default: auto-detect)
#   OPENAI_SECRET_NS     namespace holding the OpenAI key to reuse   (default: team1)
#   OPENAI_SECRET_NAME   name of that Secret ('apikey' data key)     (default: openai-secret)
#   LLM_BASE_URL         AIAC Policy Rules Builder LLM endpoint      (default: https://api.openai.com/v1)
#   LLM_MODEL            AIAC Policy Rules Builder model             (default: gpt-4o-mini)
#   KC                   Keycloak base URL                          (default: http://keycloak.localtest.me:8080)
#   REALM                Keycloak realm                             (default: rossoctl)
#   KEYCLOAK_NAMESPACE   namespace Keycloak runs in                  (default: keycloak)
#   KEYCLOAK_STATEFULSET name of the Keycloak StatefulSet             (default: keycloak)
#   KEYCLOAK_IMAGE_BASE  base image to derive the SPI image from     (default: read live, fallback quay.io/keycloak/keycloak:26.5.2)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORTEX_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-rossoctl}"
AIAC_NAMESPACE="${AIAC_NAMESPACE:-aiac-system}"
OPENAI_SECRET_NS="${OPENAI_SECRET_NS:-team1}"
OPENAI_SECRET_NAME="${OPENAI_SECRET_NAME:-openai-secret}"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.openai.com/v1}"
LLM_MODEL="${LLM_MODEL:-gpt-4o-mini}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
KEYCLOAK_NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_STATEFULSET="${KEYCLOAK_STATEFULSET:-keycloak}"

if [ "${KIND_EXPERIMENTAL_PROVIDER:-}" = "podman" ]; then
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
elif ! command -v docker &> /dev/null && command -v podman &> /dev/null; then
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
else
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
fi

DO_STACK=1
DO_BROKER=1
DO_SPI=1
case "${1:-}" in
  --stack-only) DO_BROKER=0; DO_SPI=0 ;;
  --broker-only) DO_STACK=0; DO_SPI=0 ;;
  --spi-only) DO_STACK=0; DO_BROKER=0 ;;
  "") ;;
  *) echo "Usage: $0 [--stack-only|--broker-only|--spi-only]" >&2; exit 1 ;;
esac

TMPFILES=()
cleanup() { [ "${#TMPFILES[@]}" -gt 0 ] && rm -f "${TMPFILES[@]}"; }
trap cleanup EXIT

load_image_to_kind() {
  local image="$1"
  if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    local tar_file
    tar_file="$(mktemp "${TMPDIR:-/tmp}/uc1-e2e-image.XXXXXX")"
    TMPFILES+=("$tar_file")
    "$CONTAINER_RUNTIME" save "$image" -o "$tar_file"
    kind load image-archive "$tar_file" --name "$CLUSTER_NAME"
    rm -f "$tar_file"
  else
    kind load docker-image "$image" --name "$CLUSTER_NAME"
  fi
}

admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'
}

# ── Step 1 — The AIAC stack ─────────────────────────────────────────────────
step_stack() {
  echo "==> [stack] Ensuring namespace '${AIAC_NAMESPACE}' exists"
  kubectl create namespace "$AIAC_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

  echo "==> [stack] Wiring the LLM secret (reusing ${OPENAI_SECRET_NS}/${OPENAI_SECRET_NAME})"
  local apikey
  apikey=$(kubectl get secret "$OPENAI_SECRET_NAME" -n "$OPENAI_SECRET_NS" -o jsonpath='{.data.apikey}' | base64 -d)
  [ -n "$apikey" ] || { echo "ERROR: could not read apikey from secret ${OPENAI_SECRET_NS}/${OPENAI_SECRET_NAME}" >&2; exit 1; }
  kubectl create secret generic aiac-agent-secret -n "$AIAC_NAMESPACE" \
    --from-literal=LLM_API_KEY="$apikey" --dry-run=client -o yaml | kubectl apply -f -

  # Four images, matching demo/use-cases/uc1-onboarding/init/01-prereqs.py's AIAC_IMAGES list —
  # keep these two lists in sync if either changes.
  local images=(
    "localhost/aiac-pdp-config:local|src/aiac/idp/service/configuration/keycloak/Dockerfile|src/aiac/idp/service/configuration/keycloak"
    "localhost/aiac-pdp-policy-opa:local|src/aiac/pdp/service/policy/opa/Dockerfile|src"
    "localhost/aiac-policy-model-store:local|src/aiac/policy/model_store/service/Dockerfile|src"
    "localhost/aiac-agent:local|src/aiac/agent/controller/Dockerfile|src"
  )
  local entry image dockerfile context
  for entry in "${images[@]}"; do
    IFS='|' read -r image dockerfile context <<< "$entry"
    if "$CONTAINER_RUNTIME" image inspect "$image" >/dev/null 2>&1; then
      echo "==> [stack] '${image}' already present locally, skipping build"
    else
      echo "==> [stack] Building '${image}' from ${context} (${dockerfile})"
      ( cd "$CORTEX_DIR/aiac" && "$CONTAINER_RUNTIME" build -t "$image" -f "$dockerfile" "$context" )
    fi
    load_image_to_kind "$image"
  done

  echo "==> [stack] Applying AIAC manifests"
  kubectl apply -f "$CORTEX_DIR/aiac/k8s/pdp-interface-deployment.yaml"
  kubectl apply -f "$CORTEX_DIR/aiac/k8s/policy-model-store-statefulset.yaml"
  kubectl apply -f "$CORTEX_DIR/aiac/k8s/agent-deployment.yaml"

  echo "==> [stack] Pointing aiac-agent-config at a real LLM endpoint (placeholders shipped on purpose)"
  kubectl patch configmap aiac-agent-config -n "$AIAC_NAMESPACE" --type merge \
    -p "{\"data\":{\"LLM_BASE_URL\":\"${LLM_BASE_URL}\",\"LLM_MODEL\":\"${LLM_MODEL}\"}}"

  echo "==> [stack] Waiting for rollout (this restarts aiac-agent to pick up the LLM config)"
  kubectl rollout restart deployment/aiac-agent -n "$AIAC_NAMESPACE"
  kubectl wait deployment/aiac-interface -n "$AIAC_NAMESPACE" --for=condition=Available --timeout=180s
  kubectl wait statefulset/aiac-policy-model-store -n "$AIAC_NAMESPACE" --for=jsonpath='{.status.readyReplicas}'=1 --timeout=180s
  kubectl wait deployment/aiac-agent -n "$AIAC_NAMESPACE" --for=condition=Available --timeout=180s
  echo "==> [stack] AIAC stack up."
}

# ── Step 2 — The NATS event broker ──────────────────────────────────────────
step_broker() {
  echo "==> [broker] Applying the NATS event broker (${AIAC_NAMESPACE})"
  kubectl apply -f "$CORTEX_DIR/aiac/k8s/event-broker-deployment.yaml"
  kubectl rollout status deployment/aiac-event-broker -n "$AIAC_NAMESPACE" --timeout=120s
  echo "==> [broker] aiac-event-broker up. Default NATS_URL (nats://aiac-event-broker-service:4222) matches — no override needed."
}

# ── Step 3 — The Keycloak SPI listener ──────────────────────────────────────
step_spi() {
  echo "==> [spi] Building the Keycloak SPI jar"
  ( cd "$CORTEX_DIR/aiac/keycloak-spi" && mvn -q package )
  local jar
  jar=$(find "$CORTEX_DIR/aiac/keycloak-spi/target" -maxdepth 1 -name '*.jar' ! -name '*-tests.jar' | head -1)
  [ -n "$jar" ] || { echo "ERROR: no jar found under aiac/keycloak-spi/target after mvn package" >&2; exit 1; }
  echo "    built: ${jar}"

  local base_image="${KEYCLOAK_IMAGE_BASE:-}"
  if [ -z "$base_image" ]; then
    base_image=$(kubectl get statefulset "$KEYCLOAK_STATEFULSET" -n "$KEYCLOAK_NAMESPACE" \
      -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)
    base_image="${base_image:-quay.io/keycloak/keycloak:26.5.2}"
  fi
  echo "==> [spi] Deriving a Keycloak image from ${base_image}"

  local build_dir
  build_dir="$(mktemp -d "${TMPDIR:-/tmp}/uc1-e2e-kc-image.XXXXXX")"
  TMPFILES+=("$build_dir")
  cp "$jar" "$build_dir/aiac-event-listener.jar"
  cat > "$build_dir/Dockerfile" <<DOCKERFILE
FROM ${base_image}
COPY aiac-event-listener.jar /opt/keycloak/providers/aiac-event-listener.jar
RUN /opt/keycloak/bin/kc.sh build
DOCKERFILE

  local kc_image="localhost/keycloak-aiac:local"
  "$CONTAINER_RUNTIME" build -t "$kc_image" "$build_dir"
  load_image_to_kind "$kc_image"

  echo "==> [spi] Patching statefulset/${KEYCLOAK_STATEFULSET} (live, reversible — not a chart edit)"
  kubectl set image "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" \
    "${KEYCLOAK_STATEFULSET}=${kc_image}"
  # AiacEventListenerProviderFactory's default NATS_URL is the bare service name
  # "aiac-event-broker-service" (no namespace suffix) — a Kubernetes short DNS name that only
  # resolves within the querying pod's own namespace. Keycloak runs in ${KEYCLOAK_NAMESPACE},
  # the broker in ${AIAC_NAMESPACE}; without this override the listener fails with
  # java.net.UnknownHostException: aiac-event-broker-service and drops every event.
  kubectl set env "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" \
    "NATS_URL=nats://aiac-event-broker-service.${AIAC_NAMESPACE}.svc.cluster.local:4222"
  kubectl rollout status "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" --timeout=180s

  echo "==> [spi] Enabling the listener on realm '${REALM}'"
  local admin
  admin=$(admin_token)
  [ -n "$admin" ] || { echo "ERROR: could not obtain a Keycloak master admin token" >&2; exit 1; }
  curl -s -o /dev/null -w "    events/config HTTP %{http_code}\n" -X PUT \
    -H "Authorization: Bearer ${admin}" -H "Content-Type: application/json" \
    "${KC}/admin/realms/${REALM}/events/config" \
    -d '{"adminEventsEnabled": true, "eventsListeners": ["jboss-logging", "aiac-event-listener"]}'

  echo "==> [spi] Keycloak SPI installed and enabled."
  echo "    Verify: kubectl logs statefulset/${KEYCLOAK_STATEFULSET} -n ${KEYCLOAK_NAMESPACE} | grep -i aiac-event-listener"
}

[ "$DO_STACK" -eq 1 ] && step_stack
[ "$DO_BROKER" -eq 1 ] && step_broker
[ "$DO_SPI" -eq 1 ] && step_spi

cat <<EOF

==> Done. github-agent/github-tool are deliberately NOT deployed by this script.

Next: ./uc1-e2e-driver.sh (its DEPLOY phase installing github-agent/github-tool for the
first time IS the live trigger) — see uc1-e2e-runbook.md.

Revert with: ./uc1-e2e-restore.sh
EOF
