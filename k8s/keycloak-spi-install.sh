#!/usr/bin/env bash
# keycloak-spi-install.sh — install the AIAC Keycloak event-listener SPI into the live Keycloak on Kind.
#
# Steps:
#   1. Preflight: find the Keycloak container and the stock image to derive from.
#   2. Build the SPI jar in a maven container (no host JDK/Maven needed).
#   3. Derive a Keycloak image from the stock one, with the jar in /opt/keycloak/providers, load it
#      into Kind, and patch the Keycloak StatefulSet in one step: the new image, NATS_URL set to the
#      cross-namespace address of the AIAC event broker (the bare service name does not resolve from
#      `keycloak`), and an annotation that records the stock image for a re-run.
#   4. Add `aiac-event-listener` to the event listeners of the realm and turn on admin events. The
#      other event settings of the realm stay as they are.
#   5. Run keycloak-spi-verify.sh.
#
# The patch is live and reversible, not a chart edit. Keycloak restarts once.
#
# Usage (from the repo root):
#   ./k8s/keycloak-spi-install.sh
#
# Env vars (keycloak-spi-verify.sh reads the same names):
#   CLUSTER_NAME             kind cluster name                       (default: $KIND_CLUSTER, else rossoctl)
#   AIAC_NAMESPACE           namespace of the AIAC event broker      (default: aiac-system)
#   KEYCLOAK_NAMESPACE       namespace Keycloak runs in              (default: keycloak)
#   KEYCLOAK_STATEFULSET     name of the Keycloak StatefulSet        (default: keycloak)
#   KEYCLOAK_CONTAINER       Keycloak container in the StatefulSet   (default: the first container)
#   KEYCLOAK_SPI_IMAGE       tag of the derived image                (default: localhost/keycloak-aiac:local)
#   KEYCLOAK_IMAGE_BASE      stock image to derive from              (default: the live image; on a
#                                                                     re-run, the image recorded by the
#                                                                     first install)
#   KC                       Keycloak base URL                       (default: http://keycloak.localtest.me:8080)
#   REALM                    realm to enable the listener on         (default: rossoctl)
#   KEYCLOAK_ADMIN_USERNAME  master-realm admin user                 (default: see "Admin credentials")
#   KEYCLOAK_ADMIN_PASSWORD  master-realm admin password             (default: see "Admin credentials")
#   AIAC_ENV_FILE            env file to read the two admin values   (default: <repo root>/.env)
#   CONTAINER_RUNTIME        docker | podman                         (default: auto-detect)
#   MAVEN_MIRROR_URL         optional Maven Central mirror (repo.maven.apache.org rate-limits shared IPs)
#
# Admin credentials, for each of the two values: the environment variable, then the env file, then
# secret ${AIAC_NAMESPACE}/keycloak-admin-secret, then `admin`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AIAC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-${KIND_CLUSTER:-rossoctl}}"
AIAC_NAMESPACE="${AIAC_NAMESPACE:-aiac-system}"
KEYCLOAK_NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_STATEFULSET="${KEYCLOAK_STATEFULSET:-keycloak}"
KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-}"
KEYCLOAK_SPI_IMAGE="${KEYCLOAK_SPI_IMAGE:-localhost/keycloak-aiac:local}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
ENV_FILE="${AIAC_ENV_FILE:-$AIAC_DIR/.env}"

LISTENER="aiac-event-listener"
NATS_URL="nats://aiac-event-broker-service.${AIAC_NAMESPACE}.svc.cluster.local:4222"
# Annotations on the StatefulSet (metadata, not the pod template, so they start no rollout). A
# re-run sees the derived image live and derives from the recorded stock image again.
ANN_BASE="aiac.rossoctl.dev/keycloak-base-image"
ANN_SPI="aiac.rossoctl.dev/keycloak-spi-image"

if [ "${KIND_EXPERIMENTAL_PROVIDER:-}" = "podman" ]; then
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
elif ! command -v docker &> /dev/null && command -v podman &> /dev/null; then
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
else
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
fi

TMPFILES=()
# An if, not `[ ... ] && rm`: as the EXIT trap's last command, a false test would become the
# script's exit status.
cleanup() { if [ "${#TMPFILES[@]}" -gt 0 ]; then rm -rf "${TMPFILES[@]}"; fi; }
trap cleanup EXIT

die() { echo "ERROR: $*" >&2; exit 1; }

# Read one key from the env file. The file is parsed, not sourced, so it cannot run code or
# override other variables of this script. A quoted value is taken up to its closing quote; an
# unquoted value loses a trailing ` # comment` and trailing spaces. Prints nothing when the file or
# the key is absent.
dotenv_get() {
  [ -f "$ENV_FILE" ] || return 0
  local v
  v="$(sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=[[:space:]]*//p" "$ENV_FILE" \
         | tail -n 1 | tr -d '\r')"
  case "$v" in
    \"*) v="${v#\"}"; v="${v%%\"*}" ;;
    \'*) v="${v#\'}"; v="${v%%\'*}" ;;
    *)   v="${v%%[[:space:]]#*}"; v="${v%"${v##*[![:space:]]}"}" ;;
  esac
  printf '%s' "$v"
}

# Read one key from the admin secret the AIAC services use. Prints nothing when it is absent.
secret_get() {
  kubectl get secret keycloak-admin-secret -n "$AIAC_NAMESPACE" -o "jsonpath={.data.$1}" 2>/dev/null \
    | base64 -d 2>/dev/null || true
}

# Sets KC_ADMIN_USER and KC_ADMIN_PASSWORD. Precedence: environment variable, env file, secret,
# `admin`.
resolve_admin_credentials() {
  KC_ADMIN_USER="${KEYCLOAK_ADMIN_USERNAME:-$(dotenv_get KEYCLOAK_ADMIN_USERNAME)}"
  KC_ADMIN_USER="${KC_ADMIN_USER:-$(secret_get KEYCLOAK_ADMIN_USERNAME)}"
  KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
  KC_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-$(dotenv_get KEYCLOAK_ADMIN_PASSWORD)}"
  KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-$(secret_get KEYCLOAK_ADMIN_PASSWORD)}"
  KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-admin}"
}

sts_get() {
  kubectl get statefulset "$KEYCLOAK_STATEFULSET" -n "$KEYCLOAK_NAMESPACE" -o "jsonpath=$1" 2>/dev/null || true
}

load_image_to_kind() {
  local image="$1"
  if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    local tar_file
    tar_file="$(mktemp "${TMPDIR:-/tmp}/spi-image.XXXXXX")"
    TMPFILES+=("$tar_file")
    "$CONTAINER_RUNTIME" save "$image" -o "$tar_file"
    kind load image-archive "$tar_file" --name "$CLUSTER_NAME"
    rm -f "$tar_file"
  else
    kind load docker-image "$image" --name "$CLUSTER_NAME"
  fi
}

# Prints the token, or "" when Keycloak is not serving yet. Always exits 0 (also when curl fails
# under pipefail), so the caller's retry loop can poll under `set -e`. -m bounds each call, so the
# loop's deadline holds.
admin_token() {
  curl -s -m 10 -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d "username=${KC_ADMIN_USER}" --data-urlencode "password=${KC_ADMIN_PASSWORD}" \
    -d grant_type=password \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("access_token","") or "")
except Exception: print("")' 2>/dev/null || true
}

echo "==> [1/5] Preflight"
kubectl get statefulset "$KEYCLOAK_STATEFULSET" -n "$KEYCLOAK_NAMESPACE" > /dev/null \
  || die "statefulset/${KEYCLOAK_STATEFULSET} not found in '${KEYCLOAK_NAMESPACE}'"
kubectl get service aiac-event-broker-service -n "$AIAC_NAMESPACE" > /dev/null 2>&1 \
  || echo "    WARNING: no aiac-event-broker-service in '${AIAC_NAMESPACE}'. The listener drops events until the broker exists."

KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-$(sts_get '{.spec.template.spec.containers[0].name}')}"
live_image="$(sts_get "{.spec.template.spec.containers[?(@.name==\"${KEYCLOAK_CONTAINER}\")].image}")"
[ -n "$live_image" ] \
  || die "statefulset/${KEYCLOAK_STATEFULSET} has no container named '${KEYCLOAK_CONTAINER}' (set KEYCLOAK_CONTAINER)"
recorded_base="$(sts_get '{.metadata.annotations.aiac\.rossoctl\.dev/keycloak-base-image}')"
recorded_spi="$(sts_get '{.metadata.annotations.aiac\.rossoctl\.dev/keycloak-spi-image}')"
echo "    container: ${KEYCLOAK_CONTAINER}   live image: ${live_image}"

# Never derive from a derived image, and never guess a Keycloak version: a version older than the
# one that migrated the database is a downgrade that Keycloak does not support.
if [ -n "${KEYCLOAK_IMAGE_BASE:-}" ]; then
  base_image="$KEYCLOAK_IMAGE_BASE"
elif [ "$live_image" != "$KEYCLOAK_SPI_IMAGE" ] && [ "$live_image" != "$recorded_spi" ]; then
  base_image="$live_image"
elif [ -n "$recorded_base" ]; then
  base_image="$recorded_base"
else
  die "the live image ${live_image} is a derived image, and the StatefulSet has no ${ANN_BASE} annotation. Set KEYCLOAK_IMAGE_BASE to the stock Keycloak image."
fi
echo "    stock image: ${base_image}"

echo "==> [2/5] Building the SPI jar in a maven container (no host mvn/java needed)"
mvn_mirror_mount=()
if [ -n "${MAVEN_MIRROR_URL:-}" ]; then
  settings_file="$(mktemp "${TMPDIR:-/tmp}/spi-mvn-settings.XXXXXX.xml")"
  TMPFILES+=("$settings_file")
  cat > "$settings_file" <<SETTINGS
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <mirrors>
    <mirror>
      <id>spi-mirror</id>
      <name>configured Maven mirror</name>
      <url>${MAVEN_MIRROR_URL}</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
SETTINGS
  mvn_mirror_mount=(-v "${settings_file}:/root/.m2/settings.xml:ro")
  echo "    routing Maven Central through mirror: ${MAVEN_MIRROR_URL}"
fi
"$CONTAINER_RUNTIME" run --rm \
  -v "$AIAC_DIR/keycloak-spi":/build -w /build \
  ${mvn_mirror_mount[@]+"${mvn_mirror_mount[@]}"} \
  maven:3.9-eclipse-temurin-17 \
  mvn -B -DskipTests package

# Exclude the shade plugin's pre-shade artifact (original-*.jar): it lacks the bundled jnats
# dependency, so loading it as the SPI would fail at runtime.
jar=$(find "$AIAC_DIR/keycloak-spi/target" -maxdepth 1 -name '*.jar' \
        ! -name 'original-*.jar' ! -name '*-tests.jar' | head -1)
[ -n "$jar" ] || die "no jar found under keycloak-spi/target after mvn package"
echo "    built: ${jar}"

echo "==> [3/5] Deriving ${KEYCLOAK_SPI_IMAGE} from ${base_image}, loading it, patching the StatefulSet"
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/spi-kc-image.XXXXXX")"
TMPFILES+=("$build_dir")
cp "$jar" "$build_dir/aiac-event-listener.jar"
cat > "$build_dir/Dockerfile" <<DOCKERFILE
FROM ${base_image}
COPY aiac-event-listener.jar /opt/keycloak/providers/aiac-event-listener.jar
RUN /opt/keycloak/bin/kc.sh build
DOCKERFILE

"$CONTAINER_RUNTIME" build -t "$KEYCLOAK_SPI_IMAGE" "$build_dir"
load_image_to_kind "$KEYCLOAK_SPI_IMAGE"

# One strategic-merge patch, so the pod template changes once and Keycloak restarts once. The
# containers and env lists merge by name: other containers and other env vars stay as they are.
# The listener default NATS_URL is the bare service name. It resolves only inside the querying
# pod's own namespace. Keycloak runs in ${KEYCLOAK_NAMESPACE}, the broker in ${AIAC_NAMESPACE}.
patch=$(python3 -c 'import json,sys
c, img, nats, ann_base, base, ann_spi = sys.argv[1:]
print(json.dumps({
  "metadata": {"annotations": {ann_base: base, ann_spi: img}},
  "spec": {"template": {"spec": {"containers": [
    {"name": c, "image": img, "env": [{"name": "NATS_URL", "value": nats}]}]}}}}))' \
  "$KEYCLOAK_CONTAINER" "$KEYCLOAK_SPI_IMAGE" "$NATS_URL" "$ANN_BASE" "$base_image" "$ANN_SPI")
gen_before="$(sts_get '{.metadata.generation}')"
kubectl patch "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" --type=strategic -p "$patch"
gen_after="$(sts_get '{.metadata.generation}')"
# A re-run with the same tag leaves the template as it was, so no rollout starts. Restart, so the
# pod loads the image that kind just put on the node.
if [ "$gen_before" = "$gen_after" ]; then
  echo "    pod template unchanged (same image tag): restarting to load the new image"
  kubectl rollout restart "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE"
fi
kubectl rollout status "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" --timeout=300s

echo "==> [4/5] Enabling the listener on realm '${REALM}'"
resolve_admin_credentials
# Rollout status returns at readiness, but the master-realm token endpoint can warm up for several
# more seconds. Poll until it serves.
admin=""
deadline=$((SECONDS + 120))
while :; do
  admin=$(admin_token)
  [ -n "$admin" ] && break
  [ "$SECONDS" -lt "$deadline" ] \
    || die "no Keycloak master admin token within 120s of the rollout (check KC, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD)"
  echo "    waiting for Keycloak's token endpoint..."
  sleep 5
done

# Read-modify-write: a PUT replaces the whole events config, so start from the live one. That keeps
# the other listeners, the stored user events and their expiration.
config=$(curl -s -f -m 10 -H "Authorization: Bearer ${admin}" "${KC}/admin/realms/${REALM}/events/config" || true)
body=$(printf '%s' "$config" | python3 -c 'import sys,json
c = json.load(sys.stdin)
listeners = c.get("eventsListeners") or []
if sys.argv[1] not in listeners: listeners.append(sys.argv[1])
c["eventsListeners"] = listeners
c["adminEventsEnabled"] = True
print(json.dumps(c))' "$LISTENER" 2>/dev/null || true)
[ -n "$body" ] || die "could not read the events config of realm '${REALM}' from ${KC}"
http=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -X PUT \
  -H "Authorization: Bearer ${admin}" -H "Content-Type: application/json" \
  "${KC}/admin/realms/${REALM}/events/config" -d "$body" || true)
echo "    events/config HTTP ${http}"
[ "$http" = "204" ] || die "enabling ${LISTENER} on realm '${REALM}' returned HTTP ${http:-<none>} (expected 204)"

echo "==> [5/5] Verifying (keycloak-spi-verify.sh)"
CLUSTER_NAME="$CLUSTER_NAME" AIAC_NAMESPACE="$AIAC_NAMESPACE" \
  KEYCLOAK_NAMESPACE="$KEYCLOAK_NAMESPACE" KEYCLOAK_STATEFULSET="$KEYCLOAK_STATEFULSET" \
  KEYCLOAK_CONTAINER="$KEYCLOAK_CONTAINER" KEYCLOAK_SPI_IMAGE="$KEYCLOAK_SPI_IMAGE" \
  KC="$KC" REALM="$REALM" AIAC_ENV_FILE="$ENV_FILE" \
  KEYCLOAK_ADMIN_USERNAME="$KC_ADMIN_USER" KEYCLOAK_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD" \
  "$SCRIPT_DIR/keycloak-spi-verify.sh"
