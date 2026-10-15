#!/usr/bin/env bash
# keycloak-spi-verify.sh — checks that the AIAC Keycloak event-listener SPI is installed. Read-only.
#
# Prints each check and the result it obtained, and FAILS with a clear message the moment an
# observed result does not match the expectation (instead of silently continuing).
#
# keycloak-spi-install.sh sets up what this checks; run this on its own to check an already
# installed cluster. It changes nothing.
#
# Checks:
#   Preflight  kubectl present, cluster reachable, Keycloak StatefulSet present
#   Verify 1   the Keycloak container runs the derived image (KEYCLOAK_SPI_IMAGE, the one with the SPI jar)
#   Verify 2   NATS_URL on the Keycloak container is the cross-namespace broker address
#   Verify 3   the Keycloak pod is Ready and has the SPI jar in /opt/keycloak/providers
#   Verify 4   the realm lists 'aiac-event-listener' in eventsListeners, and admin events are on
#
# Requires: kubectl, curl, python3 (kind, only to re-export a stale kubeconfig).
# Env vars (the same names and defaults as keycloak-spi-install.sh):
#   CLUSTER_NAME             name of the Kind cluster                (default: $KIND_CLUSTER, else rossoctl)
#   KEYCLOAK_NAMESPACE       namespace Keycloak runs in              (default: keycloak)
#   KEYCLOAK_STATEFULSET     name of the Keycloak StatefulSet        (default: keycloak)
#   KEYCLOAK_CONTAINER       Keycloak container in the StatefulSet   (default: the first container)
#   AIAC_NAMESPACE           namespace of the AIAC event broker      (default: aiac-system)
#   KEYCLOAK_SPI_IMAGE       expected derived Keycloak image         (default: localhost/keycloak-aiac:local)
#   KC                       Keycloak base URL                       (default: http://keycloak.localtest.me:8080)
#   REALM                    realm that must have the listener       (default: rossoctl)
#   KEYCLOAK_ADMIN_USERNAME  master-realm admin user                 (default: see "Admin credentials")
#   KEYCLOAK_ADMIN_PASSWORD  master-realm admin password             (default: see "Admin credentials")
#   AIAC_ENV_FILE            env file to read the two admin values   (default: <repo root>/.env)
#
# Admin credentials, for each of the two values: the environment variable, then the env file, then
# secret ${AIAC_NAMESPACE}/keycloak-admin-secret, then `admin`.
#
# Usage:
#   ./k8s/keycloak-spi-verify.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AIAC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-${KIND_CLUSTER:-rossoctl}}"
KEYCLOAK_NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_STATEFULSET="${KEYCLOAK_STATEFULSET:-keycloak}"
KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-}"
AIAC_NAMESPACE="${AIAC_NAMESPACE:-aiac-system}"
KEYCLOAK_SPI_IMAGE="${KEYCLOAK_SPI_IMAGE:-localhost/keycloak-aiac:local}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
ENV_FILE="${AIAC_ENV_FILE:-$AIAC_DIR/.env}"

LISTENER="aiac-event-listener"
JAR_PATH="/opt/keycloak/providers/aiac-event-listener.jar"
EXPECT_NATS_URL="nats://aiac-event-broker-service.${AIAC_NAMESPACE}.svc.cluster.local:4222"
INSTALL_HINT="run k8s/keycloak-spi-install.sh"

# ── Output helpers ──────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'
  C_CYN=$'\033[36m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_CYN=""; C_BLD=""; C_RST=""
fi

STEP_N=0
step() { STEP_N=$((STEP_N + 1)); printf '\n%s==> [%02d] %s%s\n' "$C_BLD$C_CYN" "$STEP_N" "$*" "$C_RST"; }
info() { printf '     %s\n' "$*"; }
pass() { printf '     %sPASS%s %s\n' "$C_GRN" "$C_RST" "$*"; }
die()  { printf '\n%sFAIL:%s %s\n' "$C_RED$C_BLD" "$C_RST" "$*" >&2; exit 1; }

# expect_eq <label> <got> <want> <hint>  — pass or die
expect_eq() {
  local label="$1" got="$2" want="$3" hint="${4:-}"
  if [ "$got" = "$want" ]; then
    pass "${label}: got '${got}' (expected '${want}')"
  else
    die "${label}: got '${got}', expected '${want}'${hint:+ — $hint}"
  fi
}

# Read one key from the env file. The file is parsed, not sourced, so it cannot run code or
# override other variables of this script. A quoted value is taken up to its closing quote; an
# unquoted value loses a trailing ` # comment` and trailing spaces. Prints nothing when the file or
# the key is absent. The same parser as keycloak-spi-install.sh.
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

# Prints the token, or "" when Keycloak does not answer. Always exits 0.
admin_token() {
  curl -s -m 10 -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d "username=${KC_ADMIN_USER}" --data-urlencode "password=${KC_ADMIN_PASSWORD}" \
    -d grant_type=password \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("access_token","") or "")
except Exception: print("")' 2>/dev/null || true
}

# ── Preflight ────────────────────────────────────────────────────────────────
printf '%s%sKeycloak SPI — verify%s\n' "$C_BLD" "$C_CYN" "$C_RST"
info "statefulset: ${KEYCLOAK_NAMESPACE}/${KEYCLOAK_STATEFULSET}   realm: ${REALM}   image: ${KEYCLOAK_SPI_IMAGE}"

step "Preflight — kubectl and cluster"
command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"
# A Kind node reassigns its API-server host port on restart, which leaves the exported kubeconfig
# stale. Re-export it once before giving up.
if ! kubectl cluster-info >/dev/null 2>&1; then
  if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    info "cluster unreachable — re-exporting kubeconfig for Kind cluster '${CLUSTER_NAME}'"
    kind export kubeconfig --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
  kubectl cluster-info >/dev/null 2>&1 \
    || die "kubectl cannot reach a cluster (try: kind export kubeconfig --name ${CLUSTER_NAME})"
fi
kubectl get statefulset "$KEYCLOAK_STATEFULSET" -n "$KEYCLOAK_NAMESPACE" >/dev/null 2>&1 \
  || die "statefulset/${KEYCLOAK_STATEFULSET} not found in '${KEYCLOAK_NAMESPACE}' — the rossoctl platform install creates it"
KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-$(sts_get '{.spec.template.spec.containers[0].name}')}"
[ -n "$KEYCLOAK_CONTAINER" ] || die "statefulset/${KEYCLOAK_STATEFULSET} has no containers"
pass "cluster reachable, statefulset/${KEYCLOAK_STATEFULSET} present, container '${KEYCLOAK_CONTAINER}'"

# ── Verify 1 — derived image ─────────────────────────────────────────────────
step "Verify 1 — Keycloak runs the image with the SPI"
LIVE_IMAGE=$(sts_get "{.spec.template.spec.containers[?(@.name==\"${KEYCLOAK_CONTAINER}\")].image}")
expect_eq "Keycloak image" "${LIVE_IMAGE:-<none>}" "$KEYCLOAK_SPI_IMAGE" "$INSTALL_HINT"

# ── Verify 2 — NATS_URL ──────────────────────────────────────────────────────
step "Verify 2 — NATS_URL points at the broker in ${AIAC_NAMESPACE}"
LIVE_NATS=$(sts_get "{.spec.template.spec.containers[?(@.name==\"${KEYCLOAK_CONTAINER}\")].env[?(@.name==\"NATS_URL\")].value}")
expect_eq "NATS_URL" "${LIVE_NATS:-<unset>}" "$EXPECT_NATS_URL" \
  "the bare default service name does not resolve from ${KEYCLOAK_NAMESPACE}; ${INSTALL_HINT}"

# ── Verify 3 — pod Ready, jar present ────────────────────────────────────────
step "Verify 3 — Keycloak pod Ready, SPI jar present"
kubectl rollout status "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" --timeout=120s >/dev/null 2>&1 \
  || die "statefulset/${KEYCLOAK_STATEFULSET} is not rolled out (Ready) within 120s. Check: kubectl describe pod -n ${KEYCLOAK_NAMESPACE}"
pass "statefulset/${KEYCLOAK_STATEFULSET} rolled out"
if kubectl exec -n "$KEYCLOAK_NAMESPACE" "${KEYCLOAK_STATEFULSET}-0" -c "$KEYCLOAK_CONTAINER" -- test -f "$JAR_PATH" >/dev/null 2>&1; then
  pass "${JAR_PATH} exists in ${KEYCLOAK_STATEFULSET}-0"
else
  die "${JAR_PATH} is missing in ${KEYCLOAK_STATEFULSET}-0 — ${INSTALL_HINT}"
fi

# ── Verify 4 — listener enabled on the realm ─────────────────────────────────
step "Verify 4 — '${LISTENER}' enabled on realm '${REALM}'"
resolve_admin_credentials
TOKEN=$(admin_token)
[ -n "$TOKEN" ] || die "no master admin token from ${KC} (is Keycloak reachable? set KC, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD)"
CONFIG=$(curl -s -m 10 -H "Authorization: Bearer ${TOKEN}" "${KC}/admin/realms/${REALM}/events/config" || true)
LISTENERS=$(printf '%s' "$CONFIG" | python3 -c 'import sys,json
try: print(" ".join(json.load(sys.stdin).get("eventsListeners") or []))
except Exception: print("")' 2>/dev/null || true)
ADMIN_EVENTS=$(printf '%s' "$CONFIG" | python3 -c 'import sys,json
try: print(str(json.load(sys.stdin).get("adminEventsEnabled")).lower())
except Exception: print("")' 2>/dev/null || true)
case " ${LISTENERS} " in
  *" ${LISTENER} "*) pass "eventsListeners of '${REALM}': '${LISTENERS}' lists ${LISTENER}" ;;
  *) die "eventsListeners of '${REALM}': got '${LISTENERS:-<none>}', expected it to list ${LISTENER} — ${INSTALL_HINT}" ;;
esac
expect_eq "adminEventsEnabled" "${ADMIN_EVENTS:-<none>}" "true" "$INSTALL_HINT"

printf '\n%s%s====== ALL CHECKS PASSED ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
info "The ${LISTENER} SPI is installed in ${KEYCLOAK_NAMESPACE}/${KEYCLOAK_STATEFULSET} and enabled on realm '${REALM}'."
