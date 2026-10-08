#!/usr/bin/env bash
# opa-kind-verify.sh — k8s/opa-kind-runbook.md "Verify", automated. Read-only.
#
# Checks that OPA is wired into the AuthBridge pipeline and that bundle-service
# is serving policy, printing each check and the result it obtained, and FAILS
# with a clear message the moment an observed result does not match the
# runbook's stated expectation (instead of silently continuing).
#
# opa-kind-enable.sh runs this as its last step; run it on its own to check an
# already-enabled cluster. It changes nothing — the only thing it creates is a
# throwaway curl pod, removed when the probe exits.
#
# Workload-agnostic: it needs no agent, tool, user or policy CR. Anything that
# exercises a real policy belongs to a use case (e.g. demo/use-cases/onboarding).
#
# Checks, mirroring the runbook 1:1:
#   Preflight  kubectl present, cluster reachable, agent namespace present
#   Verify 1   'name: opa' appears twice in authbridge-runtime-config (both legs)
#   Verify 2   AuthorizationPolicy CRD established + global 'default' CR present
#   Verify 3   bundle-service pod Running
#   Verify 4   from a throwaway pod in the agent namespace: /readyz 200, /bundles 200
#   Verify 5   every existing agent pod's authbridge-proxy runs IMAGE_TAG and is
#              Ready (skipped when the namespace has no agent pods)
#
# Requires: kubectl (kind, only to re-export a stale kubeconfig).
# Env vars (runbook defaults shown):
#   NS             agent namespace                        (default: team1)
#   SYS_NS         platform namespace                     (default: rossoctl-system)
#   TRUST_DOMAIN   SPIFFE trust domain for the bundle probe (default: localtest.me)
#   IMAGE_TAG      expected authbridge sidecar image      (default: localhost/authbridge:local)
#   READY_SECS     max seconds to wait for bundle-service readiness (default: 120)
#   KIND_CLUSTER   name of the Kind cluster                (default: rossoctl).
#                  Preflight uses this to re-export the kubeconfig if the cluster
#                  is unreachable — a Kind node reassigns its API-server host port
#                  on restart, which leaves the exported kubeconfig stale.
#
# Usage:
#   ./k8s/opa-kind-verify.sh

set -euo pipefail

NS="${NS:-team1}"
SYS_NS="${SYS_NS:-rossoctl-system}"
TRUST_DOMAIN="${TRUST_DOMAIN:-localtest.me}"
IMAGE_TAG="${IMAGE_TAG:-localhost/authbridge:local}"
READY_SECS="${READY_SECS:-120}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"

AGENT_LABEL="rossoctl.io/type=agent"
BUNDLE_URL="http://bundle-service.${SYS_NS}.svc.cluster.local:8080"

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

# expect_eq <label> <got> <want>  — pass or die
expect_eq() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    pass "${label}: got '${got}' (expected '${want}')"
  else
    die "${label}: got '${got}', expected '${want}'"
  fi
}

# probe_bundle_service  — from a throwaway pod in the agent namespace, print
# "readyz <code>" and "bundle <code>" for bundle-service (runbook Verify 4).
probe_bundle_service() {
  kubectl run "opa-probe-$RANDOM" --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
    -n "$NS" --env="BS=${BUNDLE_URL}" \
    --env="SPIFFE=${TRUST_DOMAIN}/ns/${NS}/sa/opa-probe" -- sh -c \
    'curl -s -m 10 -o /dev/null -w "readyz %{http_code}\n" "$BS/readyz"
     curl -s -m 10 -o /dev/null -w "bundle %{http_code}\n" "$BS/bundles?spiffe=$SPIFFE"' \
    2>/dev/null || true
}

# ── Preflight ────────────────────────────────────────────────────────────────
printf '%s%sOPA on Kind — verify%s\n' "$C_BLD" "$C_CYN" "$C_RST"
info "runbook: k8s/opa-kind-runbook.md   agent namespace: ${NS}   platform namespace: ${SYS_NS}"

step "Preflight — kubectl and cluster"
command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"
# A Kind node container reassigns its API-server host port on restart, which
# leaves the previously exported kubeconfig pointing at a stale port ("connection
# refused"). If the cluster is unreachable but the named Kind cluster exists,
# re-export its kubeconfig and retry before giving up — self-heals the common
# "cluster was restarted" case instead of failing preflight.
if ! kubectl cluster-info >/dev/null 2>&1; then
  if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
    info "cluster unreachable — re-exporting kubeconfig for Kind cluster '${KIND_CLUSTER}' (API-server host port may have changed on restart)"
    kind export kubeconfig --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
  fi
  kubectl cluster-info >/dev/null 2>&1 \
    || die "kubectl cannot reach a cluster (is the Kind cluster '${KIND_CLUSTER}' up and KUBECONFIG set? try: kind export kubeconfig --name ${KIND_CLUSTER})"
fi
kubectl get namespace "$NS" >/dev/null 2>&1 \
  || die "agent namespace '${NS}' does not exist — the rossoctl platform install creates it"
pass "cluster reachable, namespace ${NS} present"

# ── Verify 1 — OPA in both legs ──────────────────────────────────────────────
step "Verify 1 — OPA wired into both pipeline legs"
OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
              -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
[ "$OPA_COUNT" = "2" ] \
  || die "'name: opa' occurrences in authbridge-runtime-config: got '${OPA_COUNT}', expected '2' — run k8s/opa-kind-enable.sh"
pass "'name: opa' occurrences in authbridge-runtime-config: got '2' (expected '2')"

# ── Verify 2 — CRD + global policy ───────────────────────────────────────────
step "Verify 2 — AuthorizationPolicy CRD and the shipped global policy"
kubectl wait --for=condition=established --timeout=30s \
  crd/authorizationpolicies.agent.rossoctl.dev >/dev/null 2>&1 \
  || die "CRD authorizationpolicies.agent.rossoctl.dev is not established"
pass "CRD authorizationpolicies.agent.rossoctl.dev established"
GLOBAL_SCOPE=$(kubectl get authorizationpolicy default -n "$SYS_NS" \
                 -o jsonpath='{.spec.scope}' 2>/dev/null || true)
expect_eq "global AuthorizationPolicy 'default' scope in ${SYS_NS}" "${GLOBAL_SCOPE:-<none>}" "global"

# ── Verify 3 — bundle-service Running ────────────────────────────────────────
step "Verify 3 — bundle-service pod Running"
BS_PHASE=$(kubectl get pods -n "$SYS_NS" -l app=bundle-service \
             -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)
expect_eq "bundle-service pod phase" "${BS_PHASE:-<none>}" "Running"

# ── Verify 4 — bundle-service serves bundles to the agent namespace ──────────
step "Verify 4 — bundle-service ready and serving a bundle (probe from ${NS}) [up to ${READY_SECS}s]"
# /readyz and /bundles return 503 until the service's informer has synced, so
# poll rather than assert once.
DEADLINE=$((SECONDS + READY_SECS))
while :; do
  OUT="$(probe_bundle_service)"
  READYZ=$(printf '%s\n' "$OUT" | sed -n 's/^readyz //p' | tail -1)
  BUNDLE=$(printf '%s\n' "$OUT" | sed -n 's/^bundle //p' | tail -1)
  [ "$READYZ" = "200" ] && [ "$BUNDLE" = "200" ] && break
  if [ "$SECONDS" -ge "$DEADLINE" ]; then
    die "bundle-service probe from ${NS}: readyz=${READYZ:-none} bundle=${BUNDLE:-none}, expected 200/200 after ${READY_SECS}s (000 = unreachable from ${NS}; 503 = informer not synced)"
  fi
  info "readyz=${READYZ:-none} bundle=${BUNDLE:-none} — retrying..."
  sleep 5
done
pass "GET /readyz -> 200, GET /bundles?spiffe=${TRUST_DOMAIN}/ns/${NS}/sa/opa-probe -> 200"

# ── Verify 5 — existing agent sidecars run the built image ───────────────────
step "Verify 5 — existing agent pods run the OPA-capable sidecar"
PODS=$(kubectl get pods -n "$NS" -l "$AGENT_LABEL" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
if [ -z "$PODS" ]; then
  info "no pods labelled ${AGENT_LABEL} in ${NS} — nothing to check; workloads deployed later get the OPA pipeline from the operator webhook"
else
  for pod in $PODS; do
    kubectl wait --for=condition=ready pod -n "$NS" "$pod" --timeout=180s >/dev/null 2>&1 \
      || die "agent pod ${pod} did not become Ready within 180s. Check: kubectl describe pod -n ${NS} ${pod}"
    IMG=$(kubectl get pod -n "$NS" "$pod" \
            -o jsonpath='{.spec.containers[?(@.name=="authbridge-proxy")].image}' 2>/dev/null || true)
    expect_eq "${pod} authbridge-proxy image" "${IMG:-<no authbridge-proxy container>}" "$IMAGE_TAG"
  done
fi

printf '\n%s%s====== ALL CHECKS PASSED ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
info "OPA is in both AuthBridge legs in ${NS}; bundle-service in ${SYS_NS} is serving bundles."
