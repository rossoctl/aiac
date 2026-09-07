#!/usr/bin/env bash
# uc1-e2e-driver.sh — deploying github-agent/github-tool for the FIRST TIME is the live trigger.
#
# Unlike aiac/demo/use-cases/uc1-integration/uc1-integration-driver.sh (which forces a fresh
# CLIENT_CREATE by deleting already-registered Keycloak clients via the Admin API and restarting
# pods), this demo proves the live-trigger path with a genuine new-agent onboarding: the operator's
# AgentRuntimeReconciler stamps rossoctl.io/type=agent|tool onto a Deployment's pod-template the
# first time its AgentRuntime CR resolves, and THAT label is what the ClientRegistrationReconciler's
# watch predicate keys on — so the very first `kubectl apply` of github-agent/github-tool's
# manifests (via demo/assets/install.sh, unmodified) is itself the trigger. No curl-based client
# deletion, no clone of the agent, no manual POST /apply/service/{id} call anywhere in this script.
#
#   Phase DEPLOY          kubectl-apply github-agent/github-tool for the first time — THE trigger.
#   Phase VERIFY-TRIGGER  poll Keycloak for the brand-new clients, aiac-agent logs for evidence it
#                         consumed both over NATS, and the AuthorizationPolicy CR AIAC wrote.
#   Phase WIRE            wire AuthBridge's own outbound leg (authproxy-routes + optional
#                         client-scope) — same two sub-steps as aiac/k8s/opa-kind-runbook.md Part
#                         B.1/B.2; AIAC's own onboarding does not do this.
#   Phase ENFORCE         real HTTP probes through the live AuthBridge OPA plugin, reproducing
#                         #646's acceptance table.
#
# Style mirrors uc1-integration-driver.sh: step()/pass()/warn()/die(), fails loudly and
# specifically the moment an observed result doesn't match, rather than continuing silently.
#
# Usage:
#   ./uc1-e2e-driver.sh                    # deploy -> verify-trigger -> wire -> enforce
#   ./uc1-e2e-driver.sh --only-deploy
#   ./uc1-e2e-driver.sh --only-wire-outbound
#   ./uc1-e2e-driver.sh --only-enforce
#   ./uc1-e2e-driver.sh --collect-logs     # (composes with any of the above) dump every
#                                          # component's logs into a per-run directory at the end,
#                                          # AND on any die() failure — so a failed run is
#                                          # debuggable without re-running. Time-scoped to this run.
#
# Env vars (defaults match the rest of this demo family):
#   NS, SYS_NS, AIAC_NS   namespaces (team1, rossoctl-system, aiac-system)
#   KC, REALM             Keycloak base URL + realm
#   ROPC_CLIENT_ID        OIDC client the demo users log in through (default: rossoctl). Must be a
#                         client AIAC's inbound rego accepts as the source (its source_ok allows the
#                         "rossoctl" platform client) AND whose tokens carry the workload audiences +
#                         a username->sub claim. The rossoctl platform client is provisioned with all
#                         of that (username->sub mapper, agent-team1-github-{agent,tool}-aud default
#                         scopes, Direct Access Grants) by the rossoctl installer; aiac-demo-cli (the
#                         uc1-onboarding run-*.py client) is NOT accepted by source_ok, so inbound
#                         probes through it are denied with the wrong azp.
#   USER_PASSWORD         shared demo-user password (default: password) — see scenario.py
#   POLL_SECS             max seconds a polling phase waits for trigger evidence / a bundle-service
#                         poll (default: 420). Sized for the slowest convergence: the agent publishes
#                         its A2A AgentCard skills only AFTER the deploy trigger, so onboarding
#                         redelivers (JetStream) for a few minutes until source_operations/
#                         issue_operations resolve and AIAC writes the AuthorizationPolicy CR. Each
#                         phase still breaks the instant its condition is met, so a healthy run is fast.
#   DEPLOY_WAIT_SECS      max seconds to wait for pods to become Ready after deploy   (default: 180)
#   KIND_CLUSTER          name of the Kind cluster                             (default: rossoctl)
#   KC_NS                 namespace Keycloak runs in, for --collect-logs       (default: keycloak)
#   COLLECT_ROOT          parent dir for --collect-logs run directories        (default: /tmp)
#   COLLECT_SINCE         RFC3339 timestamp to scope collected component logs from. Overrides the
#                         default absolutely; set an earlier timestamp to widen the window further.
#   COLLECT_LOOKBACK_MIN  minutes before run-start the default collection window opens (default: 10)
#                         — the margin ensures a die() on an early/instant failure still captures
#                         recent history instead of an empty window.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORTEX_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSETS_DIR="$CORTEX_DIR/aiac/demo/assets"

NS="${NS:-team1}"
SYS_NS="${SYS_NS:-rossoctl-system}"
AIAC_NS="${AIAC_NS:-aiac-system}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
ROPC_CLIENT_ID="${ROPC_CLIENT_ID:-rossoctl}"
USER_PASSWORD="${USER_PASSWORD:-password}"
POLL_SECS="${POLL_SECS:-420}"
DEPLOY_WAIT_SECS="${DEPLOY_WAIT_SECS:-180}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"
KC_NS="${KC_NS:-keycloak}"
COLLECT_ROOT="${COLLECT_ROOT:-/tmp}"

# Recorded once, up front, so both the end-of-run collection and any die()-triggered collection
# scope component logs to this invocation (COLLECT_SINCE overrides — see the header docs).
RUN_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
TOOL_LABEL="app=github-tool"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

DO_DEPLOY=1
DO_WIRE=1
DO_ENFORCE=1
DO_COLLECT=0
COLLECT_DIR=""
# Args compose: at most one --only-* phase selector, optionally plus --collect-logs.
for arg in "$@"; do
  case "$arg" in
    --only-deploy) DO_WIRE=0; DO_ENFORCE=0 ;;
    --only-wire-outbound) DO_DEPLOY=0; DO_ENFORCE=0 ;;
    --only-enforce) DO_DEPLOY=0; DO_WIRE=0 ;;
    --collect-logs) DO_COLLECT=1 ;;
    "") ;;
    *) echo "Usage: $0 [--only-deploy|--only-wire-outbound|--only-enforce] [--collect-logs]" >&2; exit 1 ;;
  esac
done
# Fix the destination once, so the end-of-run and die()-path collections write to the same directory.
[ "$DO_COLLECT" -eq 1 ] && COLLECT_DIR="${COLLECT_ROOT}/uc1-e2e-logs-$(date -u +%Y%m%dT%H%M%SZ)"

# ── Output helpers (same palette/shape as uc1-integration-driver.sh) ───────
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_CYN=$'\033[36m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BLD=""; C_RST=""
fi

STEP_N=0
step() { STEP_N=$((STEP_N + 1)); printf '\n%s==> [%02d] %s%s\n' "$C_BLD$C_CYN" "$STEP_N" "$*" "$C_RST"; }
info() { printf '     %s\n' "$*"; }
pass() { printf '     %sPASS%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '     %sWARN%s %s\n' "$C_YEL" "$C_RST" "$*"; }
die()  {
  printf '\n%sFAIL:%s %s\n' "$C_RED$C_BLD" "$C_RST" "$*" >&2
  # Best-effort log capture on failure — the most valuable time to have it. Guarded so a
  # collection hiccup can't mask the original failure; we still exit non-zero regardless.
  [ "${DO_COLLECT:-0}" -eq 1 ] && collect_logs "$COLLECT_DIR" || true
  exit 1
}

expect_eq() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then pass "${label}: got '${got}' (expected '${want}')"
  else die "${label}: got '${got}', expected '${want}'"; fi
}

# ── Keycloak admin helpers ───────────────────────────────────────────────────
admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'
}

mint_token() {
  local user="$1"
  curl -s -X POST "${KC}/realms/${REALM}/protocol/openid-connect/token" \
    -d client_id="$ROPC_CLIENT_ID" -d "username=${user}" -d "password=${USER_PASSWORD}" \
    -d grant_type=password \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("access_token","") or "")
except Exception: print("")'
}

# client_uuid_by_name <name> <admin_token> — Keycloak clients are looked up by the "name" DISPLAY
# field (e.g. "team1/github-agent"), not clientId. Prints "" if not found (caller checks).
client_uuid_by_name() {
  local name="$1" admin="$2"
  curl -s -H "Authorization: Bearer ${admin}" "${KC}/admin/realms/${REALM}/clients" \
    | CLIENT_NAME="$name" python3 -c '
import sys, json, os
name = os.environ["CLIENT_NAME"]
for c in json.load(sys.stdin):
    if c.get("name") == name:
        print(c["id"]); break
'
}

latest_pod() {
  kubectl get pod -n "$NS" -l "$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# ── Log collection (--collect-logs) ────────────────────────────────────────────
# Dumps every component this demo touches into one per-run directory: the operator (client
# registration), aiac-agent (onboarding pipeline), the NATS broker, Keycloak (SPI listener), and the
# github-agent sidecar (the OPA allow/deny decisions) + app container + github-tool. Component logs
# are time-scoped to this run (COLLECT_SINCE / RUN_START_TS) so log volume can't push evidence out of
# view — the same reasoning phase_verify_trigger uses for --since-time over --tail. Durable state
# (the AuthorizationPolicy CR, the routing/runtime ConfigMaps, pod listings) is captured as
# point-in-time snapshots. Every command is best-effort: a missing component leaves a note in its
# file rather than aborting, so this is safe to call from die() mid-failure.
collect_logs() {
  local dir="${1:-$COLLECT_ROOT/uc1-e2e-logs-$(date -u +%Y%m%dT%H%M%SZ)}"
  # Default window: RUN_START_TS minus COLLECT_LOOKBACK_MIN (default 10m). The margin matters for the
  # die() path — an early/instant failure would otherwise pin --since-time to the run-start instant
  # and capture an EMPTY window (exactly when the logs are most wanted). A little pre-run history is
  # harmless for the success path. COLLECT_SINCE overrides this absolutely.
  local margin_min="${COLLECT_LOOKBACK_MIN:-10}" default_since
  default_since="$(date -u -d "@$(( $(date -u -d "$RUN_START_TS" +%s 2>/dev/null || date -u +%s) - margin_min * 60 ))" \
    +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$RUN_START_TS")"
  local since="${COLLECT_SINCE:-$default_since}"
  if ! mkdir -p "$dir" 2>/dev/null; then warn "could not create log dir ${dir} — skipping collection"; return 0; fi
  printf '\n%s==> Collecting logs into %s (component logs since %s)%s\n' "$C_BLD$C_CYN" "$dir" "$since" "$C_RST"

  # <outfile> <kubectl-logs-args...> — time-scoped component logs; note on absence, never abort.
  _dump() {
    local out="$1"; shift
    kubectl logs "$@" --since-time="$since" >"${dir}/${out}" 2>&1 \
      || echo "(unavailable — component absent, or no logs since ${since})" >"${dir}/${out}"
  }
  _dump operator-controller-manager.log deployment/rossoctl-controller-manager -n "$SYS_NS"
  _dump aiac-agent.log                  deployment/aiac-agent                  -n "$AIAC_NS"
  _dump aiac-event-broker.log           deployment/aiac-event-broker           -n "$AIAC_NS"
  _dump keycloak.log                    statefulset/keycloak                   -n "$KC_NS"

  local agent_pod tool_pod
  agent_pod="$(latest_pod "$AGENT_LABEL" || true)"
  tool_pod="$(latest_pod "$TOOL_LABEL" || true)"
  if [ -n "$agent_pod" ]; then
    _dump github-agent-authbridge-proxy.log -n "$NS" "$agent_pod" -c authbridge-proxy  # OPA decisions
    _dump github-agent-app.log              -n "$NS" "$agent_pod" -c agent
  else
    echo "(github-agent pod not found)" >"${dir}/github-agent-authbridge-proxy.log"
  fi
  if [ -n "$tool_pod" ]; then
    _dump github-tool.log -n "$NS" "$tool_pod" --all-containers
  else
    echo "(github-tool pod not found)" >"${dir}/github-tool.log"
  fi

  # Point-in-time snapshots of the durable artifacts (not time-scoped — current observed state).
  kubectl get "$POLICY_CR" github-agent -n "$NS" -o yaml \
    >"${dir}/authorizationpolicy-github-agent.yaml" 2>&1 || true
  kubectl get configmap authproxy-routes -n "$NS" -o yaml \
    >"${dir}/cm-authproxy-routes.yaml" 2>&1 || true
  kubectl get configmap authbridge-runtime-config -n "$NS" -o yaml \
    >"${dir}/cm-authbridge-runtime-config.yaml" 2>&1 || true
  kubectl get pods -n "$NS" -o wide      >"${dir}/pods-${NS}.txt" 2>&1 || true
  kubectl get pods -n "$AIAC_NS" -o wide >"${dir}/pods-${AIAC_NS}.txt" 2>&1 || true

  pass "logs collected: ${dir}"
  ls -1 "$dir" 2>/dev/null | sed 's/^/       /' || true
}

# ── Preflight ────────────────────────────────────────────────────────────────
printf '%s%sUC-1 E2E driver (deploying the agent IS the live trigger)%s\n' "$C_BLD" "$C_CYN" "$C_RST"

step "Preflight"
for c in kubectl curl python3; do
  command -v "$c" >/dev/null 2>&1 || die "missing required command on PATH: $c"
done
if ! kubectl cluster-info >/dev/null 2>&1; then
  if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
    info "cluster unreachable — re-exporting kubeconfig for Kind cluster '${KIND_CLUSTER}'"
    kind export kubeconfig --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
  fi
  kubectl cluster-info >/dev/null 2>&1 || die "kubectl cannot reach a cluster"
fi
kubectl get deployment aiac-agent -n "$AIAC_NS" >/dev/null 2>&1 \
  || die "aiac-agent not deployed in ${AIAC_NS} — run uc1-e2e-enable.sh --stack-only first"
kubectl get deployment aiac-event-broker -n "$AIAC_NS" >/dev/null 2>&1 \
  || die "aiac-event-broker not deployed in ${AIAC_NS} — run uc1-e2e-enable.sh --broker-only first"
OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
              -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
[ "$OPA_COUNT" = "2" ] || die "OPA not wired into both AuthBridge legs (got ${OPA_COUNT}, expected 2) — run aiac/k8s/opa-kind-enable.sh first"
ADMIN="$(admin_token)"
[ -n "$ADMIN" ] || die "could not obtain a Keycloak master admin token"
LISTENERS=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/events/config" \
  | python3 -c 'import sys,json;print(",".join(json.load(sys.stdin).get("eventsListeners",[])))' 2>/dev/null || true)
case "$LISTENERS" in
  *aiac-event-listener*) ;;
  *) die "aiac-event-listener not enabled on realm '${REALM}' (listeners: ${LISTENERS:-<none>}) — run uc1-e2e-enable.sh --spi-only first" ;;
esac
if [ "$DO_DEPLOY" -eq 1 ]; then
  if kubectl get deployment github-agent -n "$NS" >/dev/null 2>&1 || kubectl get deployment github-tool -n "$NS" >/dev/null 2>&1; then
    die "github-agent and/or github-tool already deployed in '${NS}' — deploying them now would not be a genuine first-time trigger. Run ./uc1-e2e-restore.sh first, or re-run with --only-wire-outbound/--only-enforce."
  fi
  pass "preflight: infra present, github-agent/github-tool NOT yet deployed (deploy will be a genuine first trigger)"
else
  pass "preflight: infra present"
fi

# ── Phase DEPLOY (the trigger) ────────────────────────────────────────────────
phase_deploy() {
  printf '\n%s%s====== Phase DEPLOY — first-ever kubectl apply of github-agent/github-tool ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  # Captured before the trigger fires so phase_verify_trigger's log check can scope by time
  # instead of a fixed --tail count — see that phase's own comment for why.
  DEPLOY_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  step "Recording the current AuthorizationPolicy CR (baseline — expect none)"
  BEFORE_RV=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "<none>")
  info "github-agent AuthorizationPolicy resourceVersion (before): ${BEFORE_RV}"

  step "Running demo/assets/install.sh (builds+loads images, kubectl apply's the manifests — THE trigger)"
  # Unmodified script, same one every other demo in this repo uses to stand up these workloads.
  NAMESPACE="$NS" bash "$ASSETS_DIR/install.sh"
  pass "github-agent + github-tool applied for the first time"

  step "Waiting for github-agent + github-tool pods to become Ready [timeout ${DEPLOY_WAIT_SECS}s]"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$AGENT_LABEL" --timeout="${DEPLOY_WAIT_SECS}s" \
    || die "github-agent did not become Ready after deploy"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$TOOL_LABEL" --timeout="${DEPLOY_WAIT_SECS}s" \
    || die "github-tool did not become Ready after deploy"
  pass "both workloads Ready"

  export UC1E2E_BEFORE_RV="$BEFORE_RV"
  export UC1E2E_DEPLOY_START_TS="$DEPLOY_START_TS"
}

# ── Phase VERIFY-TRIGGER ──────────────────────────────────────────────────────
phase_verify_trigger() {
  printf '\n%s%s====== Phase VERIFY-TRIGGER — Keycloak registered new clients, AIAC consumed them ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  step "Waiting for team1/github-agent + team1/github-tool clients to appear [timeout ${POLL_SECS}s]"
  local deadline=$((SECONDS + POLL_SECS))
  AGENT_UUID=""
  TOOL_UUID=""
  while :; do
    ADMIN="$(admin_token)"
    AGENT_UUID="$(client_uuid_by_name "team1/github-agent" "$ADMIN")"
    TOOL_UUID="$(client_uuid_by_name "team1/github-tool" "$ADMIN")"
    [ -n "$AGENT_UUID" ] && [ -n "$TOOL_UUID" ] && break
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "Keycloak never registered both clients within ${POLL_SECS}s (agent=${AGENT_UUID:-<none>}, tool=${TOOL_UUID:-<none>}). Check: kubectl logs deployment/rossoctl-controller-manager -n ${SYS_NS}"
    fi
    sleep 5
  done
  info "agent client uuid: ${AGENT_UUID}"
  info "tool client uuid:  ${TOOL_UUID}"
  pass "operator registered both clients for the first time — a real CLIENT_CREATE just fired from the deploy alone"

  step "Confirming AIAC consumed both live events — NO manual onboarding call was made"
  # Proof of consumption is a DURABLE artifact, not a log line. On consuming each
  # aiac.apply.service.<uuid> over NATS, AIAC's onboarding provisions that service's Keycloak
  # objects, including its per-service audience client-scope (agent-<ns>-github-agent-aud /
  # agent-<ns>-github-tool-aud). Those scopes persist regardless of pod restarts or log rotation —
  # unlike a grep of aiac-agent's pod logs, which the verbose onboarding tracing rotates out within
  # seconds and a liveness restart wipes entirely, so a log grep false-negatives even when both
  # events WERE consumed. Poll the scopes as the authoritative signal; the log line is shown only as
  # best-effort supplementary evidence when it happens to still be present.
  local ev_deadline=$((SECONDS + POLL_SECS)) agent_seen="" tool_seen=""
  while :; do
    ADMIN="$(admin_token)"
    local scopes_json
    scopes_json=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" 2>/dev/null || true)
    agent_seen=$(printf '%s' "$scopes_json" | SCOPE="agent-${NS}-github-agent-aud" python3 -c '
import sys, json, os
try: names = {s.get("name") for s in json.load(sys.stdin)}
except Exception: names = set()
print("yes" if os.environ["SCOPE"] in names else "")' 2>/dev/null || true)
    tool_seen=$(printf '%s' "$scopes_json" | SCOPE="agent-${NS}-github-tool-aud" python3 -c '
import sys, json, os
try: names = {s.get("name") for s in json.load(sys.stdin)}
except Exception: names = set()
print("yes" if os.environ["SCOPE"] in names else "")' 2>/dev/null || true)
    [ -n "$agent_seen" ] && [ -n "$tool_seen" ] && break
    if [ "$SECONDS" -ge "$ev_deadline" ]; then
      die "AIAC did not provision both services' Keycloak audience scopes (agent=${agent_seen:-no}, tool=${tool_seen:-no}) after ${POLL_SECS}s — it may not have consumed both aiac.apply.service events. Check: kubectl logs deployment/aiac-agent -n ${AIAC_NS}; kubectl logs statefulset/keycloak -n keycloak | grep -i aiac-event-listener"
    fi
    sleep 5
  done
  pass "AIAC consumed both aiac.apply.service.<uuid> events over NATS — both services' Keycloak audience scopes are provisioned (no /apply/service/{id} call anywhere in this script)"
  # Supplementary: surface the direct NATS-consumption log lines if the verbose-trace logs haven't
  # rotated them out yet (informational only — the provisioned scopes above are the durable proof).
  local logs
  logs=$(kubectl logs deployment/aiac-agent -n "$AIAC_NS" --since-time="${UC1E2E_DEPLOY_START_TS}" 2>/dev/null || true)
  if printf '%s\n' "$logs" | grep -q "$AGENT_UUID" && printf '%s\n' "$logs" | grep -q "$TOOL_UUID"; then
    info "aiac-agent logs still show both aiac.apply.service.<uuid> events (direct NATS-consumption evidence)"
  else
    info "aiac-agent's verbose onboarding logs have since rotated; the provisioned scopes above are the durable proof of consumption"
  fi

  step "Confirming a fresh AuthorizationPolicy CR for github-agent"
  local before_rv="${UC1E2E_BEFORE_RV:-<none>}" cr_deadline=$((SECONDS + POLL_SECS))
  AFTER_RV=""
  while :; do
    AFTER_RV=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "")
    if [ -n "$AFTER_RV" ] && [ "$AFTER_RV" != "$before_rv" ]; then break; fi
    if [ "$SECONDS" -ge "$cr_deadline" ]; then
      die "github-agent AuthorizationPolicy CR never appeared (still '${before_rv}') after ${POLL_SECS}s — AIAC may not have finished writing rules yet"
    fi
    sleep 5
  done
  pass "github-agent AuthorizationPolicy CR written by AIAC: resourceVersion ${before_rv} -> ${AFTER_RV} (nobody hand-wrote this CR)"
  info "content:"
  kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.spec.policies[*].content}' | sed 's/^/    /'
}

# ── Phase WIRE ────────────────────────────────────────────────────────────────
phase_wire_outbound() {
  printf '\n%s%s====== Phase WIRE — AuthBridge outbound leg (authproxy-routes + optional scope) ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  step "Adding the github-tool outbound route to authproxy-routes"
  kubectl patch configmap authproxy-routes -n "$NS" --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml":
"""- host: \"github-tool\"
  target_audience: \"spiffe://localtest.me/ns/team1/sa/github-tool\"
  token_scopes: \"openid agent-team1-github-tool-aud\"
"""}}))')" || die "failed to patch authproxy-routes"
  pass "authproxy-routes carries the github-tool route"

  step "Granting github-agent the exchange scope on its Keycloak client (expect HTTP 204)"
  ADMIN="$(admin_token)"
  AGENT_UUID="$(client_uuid_by_name "team1/github-agent" "$ADMIN")"
  [ -n "$AGENT_UUID" ] || die "could not resolve the Keycloak client uuid for team1/github-agent"
  SCOPE_ID=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" \
    | python3 -c 'import sys,json;print(next((s["id"] for s in json.load(sys.stdin) if s["name"]=="agent-team1-github-tool-aud"),""))')
  [ -n "$SCOPE_ID" ] || die "client-scope 'agent-team1-github-tool-aud' not found — has github-tool onboarded yet?"
  SCOPE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer ${ADMIN}" \
    "${KC}/admin/realms/${REALM}/clients/${AGENT_UUID}/optional-client-scopes/${SCOPE_ID}")
  case "$SCOPE_HTTP" in
    204) pass "assigned optional client-scope: HTTP 204" ;;
    409) warn "optional client-scope already assigned (HTTP 409) — idempotent, continuing" ;;
    *) die "assigning the optional client-scope returned HTTP ${SCOPE_HTTP} (expected 204)" ;;
  esac

  step "Restarting github-agent to load the route"
  kubectl delete pod -n "$NS" -l "$AGENT_LABEL" || die "failed to delete github-agent pod"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$AGENT_LABEL" --timeout=120s \
    || die "github-agent did not become Ready after the route-load restart"
  pass "github-agent restarted and Ready"
}

# ── Phase ENFORCE ─────────────────────────────────────────────────────────────

probe_agent() {
  local user="$1" want="$2" secs="$3" label="$4"
  local deadline=$((SECONDS + secs)) tok out code body
  while :; do
    tok="$(mint_token "$user")"
    [ -n "$tok" ] || die "could not mint a token for '${user}' (client=${ROPC_CLIENT_ID}, password=${USER_PASSWORD})"
    out=$(kubectl run "probe-${user}-$RANDOM" --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
      -n "$NS" --env="TOK=$tok" -- sh -c \
      'curl -s -m 15 -w "\nHTTP_CODE:%{http_code}\n" -X POST http://github-agent.team1.svc.cluster.local:8080/ \
         -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" \
         -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping/nonexistent\",\"params\":{}}"' 2>/dev/null || true)
    code=$(printf '%s' "$out" | grep -o 'HTTP_CODE:[0-9]*' | tail -1 | cut -d: -f2 || true)
    body=$(printf '%s' "$out" | grep -vE 'HTTP_CODE:|deleted' | tr -d '\r' | grep -v '^$' | tail -1 || true)
    if [ "$code" = "$want" ]; then
      info "probe_agent ${user}: HTTP ${code}  body: ${body}"
      pass "${label}: HTTP ${code} (expected ${want})"
      return 0
    fi
    [ "$SECONDS" -ge "$deadline" ] && die "${label}: got HTTP ${code:-<none>}, expected ${want} after ${secs}s. body: ${body}"
    info "probe_agent ${user}: HTTP ${code:-<none>} — retrying (want ${want})..."
    sleep 5
  done
}

# probe_tool <user> <tool_name> — real tools/call through the agent's forward proxy (127.0.0.1:8081).
# Echoes a VERDICT string: ALLOWED_RESULT | DENIED_JSONRPC | "DENIED_HTTP <code>" | ERROR | UNEXPECTED.
probe_tool() {
  local user="$1" tool="$2" pod tok py out
  pod="$(latest_pod "$AGENT_LABEL")"
  [ -n "$pod" ] || { echo "ERROR"; return 0; }
  tok="$(mint_token "$user")"
  py="$(mktemp /tmp/uc1-e2e-probe.XXXXXX.py)"
  cat > "$py" <<PY
import urllib.request, urllib.error, json
tok = """$tok"""
op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://127.0.0.1:8081"}))
body = json.dumps({"jsonrpc":"2.0","id":"1","method":"tools/call",
                    "params":{"name":"$tool","arguments":{}}}).encode()
# FastMCP's streamable_http_app serves the MCP endpoint at /mcp (not /) and requires the
# streamable Accept header; posting to / or without it 404s/406s even on an OPA-allowed call.
# Matches the agent's real MCP_URL (…/mcp) and test/integration/launcher.py's outbound_probe.
req = urllib.request.Request("http://github-tool:9090/mcp", data=body,
    headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream","Authorization":"Bearer "+tok})
code, raw = None, ""
try:
    r = op.open(req, timeout=15); code = r.status; raw = r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    code = e.code
    try: raw = e.read().decode("utf-8", "replace")
    except Exception: raw = ""
except Exception as e:
    print("VERDICT ERROR", type(e).__name__, e); raise SystemExit(0)
doc = None
try: doc = json.loads(raw)
except Exception: doc = None
if code in (403, 503):
    print(f"VERDICT DENIED_HTTP {code}")
elif code == 200 and isinstance(doc, dict) and "error" in doc:
    print("VERDICT DENIED_JSONRPC")
elif code == 200 and isinstance(doc, dict) and "result" in doc:
    print("VERDICT ALLOWED_RESULT")
else:
    print("VERDICT UNEXPECTED", code, raw[:200])
PY
  out=$(kubectl exec -i -n "$NS" "$pod" -c agent -- python3 - < "$py" 2>/dev/null || true)
  rm -f "$py"
  printf '%s\n' "$out" | sed -n 's/^VERDICT //p' | tail -1
}

phase_enforce() {
  printf '\n%s%s====== Phase ENFORCE — live HTTP through the real OPA plugin ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  step "Confirming OPA is still wired into both AuthBridge legs (expect 2)"
  OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
                -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
  expect_eq "'name: opa' occurrences" "$OPA_COUNT" "2"

  step "Granting ${ROPC_CLIENT_ID} the github-agent audience scope (so dev-user's ROPC token carries it)"
  # AIAC's onboarding creates the "agent-${NS}-github-agent-aud" client-scope (a hardcoded-audience
  # mapper pointed at github-agent's own SPIFFE clientId) but only ever assigns it to *target*
  # clients for the outbound leg (see setup_keycloak.py's ensure_default_audience_scope) — nothing
  # in this demo family assigns it to the ROPC client users log in through. Without it, mint_token's
  # plain grant_type=password login only carries the realm's own issuer audience, and AuthBridge's
  # jwt-validation plugin 401s every inbound probe. Made a default scope (not optional) so plain
  # mint_token calls need no scope= change; idempotent, safe to re-run.
  ADMIN="$(admin_token)"
  [ -n "$ADMIN" ] || die "could not obtain a Keycloak master admin token"
  AUD_SCOPE="agent-${NS}-github-agent-aud"
  ROPC_UUID="$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients?clientId=${ROPC_CLIENT_ID}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')"
  [ -n "$ROPC_UUID" ] || die "ROPC client '${ROPC_CLIENT_ID}' not found in realm '${REALM}'"
  AUD_SCOPE_ID="$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" \
    | AUD_SCOPE="$AUD_SCOPE" python3 -c 'import sys,json,os;print(next((s["id"] for s in json.load(sys.stdin) if s["name"]==os.environ["AUD_SCOPE"]),""))')"
  [ -n "$AUD_SCOPE_ID" ] || die "client-scope '${AUD_SCOPE}' not found — has github-agent onboarded yet?"
  ALREADY="$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients/${ROPC_UUID}/default-client-scopes" \
    | AUD_SCOPE="$AUD_SCOPE" python3 -c 'import sys,json,os;print("yes" if any(s["name"]==os.environ["AUD_SCOPE"] for s in json.load(sys.stdin)) else "no")')"
  if [ "$ALREADY" = "yes" ]; then
    pass "'${AUD_SCOPE}' already a default scope on '${ROPC_CLIENT_ID}'"
  else
    curl -s -o /dev/null -X PUT -H "Authorization: Bearer ${ADMIN}" \
      "${KC}/admin/realms/${REALM}/clients/${ROPC_UUID}/default-client-scopes/${AUD_SCOPE_ID}"
    pass "added '${AUD_SCOPE}' as a default scope on '${ROPC_CLIENT_ID}'"
  fi

  step "Ensuring ${ROPC_CLIENT_ID} stamps the username into the token 'sub' claim"
  # AuthBridge's jwt-validation sets input.identity.subject from the token 'sub'; AIAC's inbound
  # rego keys subject_roles on the USERNAME ("dev-user"/"test-user"). Stock Keycloak 26 puts the
  # user UUID in 'sub' (and only when the 'basic' client scope is assigned — otherwise 'sub' is
  # absent entirely), so without a username->sub mapper every inbound probe is denied with an
  # EMPTY subject. This is the realm's "username -> sub mapper" prerequisite that
  # test/integration/launcher.py:verify_subject_mapper only *skips* on — provisioned here so the
  # demo is self-sufficient. Idempotent: 201 created, 409 already present.
  MAPPER_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer ${ADMIN}" -H "Content-Type: application/json" \
    "${KC}/admin/realms/${REALM}/clients/${ROPC_UUID}/protocol-mappers/models" \
    -d '{"name":"username-to-sub","protocol":"openid-connect","protocolMapper":"oidc-usermodel-property-mapper","config":{"user.attribute":"username","claim.name":"sub","jsonType.label":"String","access.token.claim":"true","id.token.claim":"true","userinfo.token.claim":"true"}}')
  case "$MAPPER_HTTP" in
    201) pass "created 'username-to-sub' mapper on '${ROPC_CLIENT_ID}' (HTTP 201)" ;;
    409) warn "'username-to-sub' mapper already present (HTTP 409) — idempotent, continuing" ;;
    *) die "creating the username->sub mapper returned HTTP ${MAPPER_HTTP} (expected 201/409)" ;;
  esac

  step "Inbound — dev-user and test-user allowed, devops-user denied [polling up to ${POLL_SECS}s]"
  probe_agent dev-user    200 "$POLL_SECS" "dev-user -> github-agent (inbound)"
  probe_agent test-user   200 "$POLL_SECS" "test-user -> github-agent (inbound)"
  probe_agent devops-user 403 "$POLL_SECS" "devops-user -> github-agent (inbound, expected denied)"

  step "Outbound — per-tool matrix for dev-user and test-user (reported; source-read is a hard check)"
  local user tool verdict
  printf '     %-12s %-14s %s\n' "user" "tool" "verdict"
  for user in dev-user test-user; do
    for tool in source-read source-write issues-read issues-write; do
      verdict="$(probe_tool "$user" "$tool")"
      printf '     %-12s %-14s %s\n' "$user" "$tool" "${verdict:-<none>}"
    done
  done
  DEV_SOURCE_READ="$(probe_tool dev-user source-read)"
  [ "$DEV_SOURCE_READ" = "ALLOWED_RESULT" ] \
    && pass "dev-user -> source-read: ALLOWED_RESULT" \
    || die "dev-user -> source-read: got '${DEV_SOURCE_READ}', expected ALLOWED_RESULT"
  TEST_SOURCE_READ="$(probe_tool test-user source-read)"
  [ "$TEST_SOURCE_READ" != "ALLOWED_RESULT" ] \
    && pass "test-user -> source-read: ${TEST_SOURCE_READ} (correctly not ALLOWED_RESULT)" \
    || die "test-user -> source-read: got ALLOWED_RESULT, expected denied (testers don't touch source)"

  step "Decision logs — one inbound allow/deny, one outbound allow/deny"
  local pod
  pod="$(latest_pod "$AGENT_LABEL")"
  info "inbound (dev-user, allowed):"
  kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep 'path=authbridge/inbound/request' | grep 'allow:true' | tail -1 | sed 's/^/    /'
  info "inbound (devops-user, denied):"
  kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep 'path=authbridge/inbound/request' | grep 'allow:false' | tail -1 | sed 's/^/    /'
  info "outbound (dev-user -> source-read, allowed):"
  kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep 'path=authbridge/outbound/request' | grep 'allow:true' | tail -1 | sed 's/^/    /'
  info "outbound (test-user -> source-read, denied):"
  kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep 'path=authbridge/outbound/request' | grep 'allow:false' | tail -1 | sed 's/^/    /'

  warn "known gap: 'direct dev-user -> github-tool, no agent' (row 4 of #646's table) is NOT enforced by this deployment — github-tool has no AuthBridge sidecar and no auth of its own (see uc1-e2e-runbook.md's 'Known gaps' section). Not probed here to avoid reporting a fabricated result."
}

if [ "$DO_DEPLOY" -eq 1 ]; then
  phase_deploy
  phase_verify_trigger
fi
[ "$DO_WIRE" -eq 1 ] && phase_wire_outbound
[ "$DO_ENFORCE" -eq 1 ] && phase_enforce

[ "$DO_COLLECT" -eq 1 ] && collect_logs "$COLLECT_DIR"

printf '\n%s%s====== DONE ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
cat <<EOF

Revert with: ./uc1-e2e-restore.sh
EOF
