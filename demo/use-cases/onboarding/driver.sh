#!/usr/bin/env bash
# driver.sh — Parts 4-5 of demo.md: deploying github-agent/github-tool for the FIRST TIME is the
# live onboarding trigger, and a real HTTP request through the live OPA plugin decides allow/deny.
#
# The operator's AgentRuntimeReconciler stamps rossoctl.io/type=agent|tool onto a Deployment's
# pod-template the first time its AgentRuntime CR resolves, and THAT label is what the
# ClientRegistrationReconciler's watch predicate keys on — so the very first `kubectl apply` of
# github-agent/github-tool's manifests (demo/assets/deploy.sh, unmodified) is itself the trigger.
# No curl-based client deletion, no clone of the agent, no manual POST /apply/service/{id} call
# anywhere in a default run.
#
#   Phase DEPLOY          kubectl-apply github-agent/github-tool for the first time — THE trigger.
#   Phase VERIFY-TRIGGER  poll Keycloak for the brand-new clients, aiac-agent logs for evidence it
#                         consumed both over NATS, and the two AuthorizationPolicy CRs AIAC wrote
#                         (one per managed service, D20: github-agent AND github-tool).
#   Phase WIRE            wire AuthBridge's own outbound leg (authproxy-routes + optional
#                         client-scope) — demo-owned wiring the platform runbook
#                         (k8s/opa-kind-runbook.md) leaves out; AIAC's own onboarding does not do this.
#   Phase ENFORCE         real HTTP probes through the live AuthBridge OPA plugin, reproducing
#                         #646's acceptance table.
#   Phase REPLAY-TRIGGER  opt-in only (--only-replay-trigger): re-prove the trigger on a cluster
#                         where the workloads are ALREADY deployed, by deleting their Keycloak
#                         clients via the Admin API and restarting the pods so the operator
#                         re-registers them. Not part of a default run — DEPLOY is the real story;
#                         this exists for when tearing the workloads down isn't worth it.
#
# The enforcement side (D16, D29) is read from the live aiac-agent-config ConfigMap
# (AIAC_ENFORCEMENT_SIDE; absent = target-side, the default). It selects where a tool call is
# checked, so it selects what VERIFY-TRIGGER waits for and where ENFORCE reads the decision logs:
#   target-side  github-tool's inbound OPA decides each tool call (the github-tool CR carries the
#                per-tool check); every outbound is a pass-through. A tool-call deny is an HTTP 403.
#   agent-side   github-agent's outbound OPA decides it (the github-agent CR's outbound package);
#                github-tool gets a pass-through CR. A tool-call deny is a JSON-RPC error frame.
# The verdicts are the same under both sides. Switch the side with k8s/opa-kind-runbook.md
# "Switch the enforcement side".
#
# step()/pass()/warn()/die() style matches k8s/opa-kind-verify.sh: fails loudly and specifically the
# moment an observed result doesn't match, rather than continuing silently.
#
# Usage:
#   ./driver.sh                    # deploy -> verify-trigger -> wire -> enforce
#   ./driver.sh --only-deploy
#   ./driver.sh --only-wire-outbound
#   ./driver.sh --only-enforce
#   ./driver.sh --only-replay-trigger      # forced replay (workloads must already be deployed)
#   ./driver.sh --collect-logs     # (composes with any of the above) dump every component's logs
#                                  # into a per-run directory at the end, AND on any die() failure
#                                  # — so a failed run is debuggable without re-running.
#                                  # Time-scoped to this run.
#
# Env vars (defaults match the rest of this demo family):
#   NS, SYS_NS, AIAC_NS   namespaces (team1, rossoctl-system, aiac-system)
#   KC, REALM             Keycloak base URL + realm
#   ROPC_CLIENT_ID        OIDC client the demo users log in through (default: rossoctl). Must be a
#                         client AIAC's inbound rego accepts as the source (its source_ok allows the
#                         "rossoctl" platform client) AND whose tokens carry the workload audiences +
#                         sub = username. sub = username comes from the client scope aiac-username-sub
#                         (D31), which AIAC links as a default scope to each platform login client
#                         (PLATFORM_SOURCE_CLIENTS, default rossoctl) — ENFORCE checks that link and
#                         does not add a sub mapper by hand. aiac-demo-cli (the client this demo's own
#                         run-*.py scripts use) is NOT accepted by source_ok, so inbound probes through
#                         it are denied with the wrong azp.
#   USER_PASSWORD         shared demo-user password (default: password) — see scenario.py
#   POLL_SECS             max seconds a polling phase waits for trigger evidence / a bundle-service
#                         poll (default: 720). Sized for the slowest convergence: the agent publishes
#                         its A2A AgentCard skills only AFTER the deploy trigger, so onboarding
#                         redelivers (JetStream) for a few minutes until source_operations/
#                         issue_operations resolve and AIAC writes the AuthorizationPolicy CR. Keep it
#                         ABOVE the consumer's ACK_WAIT (600s) — a deploy-race 502 is only retried
#                         after that, so a smaller value makes the failure unrecoverable in-run. Each
#                         phase still breaks the instant its condition is met, so a healthy run is fast.
#   DEPLOY_WAIT_SECS      max seconds to wait for pods to become Ready after deploy   (default: 180)
#   TRIGGER_WAIT_SECS     max seconds --only-replay-trigger waits for the operator to re-register
#                         fresh Keycloak client uuids                          (default: 180)
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
AIAC_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ASSETS_DIR="$AIAC_DIR/demo/assets"

NS="${NS:-team1}"
SYS_NS="${SYS_NS:-rossoctl-system}"
AIAC_NS="${AIAC_NS:-aiac-system}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
ROPC_CLIENT_ID="${ROPC_CLIENT_ID:-rossoctl}"
USER_PASSWORD="${USER_PASSWORD:-password}"
# MUST exceed the consumer's ACK_WAIT (600s, src/aiac/agent/eventbus/stream.py) or this driver cannot
# survive a first-delivery failure: a deploy-race 502 leaves the message unacked, JetStream redelivers
# it only after ACK_WAIT, and that redelivery usually succeeds. At the old 420s the driver quit ~5
# minutes BEFORE the retry it was waiting for — observed 2026-09-30, where onboarding self-healed at
# 14:38 having failed at 14:28, but the run had already died at 14:33. 720s leaves room for one.
POLL_SECS="${POLL_SECS:-720}"
DEPLOY_WAIT_SECS="${DEPLOY_WAIT_SECS:-180}"
TRIGGER_WAIT_SECS="${TRIGGER_WAIT_SECS:-180}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"
KC_NS="${KC_NS:-keycloak}"
COLLECT_ROOT="${COLLECT_ROOT:-/tmp}"

# Recorded once, up front, so both the end-of-run collection and any die()-triggered collection
# scope component logs to this invocation (COLLECT_SINCE overrides — see the header docs).
RUN_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
TOOL_LABEL="app=github-tool"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"
# The client scope that sets sub=<username> in the login and the exchanged token (D31).
SUBJECT_SCOPE="aiac-username-sub"
# The live enforcement side; read in preflight.
SIDE=""

DO_DEPLOY=1
DO_WIRE=1
DO_ENFORCE=1
# Opt-in only: REPLAY-TRIGGER is never part of a default run. DEPLOY is this demo's real trigger
# story; the replay exists for a cluster where the workloads are already deployed.
DO_REPLAY=0
DO_COLLECT=0
COLLECT_DIR=""
# Args compose: at most one --only-* phase selector, optionally plus --collect-logs. Two different
# selectors would switch every phase off and "pass" having done nothing, so reject them.
ONLY_FLAG=""
for arg in "$@"; do
  case "$arg" in
    --only-*)
      if [ -n "$ONLY_FLAG" ] && [ "$ONLY_FLAG" != "$arg" ]; then
        echo "Error: ${ONLY_FLAG} and ${arg} are mutually exclusive." >&2
        exit 1
      fi
      ONLY_FLAG="$arg"
      ;;
  esac
  case "$arg" in
    --only-deploy) DO_WIRE=0; DO_ENFORCE=0 ;;
    --only-wire-outbound) DO_DEPLOY=0; DO_ENFORCE=0 ;;
    --only-enforce) DO_DEPLOY=0; DO_WIRE=0 ;;
    --only-replay-trigger) DO_DEPLOY=0; DO_WIRE=0; DO_ENFORCE=0; DO_REPLAY=1 ;;
    --collect-logs) DO_COLLECT=1 ;;
    "") ;;
    *) echo "Usage: $0 [--only-deploy|--only-wire-outbound|--only-enforce|--only-replay-trigger] [--collect-logs]" >&2; exit 1 ;;
  esac
done
# Fix the destination once, so the end-of-run and die()-path collections write to the same directory.
[ "$DO_COLLECT" -eq 1 ] && COLLECT_DIR="${COLLECT_ROOT}/onboarding-logs-$(date -u +%Y%m%dT%H%M%SZ)"

# ── Output helpers (same palette/shape as k8s/opa-kind-verify.sh) ───────
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
# Prints "" (exit 0) rather than raising when Keycloak returns a non-JSON/empty body — under
# `set -euo pipefail` a raising python3 would abort the phase with a traceback instead of letting the
# caller report a missing token. Same hardening as mint_token below.
admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("access_token","") or "")
except Exception: print("")'
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

# json_eval <python-expr> — evaluate <python-expr> over the JSON on stdin (bound to `d`; env vars via
# `os.environ`) and print the result. Prints "" (exit 0) instead of raising when the body is not the
# expected JSON — a Keycloak error object, an empty list, an unreachable server — so the caller's
# `[ -n ... ] || die` guard reports it, rather than `set -e` killing the script on a traceback.
json_eval() {
  python3 -c '
import sys, json, os
try:
    d = json.load(sys.stdin)
    r = eval(sys.argv[1])
except Exception:
    r = ""
print("" if r is None else r)' "$1"
}

# client_uuid_by_name <name> <admin_token> — Keycloak clients are looked up by the "name" DISPLAY
# field (e.g. "team1/github-agent"), not clientId. Prints "" if not found (caller checks).
client_uuid_by_name() {
  local name="$1" admin="$2"
  curl -s -H "Authorization: Bearer ${admin}" "${KC}/admin/realms/${REALM}/clients" \
    | CLIENT_NAME="$name" json_eval 'next((c["id"] for c in d if c.get("name") == os.environ["CLIENT_NAME"]), "")'
}

# scope_id_by_name <name> <admin_token> — the realm client-scope's id, or "" if absent (caller checks).
scope_id_by_name() {
  local name="$1" admin="$2"
  curl -s -H "Authorization: Bearer ${admin}" "${KC}/admin/realms/${REALM}/client-scopes" \
    | SCOPE_NAME="$name" json_eval 'next((s["id"] for s in d if s.get("name") == os.environ["SCOPE_NAME"]), "")'
}

latest_pod() {
  kubectl get pod -n "$NS" -l "$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# scope_linked <admin> <client-uuid> <default|optional>  — read only (GET). Print "yes" when the
# client links the client scope aiac-username-sub as that kind of scope, "no" when it does not, and
# "error" when the admin API reply is not a list.
scope_linked() {
  local admin="$1" cid="$2" kind="$3" res
  res=$(curl -s -H "Authorization: Bearer $admin" \
          "${KC}/admin/realms/${REALM}/clients/${cid}/${kind}-client-scopes" \
        | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: d=None
if not isinstance(d,list): print("error")
else: print("yes" if any(isinstance(s,dict) and s.get("name")==sys.argv[1] for s in d) else "no")' \
            "$SUBJECT_SCOPE" 2>/dev/null || true)
  printf '%s' "${res:-error}"
}

# check_subject_scope <label> <client-uuid> <cause>  — read only (D31). Pass when the client links
# the client scope aiac-username-sub as a DEFAULT scope; else die at once with the cause and the fix.
# The mapper of an optional scope runs only when the token request names that scope, and neither the
# password grant nor the token exchange names it, so an optional link is not enough.
check_subject_scope() {
  local label="$1" cid="$2" cause="$3" admin def opt fix
  admin="$(admin_token)"
  def="$(scope_linked "$admin" "$cid" default)"
  [ "$def" != "error" ] \
    || die "could not read the default client scopes of the ${label} Keycloak client (${cid}) at ${KC}"
  if [ "$def" = "yes" ]; then
    pass "${label} links the client scope ${SUBJECT_SCOPE} as a default scope (D31)"
    return 0
  fi
  opt="$(scope_linked "$admin" "$cid" optional)"
  fix="Fix: AIAC makes this link at the start of the IdP Configuration Service (aiac-pdp-config) for each platform login client (restart the service once Keycloak is ready), and at each onboarding for the onboarded client (or POST /services/${cid}/subject-scope on svc/aiac-pdp-config-service:7071 in ${AIAC_NS}). Do not add a sub mapper by hand."
  if [ "$opt" = "yes" ]; then
    die "${label} links the client scope ${SUBJECT_SCOPE} only as an OPTIONAL scope, not as a default scope (D31). Thus ${cause}
     ${fix}"
  fi
  die "${label} does not link the client scope ${SUBJECT_SCOPE} as a default scope (D31). Thus ${cause}
     ${fix}"
}

# delete_client <uuid> <admin_token> — used only by the opt-in REPLAY-TRIGGER phase.
delete_client() {
  local uuid="$1" admin="$2"
  curl -s -o /dev/null -w "     delete client %{http_code}\n" -X DELETE \
    -H "Authorization: Bearer ${admin}" "${KC}/admin/realms/${REALM}/clients/${uuid}"
}

# ── Log collection (--collect-logs) ────────────────────────────────────────────
# Dumps every component this demo touches into one per-run directory: the operator (client
# registration), aiac-agent (onboarding pipeline), the NATS broker, Keycloak (SPI listener), and the
# github-agent sidecar (the OPA allow/deny decisions) + app container + github-tool (its sidecar has
# the tool-call decisions under target side). Component logs
# are time-scoped to this run (COLLECT_SINCE / RUN_START_TS) so log volume can't push evidence out of
# view — the same reasoning phase_verify_trigger uses for --since-time over --tail. Durable state
# (the two AuthorizationPolicy CRs, the routing/runtime ConfigMaps, pod listings) is captured as
# point-in-time snapshots. Every command is best-effort: a missing component leaves a note in its
# file rather than aborting, so this is safe to call from die() mid-failure.
collect_logs() {
  local dir="${1:-$COLLECT_ROOT/onboarding-logs-$(date -u +%Y%m%dT%H%M%SZ)}"
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
  kubectl get "$POLICY_CR" github-tool -n "$NS" -o yaml \
    >"${dir}/authorizationpolicy-github-tool.yaml" 2>&1 || true
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
printf '%s%sonboarding demo driver (deploying the agent IS the live trigger)%s\n' "$C_BLD" "$C_CYN" "$C_RST"

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
  || die "aiac-agent not deployed in ${AIAC_NS} — run ./enable.sh --stack-only first"
kubectl get deployment aiac-event-broker -n "$AIAC_NS" >/dev/null 2>&1 \
  || die "aiac-event-broker not deployed in ${AIAC_NS} — run ./enable.sh --broker-only first"
OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
              -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
[ "$OPA_COUNT" = "2" ] || die "OPA not wired into both AuthBridge legs (got ${OPA_COUNT}, expected 2) — run k8s/opa-kind-enable.sh first"
# The changed combiner (D20): no request fallback rule, so a pod with no client CR is denied. The AIAC
# Controller does not start without it (start check #4, D30).
REQ_FALLBACK=$(kubectl get "$POLICY_CR" default -n "$SYS_NS" -o jsonpath='{.spec.policies[*].content}' 2>/dev/null \
  | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.request' || true)
[ "$REQ_FALLBACK" = "0" ] \
  || die "the global combiner in ${SYS_NS} is not the changed combiner (D20): ${REQ_FALLBACK} request fallback rules, expected 0 — run k8s/opa-kind-enable.sh first"
SIDE=$(kubectl get configmap aiac-agent-config -n "$AIAC_NS" \
         -o jsonpath='{.data.AIAC_ENFORCEMENT_SIDE}' 2>/dev/null || true)
SIDE="${SIDE:-target-side}"
case "$SIDE" in
  target-side|agent-side) info "enforcement side: ${SIDE} (AIAC_ENFORCEMENT_SIDE in configmap/aiac-agent-config)" ;;
  *) die "unknown AIAC_ENFORCEMENT_SIDE='${SIDE}' in configmap/aiac-agent-config (${AIAC_NS}) — want target-side or agent-side" ;;
esac
ADMIN="$(admin_token)"
[ -n "$ADMIN" ] || die "could not obtain a Keycloak master admin token"
LISTENERS=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/events/config" \
  | python3 -c 'import sys,json;print(",".join(json.load(sys.stdin).get("eventsListeners",[])))' 2>/dev/null || true)
case "$LISTENERS" in
  *aiac-event-listener*) ;;
  *) die "aiac-event-listener not enabled on realm '${REALM}' (listeners: ${LISTENERS:-<none>}) — run ./enable.sh --spi-only first" ;;
esac
if [ "$DO_DEPLOY" -eq 1 ]; then
  if kubectl get deployment github-agent -n "$NS" >/dev/null 2>&1 || kubectl get deployment github-tool -n "$NS" >/dev/null 2>&1; then
    die "github-agent and/or github-tool already deployed in '${NS}' — deploying them now would not be a genuine first-time trigger. Run ./restore.sh first, or re-run with --only-replay-trigger (forced replay against the deployed workloads) / --only-wire-outbound / --only-enforce."
  fi
  pass "preflight: infra present, github-agent/github-tool NOT yet deployed (deploy will be a genuine first trigger)"
elif [ "$DO_REPLAY" -eq 1 ]; then
  # The mirror image of the DEPLOY guard: a forced replay has nothing to act on unless both
  # workloads are already deployed and registered.
  kubectl get deployment github-agent -n "$NS" >/dev/null 2>&1 \
    || die "github-agent not deployed in '${NS}' — a forced replay needs already-registered workloads. Run a normal ./driver.sh (its DEPLOY phase is the genuine first-time trigger) instead."
  kubectl get deployment github-tool -n "$NS" >/dev/null 2>&1 \
    || die "github-tool not deployed in '${NS}' — a forced replay needs already-registered workloads. Run a normal ./driver.sh instead."
  pass "preflight: infra present, github-agent/github-tool already deployed (forced replay can act on them)"
else
  pass "preflight: infra present"
fi

# ── Phase DEPLOY (the trigger) ────────────────────────────────────────────────
phase_deploy() {
  printf '\n%s%s====== Phase DEPLOY — first-ever kubectl apply of github-agent/github-tool ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  # Captured before the trigger fires so phase_verify_trigger's log check can scope by time
  # instead of a fixed --tail count — see that phase's own comment for why.
  DEPLOY_START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  step "Recording the current AuthorizationPolicy CRs (baseline — expect none)"
  BEFORE_RV=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "<none>")
  BEFORE_TOOL_RV=$(kubectl get "$POLICY_CR" github-tool -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "<none>")
  info "github-agent AuthorizationPolicy resourceVersion (before): ${BEFORE_RV}"
  info "github-tool AuthorizationPolicy resourceVersion (before):  ${BEFORE_TOOL_RV}"

  # demo/assets/ splits standing these workloads up into the two halves that matter to this demo's
  # claim: kind-load.sh is the *images precondition* (build + `kind load`, applies nothing, fires
  # nothing), and deploy.sh is the `kubectl apply` + rollout. So the trigger is isolated to the
  # second call — the first cannot register a Keycloak client. Both scripts are used unmodified,
  # exactly as the `-m system` suite uses them.
  step "Loading the workload images (demo/assets/kind-load.sh — precondition, applies nothing)"
  CLUSTER_NAME="$KIND_CLUSTER" bash "$ASSETS_DIR/kind-load.sh"
  pass "github-agent + github-tool images present in the Kind node"

  step "Deploying the workloads (demo/assets/deploy.sh — kubectl apply: THE trigger)"
  NAMESPACE="$NS" bash "$ASSETS_DIR/deploy.sh"
  pass "github-agent + github-tool applied for the first time"

  step "Waiting for github-agent + github-tool pods to become Ready [timeout ${DEPLOY_WAIT_SECS}s]"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$AGENT_LABEL" --timeout="${DEPLOY_WAIT_SECS}s" \
    || die "github-agent did not become Ready after deploy"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$TOOL_LABEL" --timeout="${DEPLOY_WAIT_SECS}s" \
    || die "github-tool did not become Ready after deploy"
  pass "both workloads Ready"

  export ONBOARDING_BEFORE_RV="$BEFORE_RV"
  export ONBOARDING_BEFORE_TOOL_RV="$BEFORE_TOOL_RV"
  export ONBOARDING_DEPLOY_START_TS="$DEPLOY_START_TS"
}

# ── Phase VERIFY-TRIGGER ──────────────────────────────────────────────────────
phase_verify_trigger() {
  printf '\n%s%s====== Phase VERIFY-TRIGGER — Keycloak registered new clients, AIAC consumed them ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  step "Waiting for ${NS}/github-agent + ${NS}/github-tool clients to appear [timeout ${POLL_SECS}s]"
  local deadline=$((SECONDS + POLL_SECS))
  AGENT_UUID=""
  TOOL_UUID=""
  while :; do
    ADMIN="$(admin_token)"
    AGENT_UUID="$(client_uuid_by_name "${NS}/github-agent" "$ADMIN")"
    TOOL_UUID="$(client_uuid_by_name "${NS}/github-tool" "$ADMIN")"
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
  logs=$(kubectl logs deployment/aiac-agent -n "$AIAC_NS" --since-time="${ONBOARDING_DEPLOY_START_TS}" 2>/dev/null || true)
  if printf '%s\n' "$logs" | grep -q "$AGENT_UUID" && printf '%s\n' "$logs" | grep -q "$TOOL_UUID"; then
    info "aiac-agent logs still show both aiac.apply.service.<uuid> events (direct NATS-consumption evidence)"
  else
    info "aiac-agent's verbose onboarding logs have since rotated; the provisioned scopes above are the durable proof of consumption"
  fi

  step "Confirming fresh AuthorizationPolicy CRs for github-agent AND github-tool [polling up to ${POLL_SECS}s]"
  # One CR per managed service (D20), under both sides: under target side the tool CR carries the
  # per-tool check, under agent side it is a pass-through. Under the changed combiner a pod with no CR
  # is denied, so both must exist.
  local before_rv="${ONBOARDING_BEFORE_RV:-<none>}" before_tool_rv="${ONBOARDING_BEFORE_TOOL_RV:-<none>}"
  local cr_start=$SECONDS cr_deadline=$((SECONDS + POLL_SECS)) cr_next_info=$((SECONDS + 30))
  AFTER_RV=""
  AFTER_TOOL_RV=""
  while :; do
    AFTER_RV=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "")
    AFTER_TOOL_RV=$(kubectl get "$POLICY_CR" github-tool -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "")
    if [ -n "$AFTER_RV" ] && [ "$AFTER_RV" != "$before_rv" ] \
       && [ -n "$AFTER_TOOL_RV" ] && [ "$AFTER_TOOL_RV" != "$before_tool_rv" ]; then break; fi
    if [ "$SECONDS" -ge "$cr_deadline" ]; then
      die "the AuthorizationPolicy CRs never both appeared after ${POLL_SECS}s (github-agent: '${AFTER_RV:-<none>}', github-tool: '${AFTER_TOOL_RV:-<none>}') — AIAC may not have finished writing rules yet"
    fi
    # Policy generation is a chain of LLM calls and routinely takes minutes — say so, so a long
    # quiet wait isn't mistaken for a hang.
    if [ "$SECONDS" -ge "$cr_next_info" ]; then
      info "still waiting for AIAC to write the CR ($((SECONDS - cr_start))s / ${POLL_SECS}s) — policy generation is LLM-bound; watch: kubectl logs -f deployment/aiac-agent -n ${AIAC_NS} | grep chat/completions"
      cr_next_info=$((SECONDS + 30))
    fi
    sleep 5
  done
  pass "github-agent AuthorizationPolicy CR written by AIAC: resourceVersion ${before_rv} -> ${AFTER_RV} (nobody hand-wrote this CR)"
  pass "github-tool AuthorizationPolicy CR written by AIAC: resourceVersion ${before_tool_rv} -> ${AFTER_TOOL_RV}"

  # The CR EXISTING is not the same as the CR being COMPLETE. If the tool's onboarding failed (a
  # deploy-race 502 in classify_service/analyze_tool) while the agent's succeeded, AIAC still writes
  # CRs — but the per-tool check has all empty maps, and every tool call then denies. That state
  # passed this phase twice before this check existed, and only blew up later in ENFORCE, where the
  # cause is much harder to see. So wait for the per-tool check to actually carry the tool's scopes.
  # The wait matters because a failed onboard is REDELIVERED by JetStream (ACK_WAIT) and succeeds on a
  # later attempt — POLL_SECS is sized to outlast one such redelivery.
  #
  # Where the per-tool check lives depends on the side:
  #   target-side  github-tool's inbound package. `source_roles` (the calling-agent gate, keyed by
  #                github-agent's SPIFFE id) is filled only when both services are onboarded.
  #   agent-side   github-agent's outbound package. `target_allow_scopes` (keyed by github-tool's
  #                SPIFFE id) is filled only when the tool is onboarded.
  # The generator renders an empty map as `:= {}` on one line and a filled one as `:= {` followed by
  # newline-separated entries — so the EMPTY LITERAL is the exact signal. Test for it first (`:= {`
  # matches both forms), and require the key to be present at all.
  local gate_cr gate_map gate_what
  if [ "$SIDE" = "target-side" ]; then
    gate_cr="github-tool"; gate_map="source_roles"
    gate_what="github-tool's inbound gate (target side)"
  else
    gate_cr="github-agent"; gate_map="target_allow_scopes"
    gate_what="github-agent's outbound gate (agent side)"
  fi
  step "Confirming ${gate_what} carries the tool's scopes (not just that the CR exists) [timeout ${POLL_SECS}s]"
  local gate_deadline=$((SECONDS + POLL_SECS)) cr_content=""
  while :; do
    cr_content=$(kubectl get "$POLICY_CR" "$gate_cr" -n "$NS" -o jsonpath='{.spec.policies[*].content}' 2>/dev/null || true)
    if printf '%s' "$cr_content" | grep -q "${gate_map} := {}"; then
      : # key present but empty -> not both onboarded yet
    elif printf '%s' "$cr_content" | grep -q "${gate_map} := {"; then
      break
    fi
    if [ "$SECONDS" -ge "$gate_deadline" ]; then
      die "${gate_what} still has an EMPTY or absent ${gate_map} after ${POLL_SECS}s — one of the two onboardings did not finish, so every tool call would deny. Check for a deploy-race 502 in: kubectl logs deployment/aiac-agent -n ${AIAC_NS} | grep -iE 'label missing|MCP tools/list'"
    fi
    info "${gate_map} still empty (not both onboarded yet) — retrying..."
    sleep 10
  done
  pass "${gate_what} populated: ${gate_map} carries the tool's scopes"

  info "github-agent CR content:"
  kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.spec.policies[*].content}' | sed 's/^/    /'
  info "github-tool CR content:"
  kubectl get "$POLICY_CR" github-tool -n "$NS" -o jsonpath='{.spec.policies[*].content}' | sed 's/^/    /'
}

# ── Phase WIRE ────────────────────────────────────────────────────────────────
phase_wire_outbound() {
  printf '\n%s%s====== Phase WIRE — AuthBridge outbound leg (authproxy-routes + optional scope) ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  step "Adding the github-tool outbound route to authproxy-routes"
  kubectl patch configmap authproxy-routes -n "$NS" --type merge -p "$(NS="$NS" python3 -c '
import json, os
ns = os.environ["NS"]
print(json.dumps({"data":{"routes.yaml":
f"""- host: \"github-tool\"
  target_audience: \"spiffe://localtest.me/ns/{ns}/sa/github-tool\"
  token_scopes: \"openid agent-{ns}-github-tool-aud\"
"""}}))')" || die "failed to patch authproxy-routes"
  pass "authproxy-routes carries the github-tool route"

  step "Granting github-agent the exchange scope on its Keycloak client (expect HTTP 204)"
  ADMIN="$(admin_token)"
  [ -n "$ADMIN" ] || die "could not obtain a Keycloak master admin token"
  AGENT_UUID="$(client_uuid_by_name "${NS}/github-agent" "$ADMIN")"
  [ -n "$AGENT_UUID" ] || die "could not resolve the Keycloak client uuid for ${NS}/github-agent"
  local tool_aud="agent-${NS}-github-tool-aud"
  SCOPE_ID="$(scope_id_by_name "$tool_aud" "$ADMIN")"
  [ -n "$SCOPE_ID" ] || die "client-scope '${tool_aud}' not found — has github-tool onboarded yet?"
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
      -n "$NS" --env="TOK=$tok" --env="NS=$NS" -- sh -c \
      'curl -s -m 15 -w "\nHTTP_CODE:%{http_code}\n" -X POST "http://github-agent.${NS}.svc.cluster.local:8080/" \
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
  py="$(mktemp /tmp/onboarding-probe.XXXXXX.py)"
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

# probe_tool_direct <user> <tool_name> — real tools/call straight to github-tool from a throwaway pod,
# with the user's login token and NO agent (row 4 of #646's table). Echoes a VERDICT string like
# probe_tool: ALLOWED_RESULT | DENIED_JSONRPC | "DENIED_HTTP <code>" | ERROR | UNEXPECTED.
probe_tool_direct() {
  local user="$1" tool="$2" tok out code body
  tok="$(mint_token "$user")"
  [ -n "$tok" ] || { echo "ERROR"; return 0; }
  # $TOK and $TOOL are expanded by the sh in the probe pod (--env), not here.
  # shellcheck disable=SC2016
  out=$(kubectl run "probe-direct-${user}-$RANDOM" --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
    -n "$NS" --env="TOK=$tok" --env="TOOL=$tool" -- sh -c \
    'curl -s -m 15 -w "\nHTTP_CODE:%{http_code}\n" -X POST "http://github-tool:9090/mcp" \
       -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
       -H "Authorization: Bearer $TOK" \
       -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":{}}}"' \
    2>/dev/null || true)
  code=$(printf '%s' "$out" | grep -o 'HTTP_CODE:[0-9]*' | tail -1 | cut -d: -f2 || true)
  body=$(printf '%s' "$out" | grep -vE 'HTTP_CODE:|deleted' | tr -d '\r' | grep -v '^$' | tail -1 || true)
  case "$code" in
    401|403|503) echo "DENIED_HTTP ${code}" ;;
    200)
      case "$body" in
        *'"result"'*) echo "ALLOWED_RESULT" ;;
        *'"error"'*) echo "DENIED_JSONRPC" ;;
        *) echo "UNEXPECTED 200" ;;
      esac ;;
    "") echo "ERROR" ;;
    *) echo "UNEXPECTED ${code}" ;;
  esac
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
    | json_eval 'd[0]["id"]')"
  [ -n "$ROPC_UUID" ] || die "ROPC client '${ROPC_CLIENT_ID}' not found in realm '${REALM}'"
  AUD_SCOPE_ID="$(scope_id_by_name "$AUD_SCOPE" "$ADMIN")"
  [ -n "$AUD_SCOPE_ID" ] || die "client-scope '${AUD_SCOPE}' not found — has github-agent onboarded yet?"
  ALREADY="$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients/${ROPC_UUID}/default-client-scopes" \
    | AUD_SCOPE="$AUD_SCOPE" json_eval '"yes" if any(s.get("name") == os.environ["AUD_SCOPE"] for s in d) else "no"')"
  if [ "$ALREADY" = "yes" ]; then
    pass "'${AUD_SCOPE}' already a default scope on '${ROPC_CLIENT_ID}'"
  else
    DEFAULT_SCOPE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer ${ADMIN}" \
      "${KC}/admin/realms/${REALM}/clients/${ROPC_UUID}/default-client-scopes/${AUD_SCOPE_ID}")
    case "$DEFAULT_SCOPE_HTTP" in
      204) pass "added '${AUD_SCOPE}' as a default scope on '${ROPC_CLIENT_ID}': HTTP 204" ;;
      *) die "adding '${AUD_SCOPE}' as a default scope on '${ROPC_CLIENT_ID}' returned HTTP ${DEFAULT_SCOPE_HTTP} (expected 204)" ;;
    esac
  fi

  step "Checking that the login and the exchanged tokens carry sub = username (D31)"
  # AuthBridge's jwt-validation sets input.identity.subject from the token 'sub'; AIAC's rego keys
  # subject_roles on the USERNAME ("dev-user"/"test-user"). Stock Keycloak 26 puts the user UUID in
  # 'sub'. The one source of sub = username is the client scope aiac-username-sub, linked as a
  # DEFAULT scope (D31). AIAC makes both links; this demo only checks them (read only), and never adds
  # a sub mapper by hand:
  #   - on ${ROPC_CLIENT_ID} (a platform login client), for the login token — else every inbound
  #     probe is denied with a UUID subject;
  #   - on github-agent (an onboarded client), for the token it exchanges for github-tool — the
  #     Keycloak standard token exchange (V2) applies the scopes of the agent client. Under target
  #     side github-tool's inbound keys users by that 'sub', so without the link every tool call is
  #     denied.
  check_subject_scope "${ROPC_CLIENT_ID}" "$ROPC_UUID" \
    "the login token keeps sub = the Keycloak user ID, but the inbound rego keys users by username, so every inbound probe would be DENIED."
  AGENT_UUID="$(client_uuid_by_name "${NS}/github-agent" "$ADMIN")"
  [ -n "$AGENT_UUID" ] || die "could not resolve the Keycloak client uuid for ${NS}/github-agent"
  check_subject_scope "github-agent" "$AGENT_UUID" \
    "the token that github-agent exchanges for github-tool keeps sub = the Keycloak user ID, but github-tool's inbound keys users by username, so every tool call would be DENIED under target side."

  step "Inbound — dev-user and test-user allowed, devops-user denied [polling up to ${POLL_SECS}s]"
  probe_agent dev-user    200 "$POLL_SECS" "dev-user -> github-agent (inbound)"
  probe_agent test-user   200 "$POLL_SECS" "test-user -> github-agent (inbound)"
  probe_agent devops-user 403 "$POLL_SECS" "devops-user -> github-agent (inbound, expected denied)"

  step "Tool calls through github-agent — per-tool matrix for dev-user and test-user (reported; source-read is a hard check)"
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

  step "Decision logs — one inbound allow/deny, one tool-call allow/deny (${SIDE})"
  local pod tool_pod tool_leg tool_path
  pod="$(latest_pod "$AGENT_LABEL")"
  info "inbound (dev-user, allowed):"
  kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep 'path=authbridge/inbound/request' | grep 'allow:true' | tail -1 | sed 's/^/    /'
  info "inbound (devops-user, denied):"
  kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep 'path=authbridge/inbound/request' | grep 'allow:false' | tail -1 | sed 's/^/    /'
  # The tool-call decision is on github-tool's inbound under target side, on github-agent's
  # outbound under agent side (the other one is a pass-through).
  if [ "$SIDE" = "target-side" ]; then
    tool_pod="$(latest_pod "$TOOL_LABEL")"; tool_leg="github-tool inbound"; tool_path="authbridge/inbound/request"
  else
    tool_pod="$pod"; tool_leg="github-agent outbound"; tool_path="authbridge/outbound/request"
  fi
  info "${tool_leg} (dev-user -> source-read, allowed):"
  kubectl logs -n "$NS" "$tool_pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep "path=${tool_path}" | grep 'allow:true' | tail -1 | sed 's/^/    /'
  info "${tool_leg} (test-user -> source-read, denied):"
  kubectl logs -n "$NS" "$tool_pod" -c authbridge-proxy --tail=500 2>/dev/null \
    | grep "path=${tool_path}" | grep 'allow:false' | tail -1 | sed 's/^/    /'

  # Row 4 of #646's table: dev-user calls github-tool DIRECTLY, with no agent. Under target side
  # github-tool's inbound package has both gates, with no platform-client bypass (D26, D27): the
  # login token's client_id (rossoctl) has no entry in source_roles, so the call is denied (403, or
  # 401 from jwt-validation when the token has no github-tool audience). Under agent side github-tool
  # has a pass-through CR, so nothing derived from policy.md constrains the path — report it, do not
  # probe it. See demo.md's 'Known gaps' section.
  if [ "$SIDE" = "target-side" ]; then
    local direct
    direct="$(probe_tool_direct dev-user source-read)"
    case "$direct" in
      ALLOWED_RESULT)
        die "direct dev-user -> github-tool (no agent) -> source-read: ALLOWED_RESULT, expected denied — github-tool's inbound gate is open" ;;
      "DENIED_HTTP 401"|"DENIED_HTTP 403"|DENIED_JSONRPC)
        pass "direct dev-user -> github-tool (no agent) -> source-read: ${direct} (github-tool's inbound gate checks the calling agent)" ;;
      *)
        warn "direct dev-user -> github-tool (no agent) -> source-read: inconclusive (${direct:-<none>}) — check: kubectl logs -n ${NS} $(latest_pod "$TOOL_LABEL") -c authbridge-proxy | grep path=authbridge/inbound/request" ;;
    esac
  else
    warn "known gap under agent side: 'direct dev-user -> github-tool, no agent' (row 4 of #646's table) is NOT enforced by the GENERATED policy — github-tool's CR is a pass-through, so no policy derived from policy.md constrains it. Not probed here to avoid reporting a fabricated result. Under target side github-tool's inbound gate denies it."
  fi
}

# ── Phase REPLAY-TRIGGER (opt-in) ─────────────────────────────────────────────
# Re-prove the live trigger WITHOUT tearing the workloads down. Both are already registered
# Keycloak clients, so their CLIENT_CREATE fired at some point in the past — leaving them alone
# proves nothing. The operator's ClientRegistrationReconciler
# (operator/internal/controller/clientregistration_controller.go) calls
# RegisterOrFetchClientWithToken unconditionally on every reconcile — it does NOT skip because a
# credentials Secret already exists — so deleting the client and forcing a reconcile (a pod restart
# touches the Deployment's pod template, which the reconciler watches) reliably produces a fresh
# CLIENT_CREATE, and therefore a fresh onboarding event, with no /apply/service/{id} call.
#
# This is weaker evidence than phase_deploy (it replays the path against workloads that were already
# onboarded once, rather than onboarding something genuinely new), which is exactly why it is opt-in
# and not part of a default run. Prefer ./restore.sh + a normal ./driver.sh when you can afford the
# teardown.
phase_replay_trigger() {
  printf '\n%s%s====== Phase REPLAY-TRIGGER — force a fresh onboarding event (opt-in) ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  local replay_start_ts
  replay_start_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  step "Recording the current AuthorizationPolicy CR (baseline, before the fresh trigger)"
  local before_rv
  before_rv=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "<none>")
  info "github-agent AuthorizationPolicy resourceVersion (before): ${before_rv}"

  step "Recording current Keycloak client UUIDs for ${NS}/github-agent, ${NS}/github-tool"
  ADMIN="$(admin_token)"
  local old_agent_uuid old_tool_uuid
  old_agent_uuid="$(client_uuid_by_name "${NS}/github-agent" "$ADMIN")"
  old_tool_uuid="$(client_uuid_by_name "${NS}/github-tool" "$ADMIN")"
  [ -n "$old_agent_uuid" ] || die "no Keycloak client named '${NS}/github-agent' found — has it registered at all yet?"
  [ -n "$old_tool_uuid" ] || die "no Keycloak client named '${NS}/github-tool' found — has it registered at all yet?"
  info "old agent client uuid: ${old_agent_uuid}"
  info "old tool client uuid:  ${old_tool_uuid}"

  step "Deleting both Keycloak clients (their original CLIENT_CREATE is long past)"
  delete_client "$old_agent_uuid" "$ADMIN"
  delete_client "$old_tool_uuid" "$ADMIN"

  step "Restarting github-agent + github-tool pods to trigger the operator's reconciler"
  kubectl delete pod -n "$NS" -l "$AGENT_LABEL" --ignore-not-found
  kubectl delete pod -n "$NS" -l "$TOOL_LABEL" --ignore-not-found

  step "Waiting for NEW client uuids to appear [timeout ${TRIGGER_WAIT_SECS}s]"
  local deadline=$((SECONDS + TRIGGER_WAIT_SECS)) restarted_operator=0
  local new_agent_uuid="" new_tool_uuid=""
  while :; do
    ADMIN="$(admin_token)"
    new_agent_uuid="$(client_uuid_by_name "${NS}/github-agent" "$ADMIN")"
    new_tool_uuid="$(client_uuid_by_name "${NS}/github-tool" "$ADMIN")"
    if [ -n "$new_agent_uuid" ] && [ -n "$new_tool_uuid" ] \
       && [ "$new_agent_uuid" != "$old_agent_uuid" ] && [ "$new_tool_uuid" != "$old_tool_uuid" ]; then
      break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "operator never re-registered fresh clients within ${TRIGGER_WAIT_SECS}s (agent=${new_agent_uuid:-<none>}, tool=${new_tool_uuid:-<none>}). Check: kubectl logs deployment/rossoctl-controller-manager -n ${SYS_NS}"
    fi
    # The reconciler is driven by a watch on the Deployment/pod-template, not a periodic resync, so
    # if a bare pod restart didn't wake it, restart the operator — that re-lists every AgentRuntime.
    if [ "$restarted_operator" -eq 0 ] && [ "$SECONDS" -ge $((deadline - TRIGGER_WAIT_SECS / 2)) ]; then
      warn "no fresh registration yet at the halfway point — restarting the operator to force a full reconcile pass"
      kubectl rollout restart deployment/rossoctl-controller-manager -n "$SYS_NS" || true
      restarted_operator=1
    fi
    sleep 5
  done
  info "new agent client uuid: ${new_agent_uuid}"
  info "new tool client uuid:  ${new_tool_uuid}"
  pass "operator re-registered both clients with fresh uuids (a real CLIENT_CREATE just fired)"

  step "Waiting for github-agent + github-tool pods to become Ready again"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$AGENT_LABEL" --timeout="${DEPLOY_WAIT_SECS}s" \
    || die "github-agent did not become Ready after the forced restart"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$TOOL_LABEL" --timeout="${DEPLOY_WAIT_SECS}s" \
    || die "github-tool did not become Ready after the forced restart"
  pass "both workloads Ready"

  step "Confirming AIAC consumed the live event — NO manual onboarding call was made [polling up to ${POLL_SECS}s]"
  local ev_deadline=$((SECONDS + POLL_SECS)) found_agent=0 found_tool=0 logs
  while :; do
    logs=$(kubectl logs deployment/aiac-agent -n "$AIAC_NS" --since-time="${replay_start_ts}" 2>/dev/null || true)
    printf '%s\n' "$logs" | grep -q "$new_agent_uuid" && found_agent=1
    printf '%s\n' "$logs" | grep -q "$new_tool_uuid" && found_tool=1
    [ "$found_agent" -eq 1 ] && [ "$found_tool" -eq 1 ] && break
    if [ "$SECONDS" -ge "$ev_deadline" ]; then
      die "aiac-agent logs never mentioned the new client uuids (agent seen=${found_agent}, tool seen=${found_tool}) after ${POLL_SECS}s. Check: kubectl logs deployment/aiac-agent -n ${AIAC_NS}; kubectl logs statefulset/keycloak -n ${KC_NS} | grep -i aiac-event-listener"
    fi
    sleep 5
  done
  pass "aiac-agent consumed both aiac.apply.service.<uuid> events over NATS — no /apply/service/{id} call in this script"

  step "Confirming a fresh AuthorizationPolicy CR for github-agent [polling up to ${POLL_SECS}s]"
  local cr_start=$SECONDS cr_deadline=$((SECONDS + POLL_SECS)) cr_next_info=$((SECONDS + 30)) after_rv=""
  while :; do
    after_rv=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "")
    if [ -n "$after_rv" ] && [ "$after_rv" != "$before_rv" ]; then break; fi
    if [ "$SECONDS" -ge "$cr_deadline" ]; then
      die "github-agent AuthorizationPolicy CR resourceVersion never changed (still '${before_rv}') after ${POLL_SECS}s — AIAC may not have finished writing rules yet"
    fi
    if [ "$SECONDS" -ge "$cr_next_info" ]; then
      info "still waiting for AIAC to rewrite the CR ($((SECONDS - cr_start))s / ${POLL_SECS}s) — policy generation is LLM-bound; watch: kubectl logs -f deployment/aiac-agent -n ${AIAC_NS} | grep chat/completions"
      cr_next_info=$((SECONDS + 30))
    fi
    sleep 5
  done
  pass "github-agent AuthorizationPolicy CR resourceVersion changed: ${before_rv} -> ${after_rv} (AIAC-written, nobody hand-wrote this CR)"
  info "content:"
  kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.spec.policies[*].content}' | sed 's/^/    /'
}

if [ "$DO_DEPLOY" -eq 1 ]; then
  phase_deploy
  phase_verify_trigger
fi
[ "$DO_REPLAY" -eq 1 ] && phase_replay_trigger
[ "$DO_WIRE" -eq 1 ] && phase_wire_outbound
[ "$DO_ENFORCE" -eq 1 ] && phase_enforce

[ "$DO_COLLECT" -eq 1 ] && collect_logs "$COLLECT_DIR"

printf '\n%s%s====== DONE ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
cat <<EOF

Revert with: ./restore.sh
EOF
