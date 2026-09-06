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
#
# Env vars (defaults match the rest of this demo family):
#   NS, SYS_NS, AIAC_NS   namespaces (team1, rossoctl-system, aiac-system)
#   KC, REALM             Keycloak base URL + realm
#   ROPC_CLIENT_ID        public client the Phase 1 demo's users log in with (default: aiac-demo-cli)
#   USER_PASSWORD         shared demo-user password (default: password) — see scenario.py
#   POLL_SECS             max seconds to wait for a bundle-service poll / trigger evidence (default: 150)
#   DEPLOY_WAIT_SECS      max seconds to wait for pods to become Ready after deploy   (default: 180)
#   KIND_CLUSTER          name of the Kind cluster                             (default: rossoctl)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORTEX_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSETS_DIR="$CORTEX_DIR/aiac/demo/assets"

NS="${NS:-team1}"
SYS_NS="${SYS_NS:-rossoctl-system}"
AIAC_NS="${AIAC_NS:-aiac-system}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
ROPC_CLIENT_ID="${ROPC_CLIENT_ID:-aiac-demo-cli}"
USER_PASSWORD="${USER_PASSWORD:-password}"
POLL_SECS="${POLL_SECS:-150}"
DEPLOY_WAIT_SECS="${DEPLOY_WAIT_SECS:-180}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
TOOL_LABEL="app=github-tool"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

DO_DEPLOY=1
DO_WIRE=1
DO_ENFORCE=1
case "${1:-}" in
  --only-deploy) DO_WIRE=0; DO_ENFORCE=0 ;;
  --only-wire-outbound) DO_DEPLOY=0; DO_ENFORCE=0 ;;
  --only-enforce) DO_DEPLOY=0; DO_WIRE=0 ;;
  "") ;;
  *) echo "Usage: $0 [--only-deploy|--only-wire-outbound|--only-enforce]" >&2; exit 1 ;;
esac

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
die()  { printf '\n%sFAIL:%s %s\n' "$C_RED$C_BLD" "$C_RST" "$*" >&2; exit 1; }

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

  step "Confirming AIAC consumed the live event — NO manual onboarding call was made"
  # aiac-agent's LangChain tracing + constant health-check logging can push a target UUID's
  # log lines well past any fixed --tail count within seconds (observed: >500 lines of other
  # chatter between one event's own "received" and "acked" lines) — a --since-time scoped to
  # when this run's DEPLOY started is immune to log volume, unlike --tail=N.
  local ev_deadline=$((SECONDS + POLL_SECS)) found_agent=0 found_tool=0
  while :; do
    local logs
    logs=$(kubectl logs deployment/aiac-agent -n "$AIAC_NS" --since-time="${UC1E2E_DEPLOY_START_TS}" 2>/dev/null || true)
    printf '%s\n' "$logs" | grep -q "$AGENT_UUID" && found_agent=1
    printf '%s\n' "$logs" | grep -q "$TOOL_UUID" && found_tool=1
    [ "$found_agent" -eq 1 ] && [ "$found_tool" -eq 1 ] && break
    if [ "$SECONDS" -ge "$ev_deadline" ]; then
      die "aiac-agent logs never mentioned the new client uuids (agent seen=${found_agent}, tool seen=${found_tool}) after ${POLL_SECS}s. Check: kubectl logs deployment/aiac-agent -n ${AIAC_NS}; kubectl logs statefulset/keycloak -n keycloak | grep -i aiac-event-listener"
    fi
    sleep 5
  done
  pass "aiac-agent consumed both aiac.apply.service.<uuid> events over NATS — no /apply/service/{id} call anywhere in this script"

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
req = urllib.request.Request("http://github-tool:9090/", data=body,
    headers={"Content-Type":"application/json","Authorization":"Bearer "+tok})
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

printf '\n%s%s====== DONE ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
cat <<EOF

Revert with: ./uc1-e2e-restore.sh
EOF
