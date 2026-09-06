#!/usr/bin/env bash
# uc1-integration-driver.sh — execute uc1-integration-runbook.md end-to-end (#646).
#
# Assumes uc1-integration-enable.sh has already wired the AIAC stack + NATS broker + Keycloak SPI
# listener, and aiac/demo/use-cases/uc1-onboarding's "make init" (keycloak/prereqs/clear/setup)
# has already run. This script proves the two things #646 actually asks for:
#
#   Phase TRIGGER   force + observe a live onboarding trigger (Keycloak client-create -> NATS ->
#                   AIAC), with NO POST /apply/service/{id} call anywhere in this script.
#   Phase WIRE      wire AuthBridge's own outbound leg (authproxy-routes + optional client-scope) —
#                   same two sub-steps as aiac/k8s/opa-kind-runbook.md Part B.1/B.2; AIAC's own
#                   onboarding does not do this.
#   Phase ENFORCE   real HTTP probes through the live AuthBridge OPA plugin, reproducing #646's
#                   acceptance table (inbound allow/deny is a hard assertion; the outbound
#                   per-tool matrix is reported and soft-checked — see uc1-integration-runbook.md's
#                   "Known gaps" section for why the fourth acceptance-table row, direct
#                   user-to-tool, isn't enforced by this deployment at all).
#
# Style mirrors aiac/k8s/opa-kind-driver.sh: step()/pass()/warn()/die(), fails loudly and
# specifically the moment an observed result doesn't match, rather than continuing silently.
#
# Usage:
#   ./uc1-integration-driver.sh                    # trigger -> wire -> enforce -> report
#   ./uc1-integration-driver.sh --only-trigger
#   ./uc1-integration-driver.sh --only-wire-outbound
#   ./uc1-integration-driver.sh --only-enforce
#
# Env vars (defaults match the rest of this demo family):
#   NS, SYS_NS, AIAC_NS   namespaces (team1, rossoctl-system, aiac-system)
#   KC, REALM             Keycloak base URL + realm
#   ROPC_CLIENT_ID        public client the Phase 1 demo's users log in with (default: aiac-demo-cli)
#   USER_PASSWORD         shared demo-user password (default: password) — see scenario.py
#   POLL_SECS             max seconds to wait for a bundle-service poll        (default: 150)
#   TRIGGER_WAIT_SECS     max seconds to wait for the operator to re-register  (default: 180)
#   KIND_CLUSTER          name of the Kind cluster                             (default: rossoctl)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORTEX_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

NS="${NS:-team1}"
SYS_NS="${SYS_NS:-rossoctl-system}"
AIAC_NS="${AIAC_NS:-aiac-system}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
ROPC_CLIENT_ID="${ROPC_CLIENT_ID:-aiac-demo-cli}"
USER_PASSWORD="${USER_PASSWORD:-password}"
POLL_SECS="${POLL_SECS:-150}"
TRIGGER_WAIT_SECS="${TRIGGER_WAIT_SECS:-180}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
TOOL_LABEL="app=github-tool"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

DO_TRIGGER=1
DO_WIRE=1
DO_ENFORCE=1
case "${1:-}" in
  --only-trigger) DO_WIRE=0; DO_ENFORCE=0 ;;
  --only-wire-outbound) DO_TRIGGER=0; DO_ENFORCE=0 ;;
  --only-enforce) DO_TRIGGER=0; DO_WIRE=0 ;;
  "") ;;
  *) echo "Usage: $0 [--only-trigger|--only-wire-outbound|--only-enforce]" >&2; exit 1 ;;
esac

# ── Output helpers (same palette/shape as opa-kind-driver.sh) ───────────────
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

# mint_token <user> — public ROPC client, USER_PASSWORD (not password==username, unlike the
# separate OPA-only runbook's dev-user/alice) — see scenario.py::USER_PASSWORD.
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
# field (e.g. "team1/github-agent"), not clientId (a SPIFFE URI) — same lookup as
# uc1-onboarding/lib/_lib.py's resolve_service_id(). Prints "" if not found (caller checks).
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

delete_client() {
  local uuid="$1" admin="$2"
  curl -s -o /dev/null -w "     delete client %{http_code}\n" -X DELETE \
    -H "Authorization: Bearer ${admin}" "${KC}/admin/realms/${REALM}/clients/${uuid}"
}

latest_pod() {
  kubectl get pod -n "$NS" -l "$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# ── Preflight ────────────────────────────────────────────────────────────────
printf '%s%sUC-1 Integration driver (#646 — live trigger + live enforcement)%s\n' "$C_BLD" "$C_CYN" "$C_RST"

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
  || die "aiac-agent not deployed in ${AIAC_NS} — run uc1-integration-enable.sh --stack-only first"
kubectl get deployment aiac-event-broker -n "$AIAC_NS" >/dev/null 2>&1 \
  || die "aiac-event-broker not deployed in ${AIAC_NS} — run uc1-integration-enable.sh --broker-only first"
kubectl get pod -n "$NS" -l "$AGENT_LABEL" >/dev/null 2>&1 \
  || die "github-agent not deployed in ${NS} — run the uc1-onboarding demo's 'make prereqs' first"
OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
              -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
[ "$OPA_COUNT" = "2" ] || die "OPA not wired into both AuthBridge legs (got ${OPA_COUNT}, expected 2) — run aiac/k8s/opa-kind-enable.sh first"
ADMIN="$(admin_token)"
[ -n "$ADMIN" ] || die "could not obtain a Keycloak master admin token"
LISTENERS=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/events/config" \
  | python3 -c 'import sys,json;print(",".join(json.load(sys.stdin).get("eventsListeners",[])))' 2>/dev/null || true)
case "$LISTENERS" in
  *aiac-event-listener*) ;;
  *) die "aiac-event-listener not enabled on realm '${REALM}' (listeners: ${LISTENERS:-<none>}) — run uc1-integration-enable.sh --spi-only first" ;;
esac
pass "preflight: AIAC stack + event broker + OPA pipeline + Keycloak SPI listener all present"

# ── Phase TRIGGER ─────────────────────────────────────────────────────────────
phase_trigger() {
  printf '\n%s%s====== Phase TRIGGER — force a fresh live onboarding event ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

  step "Recording the current AuthorizationPolicy CR (baseline, before the fresh trigger)"
  BEFORE_RV=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "<none>")
  info "github-agent AuthorizationPolicy resourceVersion (before): ${BEFORE_RV}"

  step "Recording current Keycloak client UUIDs for team1/github-agent, team1/github-tool"
  ADMIN="$(admin_token)"
  OLD_AGENT_UUID="$(client_uuid_by_name "team1/github-agent" "$ADMIN")"
  OLD_TOOL_UUID="$(client_uuid_by_name "team1/github-tool" "$ADMIN")"
  [ -n "$OLD_AGENT_UUID" ] || die "no Keycloak client named 'team1/github-agent' found — has it registered at all yet?"
  [ -n "$OLD_TOOL_UUID" ] || die "no Keycloak client named 'team1/github-tool' found — has it registered at all yet?"
  info "old agent client uuid: ${OLD_AGENT_UUID}"
  info "old tool client uuid:  ${OLD_TOOL_UUID}"

  step "Deleting both Keycloak clients (their CLIENT_CREATE already fired before the listener existed)"
  delete_client "$OLD_AGENT_UUID" "$ADMIN"
  delete_client "$OLD_TOOL_UUID" "$ADMIN"

  step "Restarting github-agent + github-tool pods to trigger the operator's reconciler"
  # ClientRegistrationReconciler calls RegisterOrFetchClientWithToken unconditionally on every
  # reconcile (operator/internal/controller/clientregistration_controller.go) — it does not skip
  # because a credentials Secret already exists — so a reconcile after the client is gone
  # re-creates it fresh, firing a genuine CLIENT_CREATE admin event.
  kubectl delete pod -n "$NS" -l "$AGENT_LABEL" --ignore-not-found
  kubectl delete pod -n "$NS" -l "$TOOL_LABEL" --ignore-not-found

  step "Waiting for NEW client uuids to appear [timeout ${TRIGGER_WAIT_SECS}s]"
  local deadline=$((SECONDS + TRIGGER_WAIT_SECS)) restarted_operator=0
  NEW_AGENT_UUID=""
  NEW_TOOL_UUID=""
  while :; do
    ADMIN="$(admin_token)"
    NEW_AGENT_UUID="$(client_uuid_by_name "team1/github-agent" "$ADMIN")"
    NEW_TOOL_UUID="$(client_uuid_by_name "team1/github-tool" "$ADMIN")"
    if [ -n "$NEW_AGENT_UUID" ] && [ -n "$NEW_TOOL_UUID" ] \
       && [ "$NEW_AGENT_UUID" != "$OLD_AGENT_UUID" ] && [ "$NEW_TOOL_UUID" != "$OLD_TOOL_UUID" ]; then
      break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "operator never re-registered fresh clients within ${TRIGGER_WAIT_SECS}s (agent=${NEW_AGENT_UUID:-<none>}, tool=${NEW_TOOL_UUID:-<none>}). Check: kubectl logs deployment/rossoctl-controller-manager -n rossoctl-system"
    fi
    if [ "$restarted_operator" -eq 0 ] && [ "$SECONDS" -ge $((deadline - TRIGGER_WAIT_SECS / 2)) ]; then
      warn "no fresh registration yet at the halfway point — restarting the operator to force a full reconcile pass"
      kubectl rollout restart deployment/rossoctl-controller-manager -n rossoctl-system || true
      restarted_operator=1
    fi
    sleep 5
  done
  info "new agent client uuid: ${NEW_AGENT_UUID}"
  info "new tool client uuid:  ${NEW_TOOL_UUID}"
  pass "operator re-registered both clients with fresh uuids (a real CLIENT_CREATE just fired)"

  step "Waiting for github-agent + github-tool pods to become Ready again"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$AGENT_LABEL" --timeout=180s \
    || die "github-agent did not become Ready after the forced restart"
  kubectl wait --for=condition=ready pod -n "$NS" -l "$TOOL_LABEL" --timeout=120s \
    || die "github-tool did not become Ready after the forced restart"
  pass "both workloads Ready"

  step "Confirming AIAC consumed the live event — NO manual onboarding call was made"
  local ev_deadline=$((SECONDS + POLL_SECS)) found_agent=0 found_tool=0
  while :; do
    local logs
    logs=$(kubectl logs deployment/aiac-agent -n "$AIAC_NS" --tail=500 2>/dev/null || true)
    printf '%s\n' "$logs" | grep -q "$NEW_AGENT_UUID" && found_agent=1
    printf '%s\n' "$logs" | grep -q "$NEW_TOOL_UUID" && found_tool=1
    [ "$found_agent" -eq 1 ] && [ "$found_tool" -eq 1 ] && break
    if [ "$SECONDS" -ge "$ev_deadline" ]; then
      die "aiac-agent logs never mentioned the new client uuids (agent seen=${found_agent}, tool seen=${found_tool}) after ${POLL_SECS}s. Check: kubectl logs deployment/aiac-agent -n ${AIAC_NS}; kubectl logs statefulset/keycloak -n keycloak | grep -i aiac-event-listener"
    fi
    sleep 5
  done
  pass "aiac-agent consumed both aiac.apply.service.<uuid> events over NATS — no /apply/service/{id} call in this script"

  step "Confirming a fresh AuthorizationPolicy CR for github-agent"
  local cr_deadline=$((SECONDS + POLL_SECS))
  AFTER_RV=""
  while :; do
    AFTER_RV=$(kubectl get "$POLICY_CR" github-agent -n "$NS" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || echo "")
    if [ -n "$AFTER_RV" ] && [ "$AFTER_RV" != "$BEFORE_RV" ]; then break; fi
    if [ "$SECONDS" -ge "$cr_deadline" ]; then
      die "github-agent AuthorizationPolicy CR resourceVersion never changed (still '${BEFORE_RV}') after ${POLL_SECS}s — AIAC may not have finished writing rules yet"
    fi
    sleep 5
  done
  pass "github-agent AuthorizationPolicy CR resourceVersion changed: ${BEFORE_RV} -> ${AFTER_RV} (AIAC-written, nobody hand-wrote this CR)"
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

# probe_agent <user> <want_code> <secs> <label> — same shape as opa-kind-driver.sh's probe_expect.
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

# probe_tool <user> <tool_name> — real tools/call through the agent's forward proxy (127.0.0.1:8081),
# exactly like opa-kind-driver.sh Part B but calling a real tool instead of tools/list. Echoes a
# VERDICT string: ALLOWED_RESULT | DENIED_JSONRPC | "DENIED_HTTP <code>" | ERROR | UNEXPECTED.
probe_tool() {
  local user="$1" tool="$2" pod tok py out
  pod="$(latest_pod "$AGENT_LABEL")"
  [ -n "$pod" ] || { echo "ERROR"; return 0; }
  tok="$(mint_token "$user")"
  py="$(mktemp /tmp/uc1-integration-probe.XXXXXX.py)"
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
  # Hard-check the one row #646's table states unambiguously for both roles: dev-user (developer,
  # "works primarily in source") must be able to read source; test-user (tester, "works in the
  # issue tracker, not in source") must be denied reading source. The full 4x2 matrix above is
  # AIAC/LLM-generated from policy.md at onboarding time — reported for the record rather than
  # hard-asserted in full, since the exact LLM output can reasonably vary at the edges.
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

  warn "known gap: 'direct dev-user -> github-tool, no agent' (row 4 of #646's table) is NOT enforced by this deployment — github-tool has no AuthBridge sidecar and no auth of its own (see uc1-integration-runbook.md's 'Known gaps' section). Not probed here to avoid reporting a fabricated result."
}

[ "$DO_TRIGGER" -eq 1 ] && phase_trigger
[ "$DO_WIRE" -eq 1 ] && phase_wire_outbound
[ "$DO_ENFORCE" -eq 1 ] && phase_enforce

printf '\n%s%s====== DONE ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
cat <<EOF

Revert with: ./uc1-integration-restore.sh
EOF
