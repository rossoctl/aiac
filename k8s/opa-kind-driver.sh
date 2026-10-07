#!/usr/bin/env bash
# opa-kind-driver.sh — execute k8s/opa-kind-runbook.md end-to-end.
#
# This is an automated driver for the AIAC "OPA Kind Cluster Runbook"
# (k8s/opa-kind-runbook.md). It runs every step of that runbook in
# order, prints each step and the result it obtained, prints the OPA `input`
# documents for BOTH the inbound and the outbound legs, and FAILS with a clear
# message the moment an observed result does not match the runbook's stated
# expectation (instead of silently continuing).
#
# What it does, mirroring the runbook 1:1:
#   Step 1   enable OPA in both legs               (opa-kind-enable.sh: its 4 steps —
#            bundle service + the changed combiner (D20), authbridge image,
#            pipeline, restart of the agent AND tool pods), then check the
#            OPA count (2) and the changed combiner (0 request / 2 response
#            fallback rules)
#   Step 2   verify the starting point             (agent + tool pods 2/2,
#            bundle-service, the combiner, the AIAC CRs, client-id)
#   Part A   inbound authorization
#     A.1    dev-user token carries sub=dev-user
#     A.2    baseline: with no client CR the changed combiner (D20) denies
#            dev-user AND alice (HTTP 403); if AIAC has already onboarded
#            github-agent, its AIAC CR decides (the A.4 result)
#     A.3    apply the two example CRs (target side: github-agent = agent
#            inbound + pass-through outbound; github-tool = tool inbound +
#            pass-through outbound)
#     A.4    enforced: dev-user -> 200, alice -> 403
#     A.5    print the INBOUND OPA input + assert the decision result
#   Part B   outbound token-exchange + OPA (no other CR: A.3 gave github-tool
#            its CR, and github-tool's inbound decides the call)
#     B.1    add the github-tool outbound route
#     B.2    grant github-agent the exchange scope   (expect HTTP 204)
#     B.3    restart github-agent to load the route
#     B.4    outbound tools/list probe as dev-user to github-tool:9090/mcp
#            (with the MCP Accept header) -> ALLOWED: github-agent's outbound
#            pass-through lets it through, github-tool's inbound session rule
#            allows it, and the reply is a JSON-RPC result frame that lists
#            the four tools. Any deny (a 403 from github-tool's inbound, an
#            OPA error frame at HTTP 200), a 503, or an app 4xx is a FAIL
#     B.5    print the OUTBOUND OPA input (github-agent) and the decision of
#            github-tool's inbound OPA
#
# Not driven: Part C (switch the enforcement side). It patches the AIAC
# Controller ConfigMap and restarts the Controller, so it is a manual step.
# Cleanup is printed at the end, not run.
#
# Requires: kubectl, helm, kind, python3, curl, and docker (or podman).
# Env vars (runbook defaults shown):
#   OPERATOR_DIR   path to the rossoctl/operator clone   (default: ../operator)
#   ROSSOCTL_DIR   path to the rossoctl/rossoctl clone    (default: ../rossoctl)
#   CORTEX_DIR     path to the rossoctl/cortex clone      (default: ../cortex);
#                  the enable step builds the authbridge-proxy image from it
#   NS             agent namespace                        (default: team1)
#   SYS_NS         platform namespace                     (default: rossoctl-system)
#   KC             Keycloak base URL          (default: http://keycloak.localtest.me:8080)
#   REALM          Keycloak realm                         (default: rossoctl)
#   POLL_SECS      max seconds to wait for OPA to poll a new bundle (default: 150).
#                  The OPA SDK bundle poller uses min_delay 10s / max_delay 120s,
#                  so a freshly applied CR can take up to ~120s to reach the
#                  agent; the default leaves margin above that worst case.
#   SKIP_ENABLE    if set to 1, skip Step 1's image rebuild + opa-kind-enable.sh
#                  and only verify OPA is already wired (fast path when iterating
#                  on the policy CR against an already-enabled cluster).
#   KIND_CLUSTER   name of the Kind cluster                (default: rossoctl).
#                  Preflight uses this to re-export the kubeconfig if the cluster
#                  is unreachable — a Kind node reassigns its API-server host port
#                  on restart, which leaves the exported kubeconfig stale.
#
# Run from the repo root:
#   OPERATOR_DIR=../operator ROSSOCTL_DIR=../rossoctl CORTEX_DIR=../cortex ./k8s/opa-kind-driver.sh
#   SKIP_ENABLE=1 ./k8s/opa-kind-driver.sh   # skip the rebuild, just re-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Configuration (runbook defaults) ────────────────────────────────────────
# Sibling repo clones the enable step needs; default to ../operator,
# ../rossoctl and ../cortex (relative to this repo root) when not set,
# mirroring opa-kind-enable.sh.
OPERATOR_DIR="${OPERATOR_DIR:-$(cd "$REPO_ROOT/../operator" 2>/dev/null && pwd || echo "")}"
ROSSOCTL_DIR="${ROSSOCTL_DIR:-$(cd "$REPO_ROOT/../rossoctl" 2>/dev/null && pwd || echo "")}"
CORTEX_DIR="${CORTEX_DIR:-$(cd "$REPO_ROOT/../cortex" 2>/dev/null && pwd || echo "")}"

NS="${NS:-team1}"
SYS_NS="${SYS_NS:-rossoctl-system}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
POLL_SECS="${POLL_SECS:-150}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
TOOL_LABEL="app=github-tool"
EXPECTED_SPIFFE="spiffe://localtest.me/ns/${NS}/sa/github-agent"
# The AuthorizationPolicy CRD, fully qualified (Istio has a kind of the same name).
AP_RES="authorizationpolicies.agent.rossoctl.dev"
MANAGED_BY="aiac-pdp-policy-writer"
POLICY_FILE="${REPO_ROOT}/docs/examples/opa-team1-policy.yaml"
ENABLE_SCRIPT="${SCRIPT_DIR}/opa-kind-enable.sh"
RESTORE_SCRIPT="${SCRIPT_DIR}/opa-kind-restore.sh"

# ── Output helpers ──────────────────────────────────────────────────────────
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

# expect_eq <label> <got> <want>  — pass or die
expect_eq() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    pass "${label}: got '${got}' (expected '${want}')"
  else
    die "${label}: got '${got}', expected '${want}'"
  fi
}

require_cmd() {
  local missing=()
  for c in kubectl helm kind python3 curl; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if ! command -v docker >/dev/null 2>&1 && ! command -v podman >/dev/null 2>&1; then
    missing+=("docker|podman")
  fi
  if [ "${#missing[@]}" -gt 0 ]; then
    die "missing required commands on PATH: ${missing[*]}"
  fi
}

# ── Keycloak helpers (from runbook A.1 / A.2 / B.2) ──────────────────────────
# mint_token <user>  — password grant, prints the access_token. On failure it
# surfaces Keycloak's actual error/error_description (e.g. unauthorized_client,
# invalid_grant) instead of guessing, and points at the exact prerequisite that
# is usually missing.
mint_token() {
  local user="$1" resp tok err
  # DEV ONLY: password == username, valid only for this Kind dev cluster's seeded
  # users (see opa-kind-runbook.md prerequisites). Never cargo-copy this grant into
  # a staging/production script — real users do not have password == username.
  resp=$(curl -s -X POST "${KC}/realms/${REALM}/protocol/openid-connect/token" \
          -d client_id=rossoctl -d "username=${user}" -d "password=${user}" \
          -d grant_type=password -d scope=openid || true)
  tok=$(printf '%s' "$resp" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("access_token","") or "")
except Exception: print("")' 2>/dev/null || true)
  if [ -z "$tok" ]; then
    err=$(printf '%s' "$resp" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
    print((d.get("error","?")+": "+d.get("error_description","")).strip())
except Exception:
    print("no/invalid JSON from the token endpoint (is Keycloak reachable at the URL above?)")' 2>/dev/null || true)
    die "could not mint a token for user '${user}' at ${KC} — Keycloak said: ${err}
     Keycloak Prerequisites (k8s/opa-kind-runbook.md): in realm '${REALM}' the
     'rossoctl' client needs Direct Access Grants enabled + a username->sub protocol
     mapper, and users must exist with password == username."
  fi
  printf '%s' "$tok"
}

# token_sub <token>  — decode the JWT payload and print the 'sub' claim.
# Tolerates an empty/malformed token (prints nothing) rather than throwing a
# Python traceback, so a caller's own assertion produces the failure message.
token_sub() {
  printf '%s' "$1" | python3 -c '
import sys,json,base64
t=sys.stdin.read().strip().split(".")
if len(t) < 2:
    print(""); raise SystemExit(0)
p=t[1]; p+="="*(-len(p)%4)
try:
    print(json.loads(base64.urlsafe_b64decode(p)).get("sub","") or "")
except Exception:
    print("")'
}

# admin_token  — realm master admin token for Keycloak admin API (B.2)
admin_token() {
  local tok
  # DEV ONLY: admin/admin is the seeded Kind cluster default — never copy into
  # staging/production scripts; real deployments do not have password == username.
  tok=$(curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
          -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || true)
  [ -n "$tok" ] || die "could not obtain a Keycloak master admin token (admin/admin) at ${KC}"
  printf '%s' "$tok"
}

# ── Cluster helpers ──────────────────────────────────────────────────────────
latest_agent_pod() {
  kubectl get pod -n "$NS" -l "$AGENT_LABEL" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

latest_tool_pod() {
  kubectl get pod -n "$NS" -l "$TOOL_LABEL" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# expect_pod_2of2 <name> <label>  — wait for the pod to become Ready after the
# Step 1 restart, then assert every container (app + authbridge-proxy) is ready.
expect_pod_2of2() {
  local name="$1" label="$2" pod states ready total
  info "waiting for ${name} to become Ready after the Step 1 restart (timeout 180s)..."
  kubectl wait --for=condition=ready pod -n "$NS" -l "$label" --timeout=180s \
    || die "${name} did not become Ready within 180s after the Step 1 restart. Check: kubectl get pods -n ${NS} -l ${label}"
  pod=$(kubectl get pod -n "$NS" -l "$label" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "$pod" ] || die "no ${name} pod in namespace ${NS}"
  states=$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null)
  info "${name} pod: ${pod}   container ready states: [${states}]"
  ready=$(printf '%s' "$states" | grep -o 'true' | wc -l | tr -d ' ' || true)
  total=$(printf '%s' "$states" | wc -w | tr -d ' ')
  if [ "$ready" = "$total" ] && [ "$total" -ge 2 ]; then
    pass "${name} is ${ready}/${total} (app + authbridge-proxy sidecar Ready)"
  else
    die "${name} is ${ready}/${total} ready — expected 2/2. Check: kubectl get pods -n ${NS} -l ${label}"
  fi
}

# check_combiner  — the changed combiner (D20, runbook Step 1): 0 request
# fallback rules (a pod with no client CR is denied), 2 response fallback rules.
check_combiner() {
  local content req resp
  content=$(kubectl get "$AP_RES" default -n "$SYS_NS" \
              -o jsonpath='{.spec.policies[*].content}' 2>/dev/null || true)
  [ -n "$content" ] || die "the global combiner (AuthorizationPolicy 'default' in ${SYS_NS}) is missing or empty"
  req=$(printf '%s\n' "$content" \
          | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.request' || true)
  resp=$(printf '%s\n' "$content" \
           | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.response' || true)
  expect_eq "combiner request fallback rules (changed combiner, D20)" "$req" "0"
  expect_eq "combiner response fallback rules" "$resp" "2"
}

# cr_owner <name>  — "absent" when the client CR <name> in NS does not exist,
# "aiac" when it carries the AIAC managed-by label (AIAC onboarded the service),
# else "hand" (applied by hand, e.g. by an earlier run of this driver).
cr_owner() {
  local name="$1" label
  if ! kubectl get "$AP_RES" "$name" -n "$NS" >/dev/null 2>&1; then
    printf 'absent'; return 0
  fi
  label=$(kubectl get "$AP_RES" "$name" -n "$NS" \
            -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null || true)
  if [ "$label" = "$MANAGED_BY" ]; then printf 'aiac'; else printf 'hand'; fi
}

# probe_as <user>  — mint a user token, POST the ping/nonexistent JSON-RPC body
# to github-agent from a throwaway pod (runbook A.2). Echoes "<code>|<body>".
probe_as() {
  local user="$1" tok out code body
  tok="$(mint_token "$user")"
  # $TOK is expanded by the sh in the probe pod (--env), not here.
  # shellcheck disable=SC2016
  out=$(kubectl run "probe-${user}-$RANDOM" --rm -i --restart=Never \
          --image=curlimages/curl:8.10.1 -n "$NS" --env="TOK=$tok" -- sh -c \
          'curl -s -m 15 -w "\nHTTP_CODE:%{http_code}\n" \
             -X POST http://github-agent.team1.svc.cluster.local:8080/ \
             -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" \
             -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping/nonexistent\",\"params\":{}}"' \
        2>/dev/null || true)
  code=$(printf '%s' "$out" | grep -o 'HTTP_CODE:[0-9]*' | tail -1 | cut -d: -f2 || true)
  body=$(printf '%s' "$out" | grep -vE 'HTTP_CODE:|deleted' | tr -d '\r' | grep -v '^$' | tail -1 || true)
  [ -n "$code" ] || die "probe as '${user}' produced no HTTP status (pod output: ${out})"
  printf '%s|%s' "$code" "$body"
}

# probe_expect <user> <want_code> <secs> <label>  — poll probe_as until it
# returns want_code (tolerates transient 502/000 while the app finishes binding
# its HTTP port, and the OPA bundle-poll delay after a CR change — up to ~120s,
# the SDK's max_delay_seconds), or die after <secs>.
probe_expect() {
  local user="$1" want="$2" secs="$3" label="$4"
  local deadline=$((SECONDS + secs)) res code body
  while :; do
    res="$(probe_as "$user")"; code="${res%%|*}"; body="${res#*|}"
    if [ "$code" = "$want" ]; then
      info "probe_as ${user}: HTTP ${code}  body: ${body}"
      pass "${label}: HTTP ${code} (expected ${want})"
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      info "probe_as ${user}: HTTP ${code}  body: ${body}"
      die "${label}: got HTTP ${code}, expected ${want} after ${secs}s. body: ${body}"
    fi
    info "probe_as ${user}: HTTP ${code} — retrying (want ${want})..."
    sleep 5
  done
}

# dump_opa_input <inbound|outbound> [agent|tool]  — print the last OPA-input log
# line that the sidecar of github-agent (the default) or github-tool emitted for
# that leg to the terminal, and stash it in the global LAST_OPA_LINE (so callers
# can assert on it without swallowing the display).
LAST_OPA_LINE=""
dump_opa_input() {
  local direction="$1" who="${2:-agent}" pod line upper
  if [ "$who" = "tool" ]; then pod="$(latest_tool_pod)"; else pod="$(latest_agent_pod)"; fi
  [ -n "$pod" ] || die "no github-${who} pod found while capturing ${direction} OPA input"
  line=$(kubectl logs -n "$NS" "$pod" -c authbridge-proxy --tail=500 2>/dev/null \
         | grep "path=authbridge/${direction}/request" | tail -1 || true)
  upper=$(printf '%s' "$direction" | tr '[:lower:]' '[:upper:]')
  printf '\n%s----- github-%s %s OPA INPUT (as logged by the authbridge-proxy sidecar) -----%s\n' \
    "$C_BLD" "$who" "$upper" "$C_RST"
  if [ -n "$line" ]; then
    printf '%s\n' "$line"
  else
    warn "no '${direction}' decision-log line found yet (decision_logs.console formatting is environment-dependent)"
  fi
  LAST_OPA_LINE="$line"
}

# ── Preflight ────────────────────────────────────────────────────────────────
printf '%s%sAIAC OPA Kind runbook driver%s\n' "$C_BLD" "$C_CYN" "$C_RST"
info "runbook: k8s/opa-kind-runbook.md   namespace: ${NS}   keycloak: ${KC}"

step "Preflight — required tooling and files"
require_cmd
[ -f "$POLICY_FILE" ]    || die "policy CR not found: ${POLICY_FILE}"
[ -x "$ENABLE_SCRIPT" ]  || die "enable script not found/executable: ${ENABLE_SCRIPT}"
[ -x "$RESTORE_SCRIPT" ] || die "restore script not found/executable: ${RESTORE_SCRIPT}"
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
pass "tooling present, policy CR + helper scripts found, cluster reachable"

# ── Step 1 — Enable OPA in both legs ─────────────────────────────────────────
if [ "${SKIP_ENABLE:-}" = "1" ]; then
  step "Step 1 — Enable OPA in both legs  [SKIPPED: SKIP_ENABLE=1]"
  info "skipping the image rebuild + opa-kind-enable.sh; verifying OPA is already wired"
else
  step "Step 1 — Enable OPA in both legs (opa-kind-enable.sh)"
  # `[ -d "" ]` is false, so one test also catches an unset or empty value.
  [ -d "${OPERATOR_DIR:-}" ] \
    || die "OPERATOR_DIR must point to a rossoctl/operator clone (got: '${OPERATOR_DIR:-<unset>}')"
  [ -d "${ROSSOCTL_DIR:-}" ] \
    || die "ROSSOCTL_DIR must point to a rossoctl/rossoctl clone (got: '${ROSSOCTL_DIR:-<unset>}')"
  [ -d "${CORTEX_DIR:-}" ] \
    || die "CORTEX_DIR must point to a rossoctl/cortex clone (got: '${CORTEX_DIR:-<unset>}')"
  info "running enable script (its 4 steps: bundle service + the changed combiner, authbridge-proxy image, pipeline helm upgrade, restart of the agent and tool pods)..."
  OPERATOR_DIR="$OPERATOR_DIR" ROSSOCTL_DIR="$ROSSOCTL_DIR" CORTEX_DIR="$CORTEX_DIR" "$ENABLE_SCRIPT" \
    || die "opa-kind-enable.sh failed"
fi

info "confirming OPA is wired into BOTH legs (expect 2)"
OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
              -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
if [ "$OPA_COUNT" = "2" ]; then
  pass "'name: opa' occurrences in authbridge-runtime-config: got '2' (expected '2')"
elif [ "${SKIP_ENABLE:-}" = "1" ]; then
  die "OPA is not wired into both legs (found ${OPA_COUNT}, expected 2), but SKIP_ENABLE=1 skipped the enable step. Re-run WITHOUT SKIP_ENABLE to run opa-kind-enable.sh first."
else
  die "'name: opa' occurrences in authbridge-runtime-config: got '${OPA_COUNT}', expected '2'"
fi

info "checking the changed combiner (D20): expect 0 request and 2 response fallback rules"
check_combiner

# ── Step 2 — Verify the starting point ───────────────────────────────────────
step "Step 2 — Verify the starting point"

# github-agent and github-tool should be 2/2 (app + authbridge-proxy sidecar)
# and Ready. Step 1 (opa-kind-enable.sh) restarts the agent AND the tool pods,
# so wait for the fresh pods to come up before asserting readiness. The tool
# has the sidecar only with injectTools=true (set by the enable step).
expect_pod_2of2 github-agent "$AGENT_LABEL"
expect_pod_2of2 github-tool "$TOOL_LABEL"

# bundle-service up and serving
BS_PHASE=$(kubectl get pods -n "$SYS_NS" -l app=bundle-service \
             -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)
expect_eq "bundle-service pod phase" "${BS_PHASE:-<none>}" "Running"

# the global combiner 'default' (scope global) — the changed one, see Step 1
GLOBAL_SCOPE=$(kubectl get "$AP_RES" default -n "$SYS_NS" -o jsonpath='{.spec.scope}' 2>/dev/null || true)
expect_eq "global AuthorizationPolicy 'default' in ${SYS_NS} scope" "${GLOBAL_SCOPE:-<none>}" "global"

# the AIAC CRs: one per managed service (none before the first onboarding)
AIAC_CRS=$(kubectl get "$AP_RES" -A -l "app.kubernetes.io/managed-by=${MANAGED_BY}" \
             -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}' 2>/dev/null || true)
info "AIAC CRs (managed-by=${MANAGED_BY}): ${AIAC_CRS:-none}"

# github-agent SPIFFE ID — the client-scoped policy targets this
CLIENT_ID=$(kubectl exec -n "$NS" "deploy/github-agent" -c authbridge-proxy \
              -- cat /shared/client-id.txt 2>/dev/null | tr -d '\r\n' || true)
info "github-agent client-id.txt: ${CLIENT_ID}"
expect_eq "github-agent SPIFFE ID" "$CLIENT_ID" "$EXPECTED_SPIFFE"

# ── Part A — Inbound authorization ───────────────────────────────────────────
printf '\n%s%s====== Part A — Inbound authorization ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"

step "A.1 — dev-user token carries sub=dev-user"
# The rossoctl client's own username->sub mapper sets the sub of this login token.
# Exchanged tokens (B.4) get the same mapping from the client scope
# aiac-username-sub, which AIAC links to each managed client at onboarding (D31).
# Mint first (mint_token dies with Keycloak's real error if the grant fails),
# then decode — so a mint failure aborts here under set -e rather than feeding
# an empty token into token_sub.
DEV_TOKEN="$(mint_token dev-user)"
DEV_SUB="$(token_sub "$DEV_TOKEN")"
info "decoded sub claim: ${DEV_SUB}"
expect_eq "dev-user token sub claim" "$DEV_SUB" "dev-user"

step "A.2 — Baseline: before any client CR, the changed combiner (D20) denies BOTH users (HTTP 403)"
# Make the baseline meaningful on re-runs: a github-agent CR applied by hand
# (an earlier run's A.3) is deleted, so "before any client CR" is actually true.
# An AIAC CR (AIAC has already onboarded github-agent) stays: it decides
# instead, and the result is the same as in A.4.
AGENT_CR_OWNER="$(cr_owner github-agent)"
info "github-agent client CR: ${AGENT_CR_OWNER}"
if [ "$AGENT_CR_OWNER" = "hand" ]; then
  info "a hand-applied github-agent CR is in place — deleting it so the baseline is clean"
  kubectl delete "$AP_RES" github-agent -n "$NS" --ignore-not-found >/dev/null \
    || die "could not delete the hand-applied github-agent CR"
  AGENT_CR_OWNER="absent"
fi
# Dropping the CR from the bundle is bundle-poll bound (up to ~120s), and a
# freshly restarted pod returns 503 until its first bundle loads, so give the
# baseline the same window as the enforced flip below.
if [ "$AGENT_CR_OWNER" = "aiac" ]; then
  info "AIAC has already onboarded github-agent: its AIAC CR decides (the A.4 result)"
  probe_expect dev-user 200 "$POLL_SECS" "baseline probe as dev-user (AIAC CR)"
  probe_expect alice    403 "$POLL_SECS" "baseline probe as alice (AIAC CR)"
else
  probe_expect dev-user 403 "$POLL_SECS" "baseline probe as dev-user (no client CR: denied by the changed combiner)"
  probe_expect alice    403 "$POLL_SECS" "baseline probe as alice (no client CR: denied by the changed combiner)"
fi

step "A.3 — Apply the two example CRs (target side: github-agent + github-tool)"
# If AIAC has already onboarded a service, A.3 replaces its AIAC CR by hand.
# AIAC writes it again at the next deploy of that service or at the next
# Controller start (the resync, D28).
for svc in github-agent github-tool; do
  if [ "$(cr_owner "$svc")" = "aiac" ]; then
    warn "${svc} has an AIAC CR: A.3 replaces it by hand (AIAC writes it again at the next deploy or Controller start)"
  fi
done
kubectl apply -f "$POLICY_FILE" || die "kubectl apply -f ${POLICY_FILE} failed"
info "applied $(basename "$POLICY_FILE") (github-agent: agent inbound + pass-through outbound; github-tool: tool inbound + pass-through outbound)"
info "bundle-service rebuilds the team1 bundle, OPA polls on its own interval"

step "A.4 — Enforced: dev-user allowed (200), alice blocked (403)  [polling up to ${POLL_SECS}s]"
# alice flips to 403 once OPA picks up the new bundle; poll for it.
probe_expect alice    403 "$POLL_SECS" "enforced probe as alice (blocked by OPA, never reaches the app)"
probe_expect dev-user 200 "$POLL_SECS"  "enforced probe as dev-user (allowed)"

step "A.5 — The INBOUND OPA input, exactly (+ decision result)"
# Re-probe dev-user to make sure a fresh inbound decision is in the log tail.
probe_as dev-user >/dev/null || true
dump_opa_input inbound
INBOUND_LINE="$LAST_OPA_LINE"
printf '\n'
if [ -n "$INBOUND_LINE" ]; then
  # dev-user's decision should be allow:true; alice's earlier decision allow:false.
  if printf '%s' "$INBOUND_LINE" | grep -q 'allow:true'; then
    pass "inbound decision for dev-user shows allow:true"
  else
    warn "could not confirm 'allow:true' on the captured inbound line (formatting may differ); line printed above"
  fi
  ALICE_LINE=$(kubectl logs -n "$NS" "$(latest_agent_pod)" -c authbridge-proxy --tail=500 2>/dev/null \
               | grep 'path=authbridge/inbound/request' | grep 'allow:false' | tail -1 || true)
  if [ -n "$ALICE_LINE" ]; then
    pass "an inbound decision with allow:false is present (alice denied)"
  else
    warn "no inbound allow:false decision line found in the tail (alice's may have rotated out)"
  fi
else
  warn "no inbound OPA input captured — decision_logs.console may format differently in this build"
fi

# Reference: the canonical inbound input shape from the runbook (A.5).
cat <<'JSON'
     ----- INBOUND OPA INPUT — canonical shape (runbook A.5, for comparison) -----
     {
       "direction": "inbound",
       "method": "POST",
       "path": "/",
       "host": "github-agent.team1.svc.cluster.local:8080",
       "headers": { "accept": "*/*", "content-type": "application/json", ... },
       "identity": {
         "subject": "dev-user",
         "client_id": "rossoctl",
         "scopes": ["...", "agent-team1-github-agent-aud", "openid", "profile", "email"]
       }
     }
     (credential headers like authorization/cookie are redacted; use identity for decisions)
JSON

# ── Part B — Outbound token-exchange + OPA ───────────────────────────────────
printf '\n%s%s====== Part B — Outbound token-exchange + OPA ======%s\n' "$C_BLD" "$C_CYN" "$C_RST"
# Target side (the example): github-agent's outbound is a pass-through, and
# github-tool's inbound (the github-tool CR that A.3 applied) decides the call.
# Part B applies no other CR.
TOOL_CR_OWNER="$(cr_owner github-tool)"
[ "$TOOL_CR_OWNER" != "absent" ] \
  || die "github-tool has no client CR: A.3 must apply it (docs/examples/opa-team1-policy.yaml). Under the changed combiner (D20) its inbound denies every call."
info "github-tool client CR: ${TOOL_CR_OWNER} (from A.3)"

step "B.1 — Add the github-tool outbound route to authproxy-routes"
kubectl patch configmap authproxy-routes -n "$NS" --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml":
"""- host: \"weather-tool-advanced-mcp\"
  target_audience: \"spiffe://localtest.me/ns/team1/sa/weather-tool-advanced\"
  token_scopes: \"openid weather-tool-exchange-aud\"
- host: \"github-tool\"
  target_audience: \"spiffe://localtest.me/ns/team1/sa/github-tool\"
  token_scopes: \"openid agent-team1-github-tool-aud\"
"""}}))')" || die "failed to patch authproxy-routes ConfigMap"
pass "authproxy-routes now carries the weather + github-tool routes"

step "B.2 — Grant github-agent the exchange scope (expect HTTP 204)"
ADMIN="$(admin_token)"
CID=$(curl -s -H "Authorization: Bearer $ADMIN" "${KC}/admin/realms/${REALM}/clients" \
      | python3 -c 'import sys,json;print(next((c["id"] for c in json.load(sys.stdin) if c["clientId"].endswith("/sa/github-agent")),""))' 2>/dev/null || true)
[ -n "$CID" ] || die "could not find the github-agent Keycloak client (clientId ending /sa/github-agent)"
SID=$(curl -s -H "Authorization: Bearer $ADMIN" "${KC}/admin/realms/${REALM}/client-scopes" \
      | python3 -c 'import sys,json;print(next((s["id"] for s in json.load(sys.stdin) if s["name"]=="agent-team1-github-tool-aud"),""))' 2>/dev/null || true)
[ -n "$SID" ] || die "could not find the 'agent-team1-github-tool-aud' client-scope in realm ${REALM}"
info "github-agent client UUID: ${CID}"
info "agent-team1-github-tool-aud scope UUID: ${SID}"
SCOPE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X PUT -H "Authorization: Bearer $ADMIN" \
             "${KC}/admin/realms/${REALM}/clients/${CID}/optional-client-scopes/${SID}")
if [ "$SCOPE_HTTP" = "204" ]; then
  pass "assigned optional client-scope: HTTP 204"
elif [ "$SCOPE_HTTP" = "409" ]; then
  warn "optional client-scope already assigned (HTTP 409) — idempotent, continuing"
else
  die "assigning the optional client-scope returned HTTP ${SCOPE_HTTP} (expected 204)"
fi

step "B.3 — Restart github-agent to load the route"
kubectl delete pod -n "$NS" -l "$AGENT_LABEL" || die "failed to delete github-agent pod(s)"
info "waiting for github-agent to become Ready (timeout 120s)..."
kubectl wait --for=condition=ready pod -n "$NS" -l "$AGENT_LABEL" --timeout=120s \
  || die "github-agent did not become Ready within 120s after restart"
pass "github-agent restarted and Ready"

step "B.4 — Outbound probe as dev-user (tools/list to github-tool:9090/mcp) — expect ALLOWED"
info "the call crosses github-agent's outbound OPA (the github-agent CR's outbound package: a"
info "pass-through) and github-tool's inbound OPA (the github-tool CR's inbound package: the tool"
info "check). tools/list is an MCP session message: the tool inbound allows it when at least one"
info "tool passes tool_ok for dev-user and the calling agent (source-read does). So the reply is a"
info "JSON-RPC result frame that lists the four tools."
info "NOTE: a deny by github-tool's inbound is an HTTP 403 with a plain JSON body that names opa;"
info "a deny by the agent's outbound (agent side) is a JSON-RPC error frame at HTTP 200"
info "(writeMCPRejection in core/listener/httpx/render.go in the cortex repo). So this probe"
info "classifies by the RESPONSE BODY, not the code alone."
POD="$(latest_agent_pod)"
[ -n "$POD" ] || die "no github-agent pod after restart"
TOK="$(mint_token dev-user)"
PROBE_PY="$(mktemp /tmp/opa-kind-driver-probe.XXXXXX)"
trap 'rm -f "$PROBE_PY"' EXIT
# The probe classifies the outcome in Python (robust JSON parsing) and prints a
# single VERDICT line the shell keys on, plus the raw HTTP status + body for the
# operator. The FastMCP app serves /mcp and needs the MCP Accept header; it is
# stateless with JSON replies, so one tools/list request gets its own reply.
cat > "$PROBE_PY" <<PY
import urllib.request, urllib.error, json
tok = """$TOK"""
op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://127.0.0.1:8081"}))
body = json.dumps({"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}).encode()
req = urllib.request.Request("http://github-tool:9090/mcp", data=body,
    headers={"Content-Type":"application/json",
             "Accept":"application/json, text/event-stream",
             "Authorization":"Bearer "+tok})
code, raw = None, ""
try:
    r = op.open(req, timeout=15); code = r.status; raw = r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    code = e.code
    try: raw = e.read().decode("utf-8", "replace")
    except Exception: raw = ""
except Exception as e:
    print("VERDICT ERROR"); print("HTTP none"); print("ERROR", type(e).__name__, e); raise SystemExit(0)
print("HTTP", code)
print("BODY", raw)
doc = None
try: doc = json.loads(raw)
except Exception: doc = None
err = doc.get("error") if isinstance(doc, dict) else None
data = err.get("data") if isinstance(err, dict) else None
plugin = data.get("plugin") if isinstance(data, dict) else None
opa_403 = (isinstance(doc, dict) and "jsonrpc" not in doc
           and (doc.get("plugin") == "opa" or doc.get("error") == "policy.forbidden"))
if code == 403 and opa_403:
    print("VERDICT DENIED_TOOL_INBOUND")                     # github-tool's inbound OPA (target side)
elif code in (403, 503):
    print("VERDICT DENIED_HTTP", code)                       # other 403 / token-exchange / no bundle yet
elif code == 200 and plugin:
    print("VERDICT DENIED_PLUGIN", plugin)                   # MCP JSON-RPC deny frame (opa, token-exchange)
elif code == 200 and isinstance(doc, dict) and isinstance(doc.get("result"), dict):
    tools = doc["result"].get("tools") or []
    print("TOOLS", ",".join(sorted(str(t.get("name")) for t in tools if isinstance(t, dict))))
    print("VERDICT ALLOWED_RESULT")                          # reached github-tool
elif code in (400, 404, 405, 406) and not plugin:
    print("VERDICT APP_REJECTED", code)                      # the tool app refused the request shape
else:
    print("VERDICT UNEXPECTED")
PY
# Poll: right after the B.3 restart the agent returns 503 until its first bundle
# loads, and a CR change (the A.3 example CRs) reaches a pod only at its next
# bundle poll (up to ~120s). Retry until the probe reaches the tool or the
# window expires — mirrors A.4.
OB_DEADLINE=$((SECONDS + POLL_SECS))
while :; do
  OUT=$(kubectl exec -i -n "$NS" "$POD" -c agent -- python3 - < "$PROBE_PY" 2>/dev/null || true)
  OB_VERDICT=$(printf '%s\n' "$OUT" | sed -n 's/^VERDICT //p' | tail -1)
  OB_HTTP=$(printf '%s\n' "$OUT" | sed -n 's/^HTTP //p' | tail -1)
  case "$OB_VERDICT" in
    ALLOWED_RESULT|APP_REJECTED*) break ;;
  esac
  [ "$SECONDS" -ge "$OB_DEADLINE" ] && break
  info "outbound probe: ${OB_VERDICT:-<none>} (HTTP ${OB_HTTP:-?}) — retrying (want ALLOWED_RESULT; a bundle may still be propagating)..."
  sleep 5
done
info "outbound probe result:"
printf '%s\n' "$OUT" | sed 's/^/    /'
case "$OB_VERDICT" in
  ALLOWED_RESULT)
    OB_TOOLS=$(printf '%s\n' "$OUT" | sed -n 's/^TOOLS //p' | tail -1)
    expect_eq "tools in the github-tool tools/list result" "$OB_TOOLS" "issues-read,issues-write,source-read,source-write"
    pass "outbound tools/list ALLOWED: a JSON-RPC result frame from github-tool (github-agent's outbound pass-through, then github-tool's inbound session rule)" ;;
  APP_REJECTED*)
    die "the github-tool app answered HTTP ${OB_HTTP:-?} with no AuthBridge rejection: the call passed both OPA checks, but the app refused the request. Check the probe URL (/mcp) and the header Accept: application/json, text/event-stream." ;;
  DENIED_TOOL_INBOUND)
    die "outbound tools/list DENIED by github-tool's inbound OPA (HTTP 403, plugin=opa) after ${POLL_SECS}s. The github-tool CR's inbound session rule allows tools/list for dev-user through github-agent. Check that A.3 applied the github-tool CR, that its bundle has propagated, and that the exchanged token has sub=dev-user and azp=${EXPECTED_SPIFFE} (sub=dev-user needs the client scope aiac-username-sub, which AIAC links to github-agent at onboarding, D31; see the runbook Prerequisites)." ;;
  "DENIED_PLUGIN opa")
    die "outbound tools/list DENIED by github-agent's outbound OPA (a JSON-RPC error frame at HTTP 200, plugin=opa) after ${POLL_SECS}s. Under target side the github-agent CR's outbound is a pass-through: check that A.3 applied the example CRs (an agent-side CR may still be in place) and that the bundle has propagated." ;;
  "DENIED_PLUGIN token-exchange")
    die "outbound tools/list failed at token-exchange (a JSON-RPC error frame, plugin=token-exchange): OPA was never consulted. Check B.1 (route) and B.2 (exchange scope)." ;;
  DENIED_PLUGIN*)
    die "outbound tools/list rejected by a plugin (${OB_VERDICT#DENIED_PLUGIN }) after ${POLL_SECS}s; expected a JSON-RPC result frame." ;;
  "DENIED_HTTP 403")
    die "outbound tools/list DENIED: HTTP 403 (no OPA body) after ${POLL_SECS}s. A pod with no client CR is denied (D20): check the two example CRs (github-agent, github-tool)." ;;
  "DENIED_HTTP 503")
    die "outbound tools/list returned HTTP 503 after ${POLL_SECS}s — blocked before reaching the tool (token-exchange, or no bundle loaded yet)." ;;
  ERROR|"")
    die "outbound probe produced no HTTP response (output: ${OUT}). The agent container may lack python3/HTTP_PROXY, or the forward proxy is down." ;;
  *)
    die "outbound tools/list returned an unexpected shape (HTTP ${OB_HTTP:-?}); expected a JSON-RPC result frame at HTTP 200. Full output:
${OUT}" ;;
esac

step "B.5 — The OUTBOUND OPA input, exactly (+ github-tool's inbound decision)"
dump_opa_input outbound
OUTBOUND_LINE="$LAST_OPA_LINE"
printf '\n'
if [ -n "$OUTBOUND_LINE" ]; then
  if printf '%s' "$OUTBOUND_LINE" | grep -q 'outbound'; then
    pass "captured an outbound OPA decision-log line (github-agent's outbound pass-through)"
  else
    warn "captured a line but it does not mention 'outbound'; printed above"
  fi
else
  warn "no outbound OPA input captured — decision_logs.console may format differently in this build"
fi

# Target side: github-tool's inbound OPA made the decision (runbook B.5).
dump_opa_input inbound tool
TOOL_INBOUND_LINE="$LAST_OPA_LINE"
printf '\n'
if [ -n "$TOOL_INBOUND_LINE" ]; then
  if printf '%s' "$TOOL_INBOUND_LINE" | grep -q 'allow:true'; then
    pass "github-tool's inbound decision shows allow:true (the tool check allowed the call)"
  else
    warn "could not confirm 'allow:true' on the captured github-tool inbound line (formatting may differ); line printed above"
  fi
else
  warn "no github-tool inbound OPA input captured — decision_logs.console may format differently in this build"
fi

# Reference: the canonical outbound input shape from the runbook (B.5).
cat <<'JSON'
     ----- OUTBOUND OPA INPUT — canonical shape (runbook B.5, for comparison) -----
     {
       "direction": "outbound",
       "method": "POST", "path": "/mcp", "host": "github-tool:9090",
       "identity": {
         "subject": "dev-user",
         "client_id": "spiffe://localtest.me/ns/team1/sa/github-agent",
         "scopes": ["openid", "agent-team1-github-tool-aud"],
         "service_id": "spiffe://localtest.me/ns/team1/sa/github-tool"
       },
       "delegation": {
         "origin": "dev-user", "actor": "dev-user", "depth": 1,
         "chain": [ { "subject_id": "dev-user",
                      "audience": "spiffe://localtest.me/ns/team1/sa/github-tool",
                      "scopes": ["openid","agent-team1-github-tool-aud"],
                      "strategy": "token-exchange", "from_cache": false } ]
       },
       "mcp": { "method": "tools/list" }
     }
     (no validated JWT outbound; identity is synthesized from the token-exchange
      delegation hop. service_id = the exchange target = the github-tool SPIFFE ID.
      Target side: github-agent's outbound pass-through reads none of it; the
      tool check runs on github-tool's inbound, from the exchanged JWT:
      subject = dev-user, client_id = the github-agent SPIFFE ID, mcp.method)
JSON

# ── Summary ──────────────────────────────────────────────────────────────────
printf '\n%s%s====== ALL RUNBOOK STEPS PASSED ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
info "Inbound:  dev-user allowed (200), alice blocked (403); inbound OPA input printed."
info "Outbound: token-exchange leg reached OPA; tools/list allowed by github-tool's inbound (${OB_VERDICT}, HTTP ${OB_HTTP}); outbound OPA input printed."
cat <<EOF

To undo everything (runbook Cleanup, in reverse order):
  # 1. delete the two example CRs (github-agent and github-tool)
  kubectl delete -f ${POLICY_FILE}
  # 2./3. revert authproxy-routes to weather-only, remove the optional client-scope (see runbook Cleanup)
  # 4. revert the pipeline (removes the OPA overlay, puts back the stock combiner,
  #    restarts the agent and tool pods)
  OPERATOR_DIR=\${OPERATOR_DIR:-../operator} ROSSOCTL_DIR=\${ROSSOCTL_DIR:-../rossoctl} ${RESTORE_SCRIPT}
Under the changed combiner (D20) a deleted CR denies its pod until step 4, or
until AIAC writes the CRs again. After the restore the AIAC Controller does not
start (start check #4) until opa-kind-enable.sh runs again.
EOF
