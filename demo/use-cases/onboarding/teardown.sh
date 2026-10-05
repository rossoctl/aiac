#!/usr/bin/env bash
# teardown.sh — return the cluster to its POST-INSTALL state: remove this demo's entire footprint,
# leaving the Rossoctl platform (SPIRE, Keycloak, the operator, the team1 namespace) as the installer
# left it.
#
# This is the complement of restore.sh, not a replacement. restore.sh is scoped to "make the next
# ./driver.sh run a genuine first-time trigger again" and deliberately KEEPS the AIAC stack, the NATS
# broker and the demo's Keycloak users/roles, because re-running the demo needs them. teardown.sh
# removes those too, so nothing of the demo survives:
#
#   restore.sh --include-infra  |  teardown.sh additionally removes
#   ----------------------------|-------------------------------------------------------------
#   github-agent/github-tool    |  the team1 ConfigMaps the demo's own manifest created
#   their Keycloak clients      |  (authbridge-config, authproxy-routes)
#   github-agent.*/github-tool.*|  the whole aiac-system namespace — AIAC stack, NATS broker,
#     roles + client scopes     |    Policy Model Store PVC, aiac-agent-secret, aiac-policy CM
#   the AuthorizationPolicy CR  |  the demo's Keycloak users (dev-user/test-user/devops-user)
#   credentials Secrets         |  the demo's Keycloak realm roles (developer/tester/devops)
#   the outbound-leg wiring     |  the demo's ROPC client (aiac-demo-cli)
#   the Keycloak SPI + image    |  optionally the OPA pipeline overlay (--include-opa)
#
# DELIBERATELY LEFT IN PLACE (platform state this demo does not own — see demo.md "Cleanup"):
#   - the team1 namespace itself. The Rossoctl installer creates and owns it
#     (demo/assets/INSTALL.md: "a precondition, not an output"); a fresh install gives you an EMPTY
#     team1, not no team1. Deleting it would force an installer re-run.
#   - the `rossoctl` client's Direct Access Grants + username->sub protocol mapper from demo.md's
#     Prerequisites. One-time cluster-wide state that k8s/opa-kind-runbook.md's probes and the
#     system test suite both depend on, and which that runbook calls harmless to leave.
#   - the operator's `*-aud` audience client scopes, which it owns and recreates.
#   - container images already loaded into the Kind node (inert; `docker image rm` them by hand).
#     Consequence worth knowing: because these survive, a later `./enable.sh` finds the stack images
#     present and SKIPS rebuilding them, so a source change made since would not reach the cluster.
#     Re-install with `./enable.sh --rebuild` to force those builds.
#
# Usage:
#   ./teardown.sh --dry-run        # list everything that WOULD be removed; change nothing
#   ./teardown.sh                  # tear down (prompts for confirmation)
#   ./teardown.sh --yes            # tear down without prompting
#   ./teardown.sh --include-opa    # also revert the OPA pipeline overlay (needs ROSSOCTL_DIR)
#   ./teardown.sh --aiac-only      # uninstall ONLY AIAC: delete the aiac-system namespace and
#                                  # nothing else (the inverse of ./enable.sh)
#
# --aiac-only exists because enable.sh installs AIAC as a separable step (--stack-only /
# --broker-only) but nothing uninstalled just that: restore.sh --include-infra reverts only the
# Keycloak-side half of enable.sh (the SPI listener and image), never the stack, which lives in
# aiac-system. In this mode the demo's workloads, its Keycloak users/roles/clients and the OPA
# overlay are all left exactly as they are, so it is NOT a path back to the post-install state — it
# only makes the install/uninstall pair symmetric. It needs no Keycloak credentials.
#
# Note that deleting the namespace destroys the Policy Model Store's PVC and its SQLite with it.
# `make clear` is the non-destructive way to reset that store's contents.
#
# Env vars:
#   NS                    demo workload namespace                       (default: team1)
#   AIAC_NS               namespace the AIAC stack lives in             (default: aiac-system)
#   KC, REALM             Keycloak base URL + realm
#   KIND_CLUSTER          Kind cluster name, for the kubeconfig refresh (default: rossoctl)
#   ROSSOCTL_DIR          Helm chart clone, only for --include-opa      (default: ../../../../rossoctl)
#   NS_WAIT_SECS          how long to wait for aiac-system to finalize  (default: 180)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AIAC_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ASSETS_DIR="$AIAC_DIR/demo/assets"

NS="${NS:-team1}"
AIAC_NS="${AIAC_NS:-aiac-system}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
KIND_CLUSTER="${KIND_CLUSTER:-rossoctl}"
NS_WAIT_SECS="${NS_WAIT_SECS:-180}"

DRY_RUN=0
ASSUME_YES=0
DO_OPA=0
AIAC_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --include-opa) DO_OPA=1 ;;
    --aiac-only) AIAC_ONLY=1 ;;
    "") ;;
    *) echo "Usage: $0 [--dry-run] [--yes] [--include-opa | --aiac-only]" >&2; exit 1 ;;
  esac
done
# Contradictory: --aiac-only touches nothing outside aiac-system, and the OPA overlay lives in the
# workload namespace. Reject rather than silently ignoring one of them.
if [ "$AIAC_ONLY" -eq 1 ] && [ "$DO_OPA" -eq 1 ]; then
  echo "Error: --aiac-only and --include-opa are mutually exclusive (the OPA overlay is in ${NS}, not ${AIAC_NS})." >&2
  exit 1
fi

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_CYN=$'\033[36m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BLD=""; C_RST=""
fi
STEP_N=0
step() { STEP_N=$((STEP_N + 1)); printf '\n%s==> [%d] %s%s\n' "$C_BLD$C_CYN" "$STEP_N" "$*" "$C_RST"; }
info() { printf '     %s\n' "$*"; }
pass() { printf '     %sOK%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '     %sWARN%s %s\n' "$C_YEL" "$C_RST" "$*"; }
die()  { printf '\n%sFAIL:%s %s\n' "$C_RED$C_BLD" "$C_RST" "$*" >&2; exit 1; }

# In --dry-run every mutation goes through this, so there is exactly one place where the
# "change nothing" promise is kept. Only ever pass kubectl/script commands here — never a curl
# carrying the admin token, or --dry-run would echo the credential to the terminal. Keycloak
# mutations go through kc_delete() instead, which prints a redacted description.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then printf '     %s[dry-run]%s %s\n' "$C_YEL" "$C_RST" "$*"; else "$@"; fi
}

# kc_delete <label> <api-path> — DELETE against the Keycloak Admin API. Prints only the label and
# path, so the bearer token never reaches stdout in either mode (curl prints just the status code).
kc_delete() {
  local label="$1" path="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '     %s[dry-run]%s would DELETE %s  (%s)\n' "$C_YEL" "$C_RST" "$label" "$path"
    return 0
  fi
  curl -s -o /dev/null -w "     delete ${label} HTTP %{http_code}\n" -X DELETE \
    -H "Authorization: Bearer ${ADMIN}" "${KC}${path}"
}

admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || true
}

# Names come from lib/scenario.py, never hand-copied — the same anti-drift rule enable.sh follows for
# POLICY_ABSTRACT. If the scenario's users/roles/client change, this teardown follows automatically.
read_scenario() {
  python3 -c '
import sys
sys.path.insert(0, sys.argv[1])
import scenario as s
print(" ".join(s.USERS))          # dev-user test-user devops-user
print(" ".join(s.USER_ROLES))     # developer tester devops
print(s.ROPC_CLIENT_ID)           # aiac-demo-cli
' "$SCRIPT_DIR/lib"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
if [ "$AIAC_ONLY" -eq 1 ]; then
  printf '%s%sAIAC uninstall — delete namespace %s only%s\n' "$C_BLD" "$C_CYN" "$AIAC_NS" "$C_RST"
else
  printf '%s%sonboarding demo teardown — back to the post-install state%s\n' "$C_BLD" "$C_CYN" "$C_RST"
fi
[ "$DRY_RUN" -eq 1 ] && printf '%s(dry run — nothing will be changed)%s\n' "$C_YEL" "$C_RST"

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

DEMO_USERS=""; DEMO_ROLES=""; ROPC_CLIENT=""; ADMIN=""
if [ "$AIAC_ONLY" -eq 1 ]; then
  info "mode: --aiac-only — only namespace '${AIAC_NS}' will be deleted; Keycloak is not touched"
else
  SCENARIO="$(read_scenario)" || die "could not read lib/scenario.py — run this from the demo directory"
  DEMO_USERS="$(printf '%s\n' "$SCENARIO" | sed -n 1p)"
  DEMO_ROLES="$(printf '%s\n' "$SCENARIO" | sed -n 2p)"
  ROPC_CLIENT="$(printf '%s\n' "$SCENARIO" | sed -n 3p)"
  info "demo users: ${DEMO_USERS}"
  info "demo roles: ${DEMO_ROLES}"
  info "ROPC client: ${ROPC_CLIENT}"

  ADMIN="$(admin_token)"
  if [ -n "$ADMIN" ]; then
    pass "Keycloak admin token acquired (${KC}, realm ${REALM})"
  else
    warn "no Keycloak admin token from ${KC} — every Keycloak step will be SKIPPED, not silently passed"
  fi
fi

# ── What is actually present ───────────────────────────────────────────────────
step "Surveying the demo's current footprint"
present() { kubectl get "$1" "$2" ${3:+-n "$3"} >/dev/null 2>&1 && echo yes || echo no; }
info "namespace ${AIAC_NS}:            $(kubectl get ns "$AIAC_NS" >/dev/null 2>&1 && echo present || echo absent)"
info "deployment ${NS}/github-agent:   $(present deployment github-agent "$NS" | sed 's/yes/present/;s/no/absent/')"
info "deployment ${NS}/github-tool:    $(present deployment github-tool "$NS" | sed 's/yes/present/;s/no/absent/')"
info "configmap ${NS}/authproxy-routes: $(present configmap authproxy-routes "$NS" | sed 's/yes/present/;s/no/absent/')"
OPA_COUNT=$(kubectl get configmap authbridge-runtime-config -n "$NS" \
              -o jsonpath='{.data.config\.yaml}' 2>/dev/null | grep -c 'name: opa' || true)
info "OPA legs wired in ${NS}:         ${OPA_COUNT:-0} (2 = both; teardown leaves this unless --include-opa)"

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
  if [ "$AIAC_ONLY" -eq 1 ]; then
    printf '\n%sThis deletes namespace %s and everything in it, including the Policy Model Store PVC.%s\n' \
      "$C_YEL" "$AIAC_NS" "$C_RST"
    printf 'Nothing else is touched — the demo workloads, Keycloak and the OPA overlay all stay.\n'
  else
    printf '\n%sThis removes the demo from the cluster, including the %s namespace and its PVC.%s\n' \
      "$C_YEL" "$AIAC_NS" "$C_RST"
    printf 'The %s namespace and the platform itself are left alone.\n' "$NS"
  fi
  printf 'Type "yes" to continue: '
  read -r reply
  [ "$reply" = "yes" ] || die "aborted by user (nothing was changed)"
fi

# ── 1. The demo's own state + the Keycloak SPI (delegated to restore.sh) ───────
if [ "$AIAC_ONLY" -eq 1 ]; then
  step "Skipping demo state + Keycloak SPI (--aiac-only)"
  info "workloads, their Keycloak clients and the SPI listener are all left in place"
else
step "Removing demo state + Keycloak SPI (restore.sh --include-infra)"
# Delegated rather than duplicated: restore.sh already owns this teardown surface (workloads, their
# Keycloak clients, provisioned roles/scopes, the AuthorizationPolicy CR, credentials Secrets, the
# outbound wiring, the SPI listener and the Keycloak image).
if [ "$DRY_RUN" -eq 1 ]; then
  info "[dry-run] would run: ${SCRIPT_DIR}/restore.sh --include-infra"
else
  NS="$NS" KC="$KC" REALM="$REALM" bash "$SCRIPT_DIR/restore.sh" --include-infra \
    || warn "restore.sh reported a problem — continuing; later steps are independent"
fi
fi

# ── 2. The team1 ConfigMaps the demo's manifest created ────────────────────────
if [ "$AIAC_ONLY" -eq 1 ]; then
  step "Skipping the demo's ${NS} ConfigMaps (--aiac-only)"
else
step "Deleting the demo's team1 ConfigMaps (authbridge-config, authproxy-routes)"
# Symmetric inverse of deploy.sh: delete exactly what the demo's own manifest declares, the same way
# restore.sh deletes the Deployment manifests. Both CMs are demo-owned
# (demo/assets/agents/github_agent/k8s/configmaps.yaml, namespace team1).
#
# Caveat worth knowing: if YOUR platform also ships an authproxy-routes in team1 (some rossoctl
# installs seed one for the weather tool), the demo overwrote it on deploy and this deletes it
# outright — there is no saved copy to put back. Re-apply the installer's version afterwards.
run kubectl delete -f "$ASSETS_DIR/agents/github_agent/k8s/configmaps.yaml" -n "$NS" --ignore-not-found
pass "demo ConfigMaps gone from ${NS} (the namespace itself is untouched)"
fi

# ── 3. The whole aiac-system namespace ────────────────────────────────────────
step "Deleting namespace ${AIAC_NS} (AIAC stack, NATS broker, Policy Model Store PVC, secrets)"
if kubectl get ns "$AIAC_NS" >/dev/null 2>&1; then
  run kubectl delete namespace "$AIAC_NS" --ignore-not-found --timeout="${NS_WAIT_SECS}s"
  if [ "$DRY_RUN" -eq 0 ]; then
    if kubectl get ns "$AIAC_NS" >/dev/null 2>&1; then
      warn "${AIAC_NS} still terminating after ${NS_WAIT_SECS}s — check for a stuck finalizer: kubectl get ns ${AIAC_NS} -o yaml"
    else
      pass "${AIAC_NS} deleted (its PVC and Secrets went with it)"
    fi
  fi
else
  info "${AIAC_NS} already absent — nothing to delete"
fi

# ── 4. Keycloak: the demo's users, realm roles, and ROPC client ────────────────
if [ "$AIAC_ONLY" -eq 1 ]; then
  step "Keycloak: users, realm roles and ROPC client"
else
  step "Deleting the demo's Keycloak users, realm roles, and ROPC client"
fi
# The gap this script exists to close: restore.sh scrubs the github-agent.*/github-tool.* roles and
# scopes that ONBOARDING generated, and init/02-clear.py's cleanup_provisioned explicitly leaves the
# demo's own developer/tester/devops roles alone so a re-run can reuse them. Nothing removes the
# users, those three roles, or the ROPC client — so without this step a "clean" realm still carries
# dev-user/test-user/devops-user and aiac-demo-cli.
if [ "$AIAC_ONLY" -eq 1 ]; then
  warn "skipped — --aiac-only leaves Keycloak untouched"
elif [ -z "$ADMIN" ]; then
  warn "skipped — no Keycloak admin token (re-run once ${KC} is reachable to finish the teardown)"
else
  for u in $DEMO_USERS; do
    uid=$(curl -s -H "Authorization: Bearer ${ADMIN}" \
            "${KC}/admin/realms/${REALM}/users?username=${u}&exact=true" \
          | python3 -c 'import sys,json
try: d=json.load(sys.stdin); print(d[0]["id"] if d else "")
except Exception: print("")')
    if [ -n "$uid" ]; then
      kc_delete "user ${u}" "/admin/realms/${REALM}/users/${uid}"
    else
      info "user ${u} already absent"
    fi
  done

  for r in $DEMO_ROLES; do
    if curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${ADMIN}" \
         "${KC}/admin/realms/${REALM}/roles/${r}" | grep -q '^200$'; then
      kc_delete "role ${r}" "/admin/realms/${REALM}/roles/${r}"
    else
      info "realm role ${r} already absent"
    fi
  done

  cid=$(curl -s -H "Authorization: Bearer ${ADMIN}" \
          "${KC}/admin/realms/${REALM}/clients?clientId=${ROPC_CLIENT}" \
        | python3 -c 'import sys,json
try: d=json.load(sys.stdin); print(d[0]["id"] if d else "")
except Exception: print("")')
  if [ -n "$cid" ]; then
    kc_delete "client ${ROPC_CLIENT}" "/admin/realms/${REALM}/clients/${cid}"
  else
    info "client ${ROPC_CLIENT} already absent"
  fi
fi

# ── 5. Optional: the OPA pipeline overlay ─────────────────────────────────────
if [ "$DO_OPA" -eq 1 ]; then
  step "Reverting the OPA pipeline overlay (k8s/opa-kind-restore.sh)"
  if [ -x "$AIAC_DIR/k8s/opa-kind-restore.sh" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] would run: ${AIAC_DIR}/k8s/opa-kind-restore.sh"
    else
      ROSSOCTL_DIR="${ROSSOCTL_DIR:-$AIAC_DIR/../rossoctl}" bash "$AIAC_DIR/k8s/opa-kind-restore.sh" \
        || warn "opa-kind-restore.sh failed — it needs a ROSSOCTL_DIR chart clone and helm on PATH"
    fi
  else
    warn "k8s/opa-kind-restore.sh not found or not executable — skipping"
  fi
elif [ "$AIAC_ONLY" -eq 1 ]; then
  step "OPA pipeline overlay left wired (--aiac-only)"
else
  step "OPA pipeline overlay left wired (pass --include-opa to revert it)"
  info "it is a cluster-level change owned by k8s/, and reverting it needs the ROSSOCTL_DIR chart clone"
fi

# ── Report ────────────────────────────────────────────────────────────────────
if [ "$DRY_RUN" -eq 1 ]; then
  printf '\n%s%s====== DRY RUN COMPLETE — nothing was changed ======%s\n' "$C_BLD" "$C_YEL" "$C_RST"
  printf '\nRe-run without --dry-run to apply.\n'
  exit 0
fi

if [ "$AIAC_ONLY" -eq 1 ]; then
  printf '\n%s%s====== AIAC UNINSTALLED ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
  cat <<EOF

Namespace ${AIAC_NS} and everything in it is gone (stack, NATS broker, Policy Model Store + its PVC,
aiac-agent-secret, aiac-policy). Verify:

  kubectl get ns ${AIAC_NS}          # expect: NotFound

Everything else is untouched, by design — this was an uninstall of AIAC, not a teardown of the demo:
  - github-agent/github-tool are still deployed in ${NS}, still registered as Keycloak clients
  - the demo's Keycloak users, realm roles and ROPC client are still there
  - the Keycloak SPI listener + derived image are still installed
  - the OPA pipeline overlay is still wired

Reinstall AIAC with: ./enable.sh        (demo.md Part 1)
Full post-install reset instead:  ./teardown.sh
EOF
  exit 0
fi

printf '\n%s%s====== TEARDOWN COMPLETE ======%s\n' "$C_BLD" "$C_GRN" "$C_RST"
cat <<EOF

Verify the demo is gone:

  kubectl get ns ${AIAC_NS}                                    # expect: NotFound
  kubectl get deployment,svc,sa -n ${NS} | grep github         # expect: no matches
  kubectl get authorizationpolicies.agent.rossoctl.dev -n ${NS}  # expect: no github-agent
  kubectl get ns ${NS}                                         # expect: still Active (installer-owned)

  # realm should hold none of the demo's users/roles/client:
  ADMIN=\$(curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \\
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \\
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  for u in ${DEMO_USERS}; do
    printf '%s: ' "\$u"
    curl -s -H "Authorization: Bearer \$ADMIN" "${KC}/admin/realms/${REALM}/users?username=\$u&exact=true" \\
      | python3 -c 'import sys,json;print("STILL PRESENT" if json.load(sys.stdin) else "gone")'
  done

Still in place, by design (platform state this demo does not own):
  - the ${NS} namespace itself — the Rossoctl installer owns it; a fresh install leaves it empty,
    not absent. Nothing of the demo remains inside it.
  - the 'rossoctl' client's Direct Access Grants + username->sub mapper (demo.md Prerequisites).
    k8s/opa-kind-runbook.md's probes and the system test suite both rely on these.
  - the operator's '*-aud' audience client scopes, which it owns and recreates.
  - container images in the Kind node (inert). Remove by hand if you want the disk back:
      docker image rm localhost/aiac-{pdp-config,pdp-policy-opa,policy-model-store,agent}:local \\
                      localhost/github-{agent,tool}:latest
    Because they survive, a plain './enable.sh' will SKIP rebuilding the stack images and re-load
    these — so any source change you made since would not reach the cluster. Use --rebuild below.
$([ "$DO_OPA" -eq 0 ] && printf '%s' "  - the OPA pipeline overlay in ${NS} — re-run with --include-opa to revert it.")

To stand the demo back up: see demo.md, Part 1.
  ./enable.sh --rebuild     # rebuild the four stack images from current source, then install
  ./enable.sh               # reuse the images already built (faster; no source change since)
EOF
