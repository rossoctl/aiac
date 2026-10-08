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
#   the Keycloak SPI + image    |  optionally everything k8s/opa-kind-enable.sh installed
#                               |    (--include-opa): the OPA pipeline overlay, bundle-service,
#                               |    and the local authbridge image pin on the rossoctl release
#                               |  optionally the locally built container images (--include-images)
#
# DELIBERATELY LEFT IN PLACE (platform state this demo does not own — see demo.md "Cleanup"):
#   - the team1 namespace itself. The Rossoctl installer creates and owns it
#     (demo/assets/INSTALL.md: "a precondition, not an output"); a fresh install gives you an EMPTY
#     team1, not no team1. Deleting it would force an installer re-run.
#   - the `rossoctl` client's Direct Access Grants + username->sub protocol mapper from demo.md's
#     Prerequisites. One-time cluster-wide state that this demo and the system test suite
#     both depend on, and which is harmless to leave.
#   - the operator's `*-aud` audience client scopes, which it owns and recreates.
#   - container images already loaded into the Kind node, unless --include-images. Inert, but
#     because they survive, a later `./enable.sh` finds the stack images present and SKIPS
#     rebuilding them, so a source change made since would not reach the cluster. Re-install with
#     `./enable.sh --rebuild` to force those builds.
#   - the AuthorizationPolicy CRD, even with --include-opa. Deleting a CRD deletes every CR of that
#     kind cluster-wide, and the operator chart may own it.
#
# Usage:
#   ./teardown.sh --dry-run        # list everything that WOULD be removed; change nothing
#   ./teardown.sh                  # tear down (prompts for confirmation)
#   ./teardown.sh --yes            # tear down without prompting
#   ./teardown.sh --include-opa    # also undo k8s/opa-kind-enable.sh: the OPA pipeline overlay,
#                                  # bundle-service, and the localhost/authbridge image pin
#                                  # (needs ROSSOCTL_DIR and helm)
#   ./teardown.sh --include-images # also delete the locally built images from the Kind node and
#                                  # the host runtime (operator + authbridge only with --include-opa,
#                                  # since otherwise the cluster still runs them)
#   ./teardown.sh --all            # --include-opa --include-images: the full reset
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
#   RELEASE_NAME          rossoctl helm release, only for --include-opa (default: rossoctl)
#   RELEASE_NAMESPACE     its namespace, where bundle-service runs      (default: rossoctl-system)
#   CONTAINER_RUNTIME     docker | podman, only for --include-images    (default: as opa-kind-enable.sh)
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
ROSSOCTL_DIR="${ROSSOCTL_DIR:-$AIAC_DIR/../rossoctl}"
RELEASE_NAME="${RELEASE_NAME:-rossoctl}"
RELEASE_NAMESPACE="${RELEASE_NAMESPACE:-rossoctl-system}"

DRY_RUN=0
ASSUME_YES=0
DO_OPA=0
DO_IMAGES=0
AIAC_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --include-opa) DO_OPA=1 ;;
    --include-images) DO_IMAGES=1 ;;
    --all) DO_OPA=1; DO_IMAGES=1 ;;
    --aiac-only) AIAC_ONLY=1 ;;
    "") ;;
    *) echo "Usage: $0 [--dry-run] [--yes] [--include-opa] [--include-images] [--all] [--aiac-only]" >&2; exit 1 ;;
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
if [ "$DO_OPA" -eq 1 ]; then
  command -v helm >/dev/null 2>&1 || die "--include-opa needs helm on PATH"
  [ -f "$ROSSOCTL_DIR/charts/rossoctl/Chart.yaml" ] \
    || die "--include-opa needs the rossoctl chart clone — set ROSSOCTL_DIR (tried ${ROSSOCTL_DIR})"
fi
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
info "deployment ${RELEASE_NAMESPACE}/bundle-service: $(present deployment bundle-service "$RELEASE_NAMESPACE" | sed 's/yes/present/;s/no/absent/')"
# The image pin as the operator actually renders it, not as helm reports the user values — see
# drop_authbridge_pin() for why those two can disagree.
AUTHBRIDGE_IMAGE=$(kubectl get configmap "${RELEASE_NAME}-platform-config" -n "$RELEASE_NAMESPACE" \
                     -o jsonpath='{.data.config\.yaml}' 2>/dev/null \
                   | sed -n 's/^  authbridge: *//p' | head -1 || true)
info "authbridge sidecar image:        ${AUTHBRIDGE_IMAGE:-unknown}"

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
  # `|| true`: a --timeout expiry exits non-zero, which under `set -e` would skip the Keycloak and
  # OPA cleanup below. The `kubectl get ns` check right after reports the still-terminating case.
  run kubectl delete namespace "$AIAC_NS" --ignore-not-found --timeout="${NS_WAIT_SECS}s" || true
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

# ── 5. Optional: everything k8s/opa-kind-enable.sh installed ─────────────────
# drop_authbridge_pin — re-render the rossoctl release without
# operator-chart.defaults.images.authbridge, so sidecars go back to the operator subchart's own
# default image. opa-kind-restore.sh re-applies that pin on purpose (it only reverts the pipeline),
# so this runs after it.
#
# Takes the release's stored user values and passes them back explicitly with -f, rather than
# `--reuse-values --set ...authbridge=null`: on this chart that removes the key from the stored
# values but still renders the old pin into ${RELEASE_NAME}-platform-config, and a second
# --reuse-values upgrade keeps rendering it. Only an explicit -f of the clean values clears it.
drop_authbridge_pin() {
  local vals had
  vals="$(mktemp "${TMPDIR:-/tmp}/teardown-values.XXXXXX")"
  # JSON is valid YAML, so helm reads this file as-is — no PyYAML needed.
  had=$(helm get values "$RELEASE_NAME" -n "$RELEASE_NAMESPACE" -o json \
        | python3 -c '
import sys, json
v = json.load(sys.stdin) or {}
had = v.get("operator-chart", {}).get("defaults", {}).get("images", {}).pop("authbridge", "")
json.dump(v, open(sys.argv[1], "w"))
print(had)' "$vals") || { rm -f "$vals"; warn "could not read the ${RELEASE_NAME} release values"; return 1; }
  if [ -z "$had" ] && ! printf '%s' "$AUTHBRIDGE_IMAGE" | grep -q '^localhost/'; then
    rm -f "$vals"
    info "no authbridge image pin on release ${RELEASE_NAME} — already on the chart default"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    rm -f "$vals"
    info "[dry-run] would helm upgrade ${RELEASE_NAME} with its current values minus" \
         "operator-chart.defaults.images.authbridge (${had:-$AUTHBRIDGE_IMAGE}), then restart the operator"
    return 0
  fi
  ( cd "$ROSSOCTL_DIR/charts/rossoctl" && helm dependency build >/dev/null ) \
    && helm upgrade "$RELEASE_NAME" "$ROSSOCTL_DIR/charts/rossoctl" -n "$RELEASE_NAMESPACE" \
         -f "$vals" >/dev/null \
    || { rm -f "$vals"; warn "helm upgrade to drop the authbridge pin failed"; return 1; }
  rm -f "$vals"
  # The operator reads its platform config at startup, so a re-rendered ConfigMap alone does not
  # change which image the next injected sidecar gets.
  kubectl rollout restart "deployment/${RELEASE_NAME}-controller-manager" -n "$RELEASE_NAMESPACE" >/dev/null
  kubectl rollout status "deployment/${RELEASE_NAME}-controller-manager" -n "$RELEASE_NAMESPACE" \
    --timeout=180s >/dev/null || warn "operator restart did not finish within 180s"
  AUTHBRIDGE_IMAGE=$(kubectl get configmap "${RELEASE_NAME}-platform-config" -n "$RELEASE_NAMESPACE" \
                       -o jsonpath='{.data.config\.yaml}' | sed -n 's/^  authbridge: *//p' | head -1)
  if printf '%s' "$AUTHBRIDGE_IMAGE" | grep -q '^localhost/'; then
    warn "release re-rendered but the authbridge image is still ${AUTHBRIDGE_IMAGE}"
    return 1
  fi
  pass "authbridge sidecar image back to the chart default (${AUTHBRIDGE_IMAGE})"
}

if [ "$DO_OPA" -eq 1 ]; then
  step "Reverting the OPA pipeline overlay (k8s/opa-kind-restore.sh)"
  if [ -x "$AIAC_DIR/k8s/opa-kind-restore.sh" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] would run: ${AIAC_DIR}/k8s/opa-kind-restore.sh"
    else
      ROSSOCTL_DIR="$ROSSOCTL_DIR" RELEASE_NAME="$RELEASE_NAME" RELEASE_NAMESPACE="$RELEASE_NAMESPACE" \
        AGENT_NAMESPACE="$NS" bash "$AIAC_DIR/k8s/opa-kind-restore.sh" \
        || warn "opa-kind-restore.sh failed — it needs a ROSSOCTL_DIR chart clone and helm on PATH"
    fi
  else
    warn "k8s/opa-kind-restore.sh not found or not executable — skipping"
  fi

  step "Deleting bundle-service from ${RELEASE_NAMESPACE} (opa-kind-enable.sh Step 1)"
  # opa-kind-restore.sh leaves this running. It was rendered with `helm template | kubectl apply`,
  # outside any release, so nothing else will ever remove it. Names mirror the five templates
  # opa-kind-enable.sh renders from the operator chart's templates/bundleservice/.
  run kubectl delete -n "$RELEASE_NAMESPACE" --ignore-not-found \
    deployment/bundle-service service/bundle-service serviceaccount/bundle-service
  # default-policy.yaml's global AuthorizationPolicy. Only meaningful as bundle-service's input.
  run kubectl delete authorizationpolicies.agent.rossoctl.dev default -n "$RELEASE_NAMESPACE" --ignore-not-found
  run kubectl delete --ignore-not-found \
    "clusterrole/${RELEASE_NAME}-bundle-service" "clusterrolebinding/${RELEASE_NAME}-bundle-service"
  info "the AuthorizationPolicy CRD is left in place (deleting it would delete every policy CR)"

  step "Dropping the local authbridge image pin from release ${RELEASE_NAME} (opa-kind-enable.sh Step 2)"
  drop_authbridge_pin || warn "authbridge pin NOT dropped — its image will be kept below too"
elif [ "$AIAC_ONLY" -eq 1 ]; then
  step "OPA pipeline overlay left wired (--aiac-only)"
else
  step "OPA pipeline overlay, bundle-service and authbridge pin left in place (pass --include-opa)"
  info "they are cluster-level changes owned by k8s/, and reverting them needs the ROSSOCTL_DIR chart clone"
fi

# ── 6. Optional: the locally built container images ───────────────────────────
# Image names mirror where each is built: init/01-prereqs.py AIAC_IMAGES (the four stack images),
# demo/assets/kind-load.sh (github-*), enable.sh (keycloak-aiac), k8s/opa-kind-enable.sh
# (operator, authbridge).
DEMO_IMAGES=(
  localhost/aiac-pdp-config:local
  localhost/aiac-pdp-policy-opa:local
  localhost/aiac-policy-model-store:local
  localhost/aiac-agent:local
)
if [ "$AIAC_ONLY" -eq 0 ]; then
  # restore.sh --include-infra (step 1) put Keycloak back on its stock image.
  DEMO_IMAGES+=(localhost/github-agent:latest localhost/github-tool:latest localhost/keycloak-aiac:local)
fi
if [ "$DO_OPA" -eq 1 ]; then
  DEMO_IMAGES+=(localhost/operator:local localhost/authbridge:local)
fi

# remove_image <image> — from every Kind node's containerd and from the host runtime. Skips an
# image a pod still runs, which is how a failed step above keeps its image instead of leaving a
# workload that cannot restart.
remove_image() {
  local img="$1" node
  if printf '%s\n' "$IMAGES_IN_USE" | grep -qxF "$img"; then
    warn "${img} is still used by a running pod — kept"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] would remove ${img} from the Kind node(s) and ${CONTAINER_RUNTIME}"
    return 0
  fi
  for node in $KIND_NODES; do
    if "$CONTAINER_RUNTIME" exec "$node" crictl rmi "$img" >/dev/null 2>&1; then
      info "removed ${img} from node ${node}"
    fi
  done
  if "$CONTAINER_RUNTIME" image rm "$img" >/dev/null 2>&1; then
    info "removed ${img} from ${CONTAINER_RUNTIME}"
  fi
}

if [ "$DO_IMAGES" -eq 1 ]; then
  step "Deleting the locally built images from the Kind node(s) and the host runtime"
  KIND_NODES="$(kind get nodes --name "$KIND_CLUSTER" 2>/dev/null || true)"
  # Whichever runtime can actually see the Kind node: a `docker` on PATH may be a podman shim, or
  # a real Docker that knows nothing of a podman-provider cluster. Falls back to the same choice
  # as k8s/opa-kind-enable.sh, which loaded some of these.
  if [ -z "${CONTAINER_RUNTIME:-}" ]; then
    first_node="$(printf '%s\n' "$KIND_NODES" | head -1)"
    for rt in docker podman; do
      if [ -n "$first_node" ] && command -v "$rt" >/dev/null 2>&1 \
         && "$rt" inspect "$first_node" >/dev/null 2>&1; then
        CONTAINER_RUNTIME="$rt"; break
      fi
    done
  fi
  if [ -z "${CONTAINER_RUNTIME:-}" ]; then
    if [ "${KIND_EXPERIMENTAL_PROVIDER:-}" = "podman" ] || ! command -v docker >/dev/null 2>&1; then
      CONTAINER_RUNTIME=podman
    else
      CONTAINER_RUNTIME=docker
    fi
  fi
  [ -n "$KIND_NODES" ] || warn "no nodes found for Kind cluster '${KIND_CLUSTER}' — removing host copies only"
  IMAGES_IN_USE="$(kubectl get pods -A \
    -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
    2>/dev/null | sort -u || true)"
  for img in "${DEMO_IMAGES[@]}"; do remove_image "$img"; done
  [ "$DRY_RUN" -eq 1 ] || pass "local images removed (anything still in use was kept and reported above)"
else
  step "Container images left in place (pass --include-images to delete them)"
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
$([ "$DO_OPA" -eq 1 ] && printf '%s\n' \
"  kubectl get deploy bundle-service -n ${RELEASE_NAMESPACE}        # expect: NotFound" \
"  kubectl get cm authbridge-runtime-config -n ${NS} -o jsonpath='{.data.config\\.yaml}' | grep -c 'name: opa'  # expect: 0")
$([ "$DO_IMAGES" -eq 1 ] && printf '%s' "  docker exec ${KIND_CLUSTER}-control-plane crictl images | grep localhost/   # expect: no matches (podman exec on podman)")

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
    This demo and the system test suite both rely on these.
  - the operator's '*-aud' audience client scopes, which it owns and recreates.
$([ "$DO_IMAGES" -eq 0 ] && printf '%s\n' \
"  - container images in the Kind node (inert) — re-run with --include-images to delete them." \
"    Because they survive, a plain './enable.sh' will SKIP rebuilding the stack images and re-load" \
"    these — so any source change you made since would not reach the cluster. Use --rebuild below.")
$([ "$DO_OPA" -eq 0 ] && printf '%s' "  - the OPA pipeline overlay, bundle-service and the authbridge image pin — re-run with --include-opa.")
$([ "$DO_OPA" -eq 1 ] && printf '%s' "  - the AuthorizationPolicy CRD (deleting it would delete every policy CR cluster-wide).")

To stand the demo back up: see demo.md, Part 1.$([ "$DO_OPA" -eq 1 ] && printf '\n%s' \
"  ../../../k8s/opa-kind-enable.sh   # first: OPA overlay, bundle-service, local authbridge + operator images")
  ./enable.sh --rebuild     # rebuild the four stack images from current source, then install
  ./enable.sh               # reuse the images already built (faster; no source change since)
EOF
