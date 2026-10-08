#!/usr/bin/env bash
# restore.sh — full teardown of what driver.sh's DEPLOY phase created, so the NEXT run's deploy is a
# genuine first-time trigger again (not a no-op against clients that are still registered). Because
# deploying the workloads for the first time *is* the point of this demo, restore must remove them
# completely: Deployments, Services, ServiceAccounts, AgentRuntime CRs, their Keycloak clients and
# credentials Secrets, and the AuthorizationPolicy CR AIAC wrote. It also reverts the outbound-leg
# wiring driver.sh's WIRE phase added.
#
# Usage:
#   ./restore.sh                   # the demo's own state (workloads, clients, CR, wiring)
#   ./restore.sh --include-infra   # ALSO revert what enable.sh installed: the realm's
#                                  # aiac-event-listener config and the Keycloak StatefulSet image
#
# By default the AIAC stack / NATS broker / Keycloak SPI stay in place (additive infra, and re-running
# the demo needs them). --include-infra reverses enable.sh's Keycloak-side changes; the aiac-system
# namespace is still yours to delete by hand (see the closing notes).
#
# Neither mode touches the OPA pipeline overlay from k8s/opa-kind-enable.sh — revert that with
# k8s/opa-kind-restore.sh.
#
# Env vars:
#   NS                        agent/tool namespace                      (default: team1)
#   KC, REALM                 Keycloak base URL + realm
#   KEYCLOAK_NAMESPACE        namespace Keycloak runs in                 (default: keycloak)
#   KEYCLOAK_STATEFULSET      name of the Keycloak StatefulSet            (default: keycloak)
#   ORIGINAL_KEYCLOAK_IMAGE   image --include-infra restores Keycloak to
#                             (default: quay.io/keycloak/keycloak:26.5.2)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AIAC_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ASSETS_DIR="$AIAC_DIR/demo/assets"

NS="${NS:-team1}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
KEYCLOAK_NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_STATEFULSET="${KEYCLOAK_STATEFULSET:-keycloak}"
ORIGINAL_KEYCLOAK_IMAGE="${ORIGINAL_KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.2}"

DO_INFRA=0
case "${1:-}" in
  --include-infra) DO_INFRA=1 ;;
  "") ;;
  *) echo "Usage: $0 [--include-infra]" >&2; exit 1 ;;
esac

AGENT_LABEL="app.kubernetes.io/name=github-agent"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

# Prints "" (exit 0) rather than raising when Keycloak is unreachable or returns a non-JSON body.
# Restore must survive a half-torn-down cluster, and under `set -euo pipefail` a raising python3 would
# abort here — the `[ -n "$ADMIN" ]` guard below is what's meant to handle a missing token.
admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("access_token","") or "")
except Exception: print("")'
}

# json_eval <python-expr> — evaluate <python-expr> over the JSON on stdin (bound to `d`; env vars via
# `os.environ`) and print the result (one line per item when it returns a newline-joined string).
# Prints "" (exit 0) instead of raising on a Keycloak error body or an unreachable server, so a
# half-torn-down cluster degrades to "nothing found" rather than a `set -e` abort.
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

# client_uuid_by_name <name> — the Keycloak client looked up by its "name" DISPLAY field
# (e.g. "team1/github-agent"), not clientId. Prints "" if not found.
client_uuid_by_name() {
  curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients" \
    | CLIENT_NAME="$1" json_eval 'next((c["id"] for c in d if c.get("name") == os.environ["CLIENT_NAME"]), "")'
}

echo "==> 1. Reverting authproxy-routes (dropping the github-tool route)"
kubectl patch configmap authproxy-routes -n "$NS" --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml": ""}}))')" || true

echo "==> 2. Removing the optional client-scope from github-agent (if present)"
ADMIN="$(admin_token)"
if [ -n "$ADMIN" ]; then
  AGENT_UUID="$(client_uuid_by_name "${NS}/github-agent")"
  SCOPE_ID=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" \
    | SCOPE_NAME="agent-${NS}-github-tool-aud" json_eval 'next((s["id"] for s in d if s.get("name") == os.environ["SCOPE_NAME"]), "")')
  if [ -n "$AGENT_UUID" ] && [ -n "$SCOPE_ID" ]; then
    curl -s -o /dev/null -w "    remove scope HTTP %{http_code}\n" -X DELETE \
      -H "Authorization: Bearer ${ADMIN}" \
      "${KC}/admin/realms/${REALM}/clients/${AGENT_UUID}/optional-client-scopes/${SCOPE_ID}"
  else
    echo "    (client or scope not found — nothing to remove)"
  fi

  echo "==> 3. Deleting the Keycloak clients ${NS}/github-agent, ${NS}/github-tool"
  for name in "${NS}/github-agent" "${NS}/github-tool"; do
    UUID="$(client_uuid_by_name "$name")"
    if [ -n "$UUID" ]; then
      curl -s -o /dev/null -w "    delete ${name} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients/${UUID}"
    else
      echo "    (${name} not registered — nothing to delete)"
    fi
  done
else
  echo "    WARNING: could not obtain a Keycloak admin token — skipping steps 2-3" >&2
fi

echo "==> 4. Deleting leftover client-scopes and realm roles for github-agent/github-tool"
echo "    (AIAC's Policy Rules Builder creates these via blind POSTs with no existence check —"
echo "     see aiac/src/aiac/idp/service/configuration/keycloak/main.py's create_scope/create_role —"
echo "     so a stale scope/role from a prior onboarding cycle causes a 409/502 on the next one.)"
if [ -n "$ADMIN" ]; then
  for component in github-agent github-tool; do
    SCOPE_IDS=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" \
      | COMPONENT="$component" AUD_NAME="agent-${NS}-${component}-aud" json_eval '"\n".join(
    s["id"] for s in d
    if s.get("name", "").startswith(os.environ["COMPONENT"] + ".") or s.get("name") == os.environ["AUD_NAME"])')
    for id in $SCOPE_IDS; do
      curl -s -o /dev/null -w "    delete client-scope (${component}) ${id} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes/${id}"
    done

    ROLE_NAMES=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/roles" \
      | COMPONENT="$component" json_eval '"\n".join(
    r["name"] for r in d if r.get("name", "").startswith(os.environ["COMPONENT"] + "."))')
    while IFS= read -r role; do
      [ -n "$role" ] || continue
      curl -s -o /dev/null -w "    delete role ${role} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/roles/${role}"
    done <<< "$ROLE_NAMES"
  done
else
  echo "    WARNING: could not obtain a Keycloak admin token — skipping leftover scope/role cleanup" >&2
fi

echo "==> 5. Deleting the AuthorizationPolicy CR AIAC wrote for github-agent"
kubectl delete "$POLICY_CR" github-agent -n "$NS" --ignore-not-found

echo "==> 6. Deleting github-agent/github-tool workloads (Deployment/Service/ServiceAccount/AgentRuntime)"
kubectl delete -f "$ASSETS_DIR/agents/github_agent/k8s/github-agent-deployment.yaml" -n "$NS" --ignore-not-found
kubectl delete -f "$ASSETS_DIR/tools/github_tool/k8s/github-tool-deployment.yaml" -n "$NS" --ignore-not-found

echo "==> 7. Deleting the github-agent/github-tool client-credentials Secrets in '${NS}'"
# Only the demo's two Secrets, not every rossoctl-keycloak-client-credentials-* in the namespace
# (other workloads have theirs there too). The operator names them deterministically from
# (namespace, workload) — mirror of clientreg.KeycloakClientCredentialsSecretName in rossoctl/operator.
for workload in github-agent github-tool; do
  secret=$(NS="$NS" WORKLOAD="$workload" python3 -c '
import hashlib, os
key = os.environ["NS"] + "\0" + os.environ["WORKLOAD"] + "\0rossoctl-keycloak-client-credentials"
print("rossoctl-keycloak-client-credentials-" + hashlib.sha256(key.encode()).hexdigest()[:16])')
  kubectl delete secret "$secret" -n "$NS" --ignore-not-found
done

# ── --include-infra: reverse enable.sh's Keycloak-side changes ────────────────
if [ "$DO_INFRA" -eq 1 ]; then
  echo "==> 8. Disabling the aiac-event-listener on realm '${REALM}' (reverses enable.sh --spi-only)"
  if [ -n "$ADMIN" ]; then
    curl -s -o /dev/null -w "    events/config HTTP %{http_code}\n" -X PUT \
      -H "Authorization: Bearer ${ADMIN}" -H "Content-Type: application/json" \
      "${KC}/admin/realms/${REALM}/events/config" \
      -d '{"adminEventsEnabled": false, "eventsListeners": ["jboss-logging"]}'
  else
    echo "    WARNING: no Keycloak admin token — skipping listener revert" >&2
  fi

  echo "==> 9. Reverting statefulset/${KEYCLOAK_STATEFULSET} to ${ORIGINAL_KEYCLOAK_IMAGE}"
  # enable.sh patched this live (kubectl set image), not via the chart, so this puts it back.
  kubectl set image "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" \
    "${KEYCLOAK_STATEFULSET}=${ORIGINAL_KEYCLOAK_IMAGE}"
  kubectl rollout status "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" --timeout=180s
fi

cat <<EOF
==> Done. github-agent/github-tool and their Keycloak clients are fully removed — the next
    ./driver.sh run's DEPLOY phase will be a genuine first-time trigger again.
$([ "$DO_INFRA" -eq 1 ] && printf '%s' "    The Keycloak SPI listener and image were reverted too (--include-infra).")

NOT reverted (additive infra, left in place — delete the namespace by hand for a full reset):
  kubectl delete namespace aiac-system$([ "$DO_INFRA" -eq 0 ] && printf '\n%s' "
Also still in place: the Keycloak SPI listener + derived image from ./enable.sh — re-run this
script with --include-infra to reverse those too.")

Verify OPA count is unaffected by this restore (still 2 — this script never touches the OPA
overlay from k8s/opa-kind-enable.sh):
  kubectl get configmap authbridge-runtime-config -n ${NS} \\
    -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
EOF
