#!/usr/bin/env bash
# uc1-integration-restore.sh — revert what uc1-integration-enable.sh + uc1-integration-driver.sh
# changed. Mirrors aiac/k8s/opa-kind-restore.sh's scope: undo the *mutations* (Keycloak client
# scope, authproxy-routes, the Keycloak realm's admin-events config, the Keycloak StatefulSet's
# image), but leave *additive* infra in place (the AIAC stack, the NATS broker — same principle as
# opa-kind-restore.sh leaving bundle-service deployed). Delete the aiac-system namespace by hand
# if you want a fully clean slate.
#
# Env vars:
#   NS                    agent namespace                                (default: team1)
#   KC, REALM             Keycloak base URL + realm
#   KEYCLOAK_NAMESPACE    namespace Keycloak runs in                     (default: keycloak)
#   KEYCLOAK_STATEFULSET  name of the Keycloak StatefulSet                (default: keycloak)
#   ORIGINAL_KEYCLOAK_IMAGE  image to revert the StatefulSet to           (default: quay.io/keycloak/keycloak:26.5.2)

set -euo pipefail

NS="${NS:-team1}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
KEYCLOAK_NAMESPACE="${KEYCLOAK_NAMESPACE:-keycloak}"
KEYCLOAK_STATEFULSET="${KEYCLOAK_STATEFULSET:-keycloak}"
ORIGINAL_KEYCLOAK_IMAGE="${ORIGINAL_KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.2}"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'
}

echo "==> 1. Deleting the forced-fresh github-agent AuthorizationPolicy CR"
kubectl delete "$POLICY_CR" github-agent -n "$NS" --ignore-not-found

echo "==> 2. Reverting authproxy-routes (dropping the github-tool route)"
kubectl patch configmap authproxy-routes -n "$NS" --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml": ""}}))')" || true

echo "==> 3. Removing the optional client-scope from github-agent"
ADMIN="$(admin_token)"
if [ -n "$ADMIN" ]; then
  AGENT_UUID=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients" \
    | python3 -c 'import sys,json;print(next((c["id"] for c in json.load(sys.stdin) if c.get("name")=="team1/github-agent"),""))')
  SCOPE_ID=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" \
    | python3 -c 'import sys,json;print(next((s["id"] for s in json.load(sys.stdin) if s["name"]=="agent-team1-github-tool-aud"),""))')
  if [ -n "$AGENT_UUID" ] && [ -n "$SCOPE_ID" ]; then
    curl -s -o /dev/null -w "    remove scope HTTP %{http_code}\n" -X DELETE \
      -H "Authorization: Bearer ${ADMIN}" \
      "${KC}/admin/realms/${REALM}/clients/${AGENT_UUID}/optional-client-scopes/${SCOPE_ID}"
  else
    echo "    (client or scope not found — nothing to remove)"
  fi

  echo "==> 4. Deleting leftover client-scopes and realm roles for github-agent/github-tool"
  echo "    (AIAC's Policy Rules Builder creates these via blind POSTs with no existence check —"
  echo "     see aiac/src/aiac/idp/service/configuration/keycloak/main.py's create_scope/create_role —"
  echo "     so a stale scope/role from a prior onboarding cycle causes a 409/502 on the next one.)"
  for component in github-agent github-tool; do
    SCOPE_IDS=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes" \
      | COMPONENT="$component" AUD_NAME="agent-${NS}-${component}-aud" python3 -c '
import sys, json, os
component = os.environ["COMPONENT"]
aud_name = os.environ["AUD_NAME"]
for s in json.load(sys.stdin):
    name = s.get("name", "")
    if name.startswith(component + ".") or name == aud_name:
        print(s["id"])
')
    for id in $SCOPE_IDS; do
      curl -s -o /dev/null -w "    delete client-scope (${component}) ${id} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes/${id}"
    done

    ROLE_NAMES=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/roles" \
      | COMPONENT="$component" python3 -c '
import sys, json, os
component = os.environ["COMPONENT"]
for r in json.load(sys.stdin):
    name = r.get("name", "")
    if name.startswith(component + "."):
        print(name)
')
    while IFS= read -r role; do
      [ -n "$role" ] || continue
      curl -s -o /dev/null -w "    delete role ${role} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/roles/${role}"
    done <<< "$ROLE_NAMES"
  done

  echo "==> 5. Disabling the aiac-event-listener on realm '${REALM}'"
  curl -s -o /dev/null -w "    events/config HTTP %{http_code}\n" -X PUT \
    -H "Authorization: Bearer ${ADMIN}" -H "Content-Type: application/json" \
    "${KC}/admin/realms/${REALM}/events/config" \
    -d '{"adminEventsEnabled": false, "eventsListeners": ["jboss-logging"]}'
else
  echo "    WARNING: could not obtain a Keycloak admin token — skipping steps 3-5" >&2
fi

echo "==> 6. Reverting statefulset/${KEYCLOAK_STATEFULSET} to ${ORIGINAL_KEYCLOAK_IMAGE}"
kubectl set image "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" \
  "${KEYCLOAK_STATEFULSET}=${ORIGINAL_KEYCLOAK_IMAGE}"
kubectl rollout status "statefulset/${KEYCLOAK_STATEFULSET}" -n "$KEYCLOAK_NAMESPACE" --timeout=180s

echo "==> 7. Restarting github-agent to drop the outbound route"
kubectl delete pod -n "$NS" -l "$AGENT_LABEL" --ignore-not-found

cat <<EOF
==> Done.

NOT reverted (additive infra, left in place — delete the namespace by hand for a full reset):
  kubectl delete namespace aiac-system

Verify OPA count is unaffected by this restore (still 2 — this script never touches the OPA
overlay from aiac/k8s/opa-kind-enable.sh):
  kubectl get configmap authbridge-runtime-config -n ${NS} \\
    -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
EOF
