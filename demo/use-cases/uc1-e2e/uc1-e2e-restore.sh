#!/usr/bin/env bash
# uc1-e2e-restore.sh — full teardown of what uc1-e2e-driver.sh's DEPLOY phase created, so the
# NEXT run's deploy is a genuine first-time trigger again (not a no-op against clients that are
# still registered). This is intentionally stronger than
# uc1-integration/uc1-integration-restore.sh, which leaves github-agent/github-tool in place —
# here, deploying them for the first time *is* the point of the demo, so restore must remove them
# completely: Deployments, Services, ServiceAccounts, AgentRuntime CRs, their Keycloak clients and
# credentials Secrets, and the AuthorizationPolicy CR AIAC wrote.
#
# Leaves the AIAC stack / NATS broker / Keycloak SPI listener in place (additive infra — same
# principle as every other *-restore.sh in this demo family). Delete the aiac-system namespace by
# hand if you want a fully clean slate.
#
# Env vars:
#   NS                    agent/tool namespace                          (default: team1)
#   KC, REALM             Keycloak base URL + realm
#   KEYCLOAK_NAMESPACE    namespace Keycloak runs in                     (default: keycloak)
#   KEYCLOAK_STATEFULSET  name of the Keycloak StatefulSet                (default: keycloak)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORTEX_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSETS_DIR="$CORTEX_DIR/aiac/demo/assets"

NS="${NS:-team1}"
KC="${KC:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"

AGENT_LABEL="app.kubernetes.io/name=github-agent"
POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

admin_token() {
  curl -s -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'
}

echo "==> 1. Reverting authproxy-routes (dropping the github-tool route)"
kubectl patch configmap authproxy-routes -n "$NS" --type merge -p "$(python3 -c '
import json
print(json.dumps({"data":{"routes.yaml": ""}}))')" || true

echo "==> 2. Removing the optional client-scope from github-agent (if present)"
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

  echo "==> 3. Deleting the Keycloak clients team1/github-agent, team1/github-tool"
  for name in "team1/github-agent" "team1/github-tool"; do
    UUID=$(curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients" \
      | CLIENT_NAME="$name" python3 -c '
import sys, json, os
name = os.environ["CLIENT_NAME"]
for c in json.load(sys.stdin):
    if c.get("name") == name:
        print(c["id"]); break
')
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
else
  echo "    WARNING: could not obtain a Keycloak admin token — skipping leftover scope/role cleanup" >&2
fi

echo "==> 5. Deleting the AuthorizationPolicy CR AIAC wrote for github-agent"
kubectl delete "$POLICY_CR" github-agent -n "$NS" --ignore-not-found

echo "==> 6. Deleting github-agent/github-tool workloads (Deployment/Service/ServiceAccount/AgentRuntime)"
kubectl delete -f "$ASSETS_DIR/agents/github_agent/k8s/github-agent-deployment.yaml" -n "$NS" --ignore-not-found
kubectl delete -f "$ASSETS_DIR/tools/github_tool/k8s/github-tool-deployment.yaml" -n "$NS" --ignore-not-found

echo "==> 7. Deleting leftover client-credentials Secrets in '${NS}'"
kubectl get secret -n "$NS" -o name 2>/dev/null \
  | { grep '^secret/rossoctl-keycloak-client-credentials-' || true; } \
  | xargs -r kubectl delete -n "$NS" --ignore-not-found

cat <<EOF
==> Done. github-agent/github-tool and their Keycloak clients are fully removed — the next
    ./uc1-e2e-driver.sh run's DEPLOY phase will be a genuine first-time trigger again.

NOT reverted (additive infra, left in place — delete the namespace by hand for a full reset):
  kubectl delete namespace aiac-system

Verify OPA count is unaffected by this restore (still 2 — this script never touches the OPA
overlay from aiac/k8s/opa-kind-enable.sh):
  kubectl get configmap authbridge-runtime-config -n ${NS} \\
    -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'
EOF
