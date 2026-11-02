#!/usr/bin/env bash
# restore.sh — full teardown of what driver.sh's DEPLOY phase created, so the NEXT run's deploy is a
# genuine first-time trigger again (not a no-op against clients that are still registered). Because
# deploying the workloads for the first time *is* the point of this demo, restore must remove them
# completely: Deployments, Services, ServiceAccounts, AgentRuntime CRs, their Keycloak clients and
# credentials Secrets, and the two AuthorizationPolicy CRs AIAC wrote (one per managed service, D20).
# It also reverts the outbound-leg wiring driver.sh's WIRE phase added.
#
# Usage:
#   ./restore.sh                   # the demo's own state (workloads, clients, CRs, wiring)
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

# json_eval, aud_scope, realm_client_scopes and scope_id_in: one copy, shared with driver.sh.
# shellcheck source=SCRIPTDIR/lib/keycloak.sh
. "${SCRIPT_DIR}/lib/keycloak.sh"

# The audience scopes restore removes, named once: step 1 unlinks the tool scopes WIRE granted, step 3
# deletes the two workloads' own. Restore must survive a half-torn-down setup, so a failure of
# k8s/operator-names.py does not stop it: it warns, and steps 1 and 3 skip the audience scopes (an empty
# name), while the clients, CRs, workloads and Secrets are still removed.
NAMES_OK=1
AGENT_AUD_SCOPE="$(aud_scope github-agent)" || NAMES_OK=0
TOOL_AUD_SCOPE="$(aud_scope github-tool)" || NAMES_OK=0
MCP_AUD_SCOPE="$(aud_scope github-tool-mcp)" || NAMES_OK=0
[ "$NAMES_OK" -eq 1 ] || echo "WARNING: k8s/operator-names.py failed — the audience scopes are not removed; the rest of restore runs" >&2

# client_uuid_by_name <name> — the Keycloak client looked up by its "name" DISPLAY field
# (e.g. "team1/github-agent"), not clientId. Prints "" if not found.
client_uuid_by_name() {
  curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients" \
    | CLIENT_NAME="$1" json_eval 'next((c["id"] for c in d if c.get("name") == os.environ["CLIENT_NAME"]), "")'
}

echo "==> 1. Removing the client-scopes WIRE linked to github-agent (default or optional, if present)"
# The audience scopes WIRE links: the stub github-tool's, and the production github-tool-mcp's when that
# tool is registered. Step 2 deletes the client anyway, which drops every link; this step says what was
# granted. The realm's client-scopes are read once, and each name looked up in them: "absent" when the
# realm has none, "" when the read failed (scope_id_in, lib/keycloak.sh). A failed read skips this step;
# step 2 still runs.
ADMIN="$(admin_token)"
if [ -n "$ADMIN" ]; then
  AGENT_UUID="$(client_uuid_by_name "${NS}/github-agent")"
  REALM_SCOPES="$(realm_client_scopes "$ADMIN")"
  if [ -n "$AGENT_UUID" ]; then
    for scope in "$TOOL_AUD_SCOPE" "$MCP_AUD_SCOPE"; do
      [ -n "$scope" ] || continue  # k8s/operator-names.py failed (warned above)
      SCOPE_ID="$(scope_id_in "$scope" <<<"$REALM_SCOPES")"
      case "$SCOPE_ID" in
        absent) echo "    ${scope}: not in the realm — nothing to remove"; continue ;;
        "") echo "    ${scope}: the realm's client-scopes could not be read — skipped"; continue ;;
      esac
      for kind in default optional; do
        # || true: a failed DELETE must not stop restore before step 2 deletes the clients.
        curl -s -o /dev/null -w "    ${scope}: remove ${kind} link HTTP %{http_code}\n" -X DELETE \
          -H "Authorization: Bearer ${ADMIN}" \
          "${KC}/admin/realms/${REALM}/clients/${AGENT_UUID}/${kind}-client-scopes/${SCOPE_ID}" || true
      done
    done
  else
    echo "    (client not found — nothing to remove)"
  fi

  echo "==> 2. Deleting the Keycloak clients ${NS}/github-agent, ${NS}/github-tool"
  for name in "${NS}/github-agent" "${NS}/github-tool"; do
    UUID="$(client_uuid_by_name "$name")"
    if [ -n "$UUID" ]; then
      curl -s -o /dev/null -w "    delete ${name} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/clients/${UUID}" || true
    else
      echo "    (${name} not registered — nothing to delete)"
    fi
  done
else
  echo "    WARNING: could not obtain a Keycloak admin token — skipping steps 1-2" >&2
fi

echo "==> 3. Deleting leftover client-scopes and realm roles for github-agent/github-tool"
echo "    (AIAC's Policy Rules Builder creates these via blind POSTs with no existence check —"
echo "     see aiac/src/aiac/idp/service/configuration/keycloak/main.py's create_scope/create_role —"
echo "     so a stale scope/role from a prior onboarding cycle causes a 409/502 on the next one.)"
if [ -n "$ADMIN" ]; then
  for component in github-agent github-tool; do
    case "$component" in
      github-agent) aud_name="$AGENT_AUD_SCOPE" ;;
      github-tool) aud_name="$TOOL_AUD_SCOPE" ;;
    esac
    # A fresh read, not step 1's list: the workloads run until step 5, so an onboarding still in flight can
    # create scopes after step 1. A failed read deletes nothing here, and restore goes on. An empty
    # aud_name (k8s/operator-names.py failed, warned above) matches no scope: the prefixed ones still go.
    SCOPE_IDS=$(realm_client_scopes "$ADMIN" \
      | COMPONENT="$component" AUD_NAME="$aud_name" json_eval '"\n".join(
    s["id"] for s in d
    if s.get("name", "").startswith(os.environ["COMPONENT"] + ".")
    or (os.environ["AUD_NAME"] and s.get("name") == os.environ["AUD_NAME"]))')
    for id in $SCOPE_IDS; do
      curl -s -o /dev/null -w "    delete client-scope (${component}) ${id} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/client-scopes/${id}" || true
    done

    ROLE_NAMES=$( { curl -s -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/roles" || true; } \
      | COMPONENT="$component" json_eval '"\n".join(
    r["name"] for r in d if r.get("name", "").startswith(os.environ["COMPONENT"] + "."))')
    while IFS= read -r role; do
      [ -n "$role" ] || continue
      curl -s -o /dev/null -w "    delete role ${role} HTTP %{http_code}\n" -X DELETE \
        -H "Authorization: Bearer ${ADMIN}" "${KC}/admin/realms/${REALM}/roles/${role}" || true
    done <<< "$ROLE_NAMES"
  done
else
  echo "    WARNING: could not obtain a Keycloak admin token — skipping leftover scope/role cleanup" >&2
fi

echo "==> 4. Deleting the AuthorizationPolicy CRs AIAC wrote for github-agent and github-tool"
kubectl delete "$POLICY_CR" github-agent github-tool -n "$NS" --ignore-not-found

echo "==> 5. Deleting github-agent/github-tool workloads (Deployment/Service/ServiceAccount/AgentRuntime)"
kubectl delete -f "$ASSETS_DIR/agents/github_agent/k8s/github-agent-deployment.yaml" -n "$NS" --ignore-not-found
kubectl delete -f "$ASSETS_DIR/tools/github_tool/k8s/github-tool-deployment.yaml" -n "$NS" --ignore-not-found

echo "==> 6. Deleting the github-agent/github-tool client-credentials Secrets in '${NS}'"
# Only the demo's two Secrets, not every rossoctl-keycloak-client-credentials-* in the namespace
# (other workloads have theirs there too). The operator names them deterministically from
# (namespace, workload): k8s/operator-names.py computes it as rossoctl/operator does, the one copy that
# the system harness also uses.
for workload in github-agent github-tool; do
  secret="$(python3 "$AIAC_DIR/k8s/operator-names.py" secret "$NS" "$workload")"
  kubectl delete secret "$secret" -n "$NS" --ignore-not-found
done

# ── --include-infra: reverse enable.sh's Keycloak-side changes ────────────────
if [ "$DO_INFRA" -eq 1 ]; then
  echo "==> 7. Disabling the aiac-event-listener on realm '${REALM}' (reverses enable.sh --spi-only)"
  if [ -n "$ADMIN" ]; then
    curl -s -o /dev/null -w "    events/config HTTP %{http_code}\n" -X PUT \
      -H "Authorization: Bearer ${ADMIN}" -H "Content-Type: application/json" \
      "${KC}/admin/realms/${REALM}/events/config" \
      -d '{"adminEventsEnabled": false, "eventsListeners": ["jboss-logging"]}'
  else
    echo "    WARNING: no Keycloak admin token — skipping listener revert" >&2
  fi

  echo "==> 8. Reverting statefulset/${KEYCLOAK_STATEFULSET} to ${ORIGINAL_KEYCLOAK_IMAGE}"
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

Verify the pipeline wiring is unaffected by this restore (still "ok trust_domain=..." — this
script never touches the OPA overlay from k8s/opa-kind-enable.sh):
  kubectl get configmap authbridge-runtime-config -n ${NS} \\
    -o jsonpath='{.data.config\.yaml}' | python3 ${AIAC_DIR}/k8s/authbridge-pipeline-check.py
EOF
