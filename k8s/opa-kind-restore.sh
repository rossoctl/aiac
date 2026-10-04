#!/usr/bin/env bash
# opa-kind-restore.sh — revert opa-kind-enable.sh.
#
# Re-applies the rossoctl chart's real, untouched charts/rossoctl/values.yaml
# (no OPA/parser overlay) and restarts the authbridge sidecars so they pick
# up the reverted pipeline. Mirrors the "Rollback" section of
# authbridge/docs/opa-kind-runbook.md verbatim — since opa-kind-enable.sh
# never wrote to values.yaml, "restoring" it is just re-running helm upgrade
# against that same file with no overlay on top.
#
# Drops the pipeline overlay (-f OVERLAY_FILE) but keeps the same
# cluster-shape --set flags as the enable step (openshift, featureFlags.
# agentSandbox, the local image override) — those describe the Kind
# cluster/local-image setup, not the OPA overlay, and the chart's own
# defaults assume OpenShift (openshift: true), so dropping them breaks
# the upgrade on Kind (see mcp-gateway.yaml's openshiftDomain check).
# It does not pass operator-chart.featureGates.injectTools=true either, so the
# webhook default (no sidecar for tool pods) comes back with the upgrade.
#
# It also puts back the stock global combiner (the `default` AuthorizationPolicy
# in RELEASE_NAMESPACE) in place of the changed combiner (D20) that
# opa-kind-enable.sh applied: it renders the stock default-policy.yaml from the
# operator chart (the one bundle-service template that the enable script skips)
# and applies it. With the stock combiner a pod that has no client CR is
# allowed again. The bundle service itself stays.
#
# Then it restarts the agent AND the tool pods, because the webhook copies the
# namespace pipeline into a pod only at pod CREATE.
#
# Env vars:
#   OPERATOR_DIR        path to the rossoctl/operator repo clone; the stock
#                       combiner is rendered from its local chart (default: ../operator)
#   ROSSOCTL_DIR        path to the rossoctl/rossoctl repo clone (the chart)
#   RELEASE_NAME        helm release name                 (default: rossoctl)
#   RELEASE_NAMESPACE   namespace the chart is installed in (default: rossoctl-system)
#   AGENT_NAMESPACE     namespace to restart agent and tool pods in (default: team1)
#   IMAGE_TAG           local authbridge-proxy image tag  (default: localhost/authbridge:local)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OPERATOR_DIR="${OPERATOR_DIR:-$(cd "$REPO_ROOT/../operator" 2>/dev/null && pwd || echo "")}"
ROSSOCTL_DIR="${ROSSOCTL_DIR:-$(cd "$REPO_ROOT/../rossoctl" 2>/dev/null && pwd || echo "")}"
RELEASE_NAME="${RELEASE_NAME:-rossoctl}"
RELEASE_NAMESPACE="${RELEASE_NAMESPACE:-rossoctl-system}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-team1}"
IMAGE_TAG="${IMAGE_TAG:-localhost/authbridge:local}"

if [ -z "$OPERATOR_DIR" ] || [ ! -f "$OPERATOR_DIR/charts/operator/templates/bundleservice/default-policy.yaml" ]; then
  echo "ERROR: Set OPERATOR_DIR to point to your rossoctl/operator repo clone" >&2
  echo "       (the stock combiner is rendered from" >&2
  echo "        \$OPERATOR_DIR/charts/operator/templates/bundleservice/default-policy.yaml)" >&2
  exit 1
fi
if [ -z "$ROSSOCTL_DIR" ] || [ ! -d "$ROSSOCTL_DIR" ]; then
  echo "ERROR: Set ROSSOCTL_DIR to point to your rossoctl/rossoctl repo clone" >&2
  exit 1
fi

VALUES_FILE="${ROSSOCTL_DIR}/charts/rossoctl/values.yaml"
CHART_DIR="${ROSSOCTL_DIR}/charts/rossoctl"
if [ ! -f "$VALUES_FILE" ]; then
  echo "ERROR: ${VALUES_FILE} not found — check ROSSOCTL_DIR" >&2
  exit 1
fi

echo "==> Step 1/3: restoring original pipeline from ${VALUES_FILE} (no OPA/parser overlay)"
( cd "$CHART_DIR" && helm dependency build )
helm upgrade "$RELEASE_NAME" "$CHART_DIR" -n "$RELEASE_NAMESPACE" \
  -f "$VALUES_FILE" \
  --set openshift=false \
  --set featureFlags.agentSandbox=true \
  --set operator-chart.defaults.images.authbridge="$IMAGE_TAG"

echo "==> Step 2/3: restoring the stock global combiner (${OPERATOR_DIR}/charts/operator)"
# The render of opa-kind-enable.sh Step 1, for default-policy.yaml only (the
# template that the enable script skips).
# kubectl apply replaces spec.policies as a whole, so the two request packages
# get their `client_ok if not data.authbridge.client.<dir>.request` rule back.
# Skip when the AuthorizationPolicy CRD is absent (the enable script never ran).
if kubectl get crd authorizationpolicies.agent.rossoctl.dev >/dev/null 2>&1; then
  helm template rossoctl-operator "$OPERATOR_DIR/charts/operator" \
    --namespace "$RELEASE_NAMESPACE" \
    --set bundleService.enabled=true \
    --show-only templates/bundleservice/default-policy.yaml \
    | kubectl apply -f -
else
  echo "    no AuthorizationPolicy CRD in the cluster — nothing to restore"
fi

echo "==> Step 3/3: restarting the agent and tool pods in ${AGENT_NAMESPACE}"
kubectl delete pods -n "$AGENT_NAMESPACE" -l 'rossoctl.io/type in (agent,tool)' --ignore-not-found

cat <<EOF
==> Done.

Verify the pipeline is back to its original state (count depends on what
values.yaml originally shipped — 0 if it never had OPA):
  kubectl get configmap authbridge-runtime-config -n ${AGENT_NAMESPACE} \\
    -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'

Verify the stock combiner is back (expect 2 request fallback rules):
  kubectl get authorizationpolicy default -n ${RELEASE_NAMESPACE} \\
    -o jsonpath='{.spec.policies[*].content}' \\
    | grep -cE 'client_ok if not data\.authbridge\.client\.(inbound|outbound)\.request'

The AIAC Controller start check #4 (D30) fails with the stock combiner, so the
Controller does not start again until opa-kind-enable.sh runs again.
EOF
