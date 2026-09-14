#!/usr/bin/env bash
# Idempotent uninstaller for the demo/assets workloads (github-tool, github-agent) from a
# rossoctl/Kind cluster. Reverses install.sh: deletes every object the matching manifest
# creates (ServiceAccount + Deployment + Service + AgentRuntime), so a subsequent install.sh
# run recreates them as if from a fresh cluster. Does NOT touch namespace `team1` itself
# (install.sh treats it as a precondition it doesn't own — this script does the same) and
# does NOT remove locally built/kind-loaded images.
#
# This only tears down the k8s objects. Keycloak roles/scopes, the Policy Store, and the
# agent's AuthorizationPolicy CR are the UC-1 onboarding demo's own state — reset those with
# `make clear` in demo/use-cases/uc1-onboarding/, not here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NAMESPACE="${NAMESPACE:-team1}"

DO_TOOL=1
DO_AGENT=1
WAIT=1

for arg in "$@"; do
  case "$arg" in
    --agent-only) DO_TOOL=0 ;;
    --tool-only) DO_AGENT=0 ;;
    --no-wait) WAIT=0 ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--agent-only|--tool-only] [--no-wait]" >&2
      exit 1
      ;;
  esac
done

log() { echo "[uninstall.sh] $*" >&2; }

preflight() {
  if ! command -v kubectl >/dev/null 2>&1; then
    log "ERROR: required binary 'kubectl' not found on PATH."
    exit 1
  fi

  if ! kubectl cluster-info >/dev/null 2>&1; then
    log "ERROR: kubectl cannot reach a cluster."
    exit 1
  fi
}

wait_gone() {
  local label="$1"
  [ "$WAIT" -eq 1 ] || return 0
  log "Waiting for pods matching '$label' to terminate"
  kubectl wait --for=delete pod -l "$label" -n "$NAMESPACE" --timeout=60s 2>/dev/null || true
}

uninstall_tool() {
  local dir="$SCRIPT_DIR/tools/github_tool"
  log "Deleting tool manifests"
  kubectl delete -n "$NAMESPACE" -f "$dir/k8s/github-tool-deployment.yaml" --ignore-not-found
  wait_gone "app=github-tool"
}

uninstall_agent() {
  local dir="$SCRIPT_DIR/agents/github_agent"
  log "Deleting agent manifests"
  kubectl delete -n "$NAMESPACE" -f "$dir/k8s/github-agent-deployment.yaml" --ignore-not-found
  log "Deleting agent configmaps"
  kubectl delete -n "$NAMESPACE" -f "$dir/k8s/configmaps.yaml" --ignore-not-found
  wait_gone "app.kubernetes.io/name=github-agent"
}

preflight

[ "$DO_TOOL" -eq 1 ] && uninstall_tool
[ "$DO_AGENT" -eq 1 ] && uninstall_agent

log "Done."
