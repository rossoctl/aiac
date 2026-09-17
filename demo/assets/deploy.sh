#!/usr/bin/env bash
# Deploy the demo/assets workloads (github-tool, github-agent) into a rossoctl/Kind cluster:
# `kubectl apply` the manifests (in order) + `kubectl rollout status`. This is the *deploy* half
# of the old install.sh — it applies only; it does NOT build or load images. Run `kind-load.sh`
# first so the images (localhost/github-*:latest, imagePullPolicy: IfNotPresent) are present in
# the Kind node; a missing image surfaces as ImagePullBackOff and `rollout status` fails loudly.
# See INSTALL.md for the manual steps this automates and the non-obvious invariants.
#
# This script does NOT wait for Keycloak client registration — that needs Keycloak credentials
# this script has no business holding. It belongs to whatever use-case demo consumes the client
# (e.g. the UC-1 onboarding demo's prereqs). Do not "fix" that omission here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-rossoctl}"
NAMESPACE="${NAMESPACE:-team1}"

DO_TOOL=1
DO_AGENT=1

for arg in "$@"; do
  case "$arg" in
    --agent-only) DO_TOOL=0 ;;
    --tool-only) DO_AGENT=0 ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--agent-only|--tool-only]" >&2
      exit 1
      ;;
  esac
done

log() { echo "[deploy.sh] $*" >&2; }

preflight() {
  # Apply only — needs kubectl, a reachable cluster, the target namespace, and the AgentRuntime CRD.
  # Deliberately NO runtime/kind checks and no build/load: kind-load.sh owns the images precondition.
  if ! command -v kubectl >/dev/null 2>&1; then
    log "ERROR: required binary 'kubectl' not found on PATH."
    exit 1
  fi

  if ! kubectl cluster-info >/dev/null 2>&1; then
    log "ERROR: kubectl cannot reach a cluster. Is your kubeconfig pointing at '$CLUSTER_NAME'?"
    exit 1
  fi

  if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    log "ERROR: namespace '$NAMESPACE' does not exist."
    log "This script does not create cluster-owned resources — run the Rossoctl installer first."
    exit 1
  fi

  if ! kubectl get crd agentruntimes.agent.rossoctl.dev >/dev/null 2>&1; then
    log "ERROR: AgentRuntime CRD not found. Is the rossoctl-operator installed?"
    exit 1
  fi
}

deploy_tool() {
  local dir="$SCRIPT_DIR/tools/github_tool"
  log "Applying tool manifests"
  kubectl apply -n "$NAMESPACE" -f "$dir/k8s/github-tool-deployment.yaml"
  kubectl rollout status -n "$NAMESPACE" deployment/github-tool
}

deploy_agent() {
  local dir="$SCRIPT_DIR/agents/github_agent"
  log "Applying agent configmaps"
  kubectl apply -n "$NAMESPACE" -f "$dir/k8s/configmaps.yaml"
  log "Applying agent manifests"
  kubectl apply -n "$NAMESPACE" -f "$dir/k8s/github-agent-deployment.yaml"
  kubectl rollout status -n "$NAMESPACE" deployment/github-agent
}

preflight

[ "$DO_TOOL" -eq 1 ] && deploy_tool
[ "$DO_AGENT" -eq 1 ] && deploy_agent

log "Done."
