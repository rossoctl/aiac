#!/usr/bin/env bash
# Build the demo/assets workload images (github-tool, github-agent) and load them into a
# rossoctl/Kind cluster. This is the *images precondition* half of the old install.sh — it
# builds + `kind load`s only; it applies NO manifests. Run `deploy.sh` afterwards to deploy.
# See INSTALL.md for the manual steps this automates and the non-obvious invariants.
#
# Split rationale: the UC-1 onboarding system tests deploy the workloads themselves (deploying
# is the event-driven onboarding trigger) and now run THIS script first to load the images they
# will deploy (test/system/uc1_onboard.py: load_workload_images -> kind-load.sh, build-if-absent).
# This script produces exactly that images precondition; `deploy.sh` mirrors the apply/rollout half.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-rossoctl}"
# Tags must carry the localhost/ prefix to match the Deployment manifests' image refs
# (image: localhost/github-*:latest, imagePullPolicy: IfNotPresent). docker does not auto-prefix
# built tags, so a bare github-*:latest would load into the kind node under a different repository
# name and the IfNotPresent pods would try to pull localhost/github-*:latest → ImagePullBackOff.
TOOL_IMAGE="${TOOL_IMAGE:-localhost/github-tool:latest}"
AGENT_IMAGE="${AGENT_IMAGE:-localhost/github-agent:latest}"

DO_TOOL=1
DO_AGENT=1
REBUILD=0

for arg in "$@"; do
  case "$arg" in
    --agent-only) DO_TOOL=0 ;;
    --tool-only) DO_AGENT=0 ;;
    --rebuild) REBUILD=1 ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--agent-only|--tool-only] [--rebuild]" >&2
      exit 1
      ;;
  esac
done

log() { echo "[kind-load.sh] $*" >&2; }

detect_runtime() {
  if command -v podman >/dev/null 2>&1; then
    echo podman
  elif command -v docker >/dev/null 2>&1; then
    echo docker
  else
    log "ERROR: neither podman nor docker found on PATH."
    exit 1
  fi
}

RUNTIME="${CONTAINER_RUNTIME:-$(detect_runtime)}"

preflight() {
  # Build/load only — needs the container runtime, kind, and the target Kind cluster to load into.
  # Deliberately NO namespace/CRD checks: nothing is applied here (that is deploy.sh's job).
  local missing=0
  for bin in kubectl kind "$RUNTIME"; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      log "ERROR: required binary '$bin' not found on PATH."
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1

  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "ERROR: Kind cluster '$CLUSTER_NAME' not found (kind get clusters). There is nowhere to load into."
    log "Create the cluster first (the Rossoctl installer owns it), or set CLUSTER_NAME."
    exit 1
  fi
}

image_exists() {
  "$RUNTIME" image exists "$1" >/dev/null 2>&1 || "$RUNTIME" image inspect "$1" >/dev/null 2>&1
}

load_image_to_kind() {
  local image="$1"
  # `kind load docker-image` shells out to the docker binary and does not work with podman;
  # for podman, save to an archive and use `kind load image-archive` instead.
  if [ "$RUNTIME" = "podman" ]; then
    local tar_file
    tar_file="$(mktemp "${TMPDIR:-/tmp}/kind-load-image.XXXXXX")"
    "$RUNTIME" save "$image" -o "$tar_file"
    kind load image-archive "$tar_file" --name "$CLUSTER_NAME"
    rm -f "$tar_file"
  else
    kind load docker-image "$image" --name "$CLUSTER_NAME"
  fi
}

build_and_load() {
  local image="$1" context="$2"
  if [ "$REBUILD" -eq 0 ] && image_exists "$image"; then
    log "Image '$image' already present locally, skipping build (pass --rebuild to force)."
  else
    log "Building '$image' from $context"
    "$RUNTIME" build -t "$image" "$context"
  fi
  log "Loading '$image' into kind cluster '$CLUSTER_NAME'"
  load_image_to_kind "$image"
}

load_tool() {
  build_and_load "$TOOL_IMAGE" "$SCRIPT_DIR/tools/github_tool"
}

load_agent() {
  build_and_load "$AGENT_IMAGE" "$SCRIPT_DIR/agents/github_agent"
}

preflight

[ "$DO_TOOL" -eq 1 ] && load_tool
[ "$DO_AGENT" -eq 1 ] && load_agent

log "Done. Images built + loaded into '$CLUSTER_NAME'. Run deploy.sh to apply the manifests."
