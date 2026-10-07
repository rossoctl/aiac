#!/usr/bin/env bash
# opa-kind-enable.sh — k8s/opa-kind-runbook.md "Enable" (Steps 1-6), on the fly.
#
# Step 6 runs opa-kind-verify.sh, so a successful exit means the wiring was
# checked, not just applied.
#
# Wires the OPA plugin into every agent's inbound AND outbound AuthBridge
# pipeline on a Kind cluster, alongside the full parser set (a2a-parser,
# mcp-parser, inference-parser) so OPA policies have input.a2a / input.mcp /
# input.inference available on both legs, not just input.host.
#
# On the outbound leg OPA is placed AFTER token-exchange so policies can
# read input.delegation (the target audience + scopes the agent's token was
# exchanged for). See the overlay comment in Step 3 for the rationale.
#
# Does NOT modify charts/rossoctl/values.yaml on disk. The pipeline override
# lives in a throwaway temp file merged on top of the real values.yaml via a
# second `helm upgrade -f` — Helm layers -f files left-to-right, so the repo
# file is only ever read, never written. Run opa-kind-restore.sh to revert.
#
# Requires: kubectl, helm, kind, docker (or podman), python3 not needed here.
# Env vars:
#   OPERATOR_DIR        path to the rossoctl/operator repo clone; Step 1 builds
#                       the operator image from operator/Dockerfile and renders
#                       the bundle-service manifests from the clone's
#                       charts/operator/templates/bundleservice/
#                                                           (default: ../operator)
#                       NOTE: this is relative to your CWD, not to this script.
#   ROSSOCTL_DIR        path to the rossoctl/rossoctl repo clone (the chart)
#   CORTEX_DIR          path to the rossoctl/cortex repo clone; the authbridge
#                       source built in Step 2 lives there, not in this repo
#                       (default: ../cortex). The Go module root is the clone
#                       root — see AUTHBRIDGE_DIR
#   AUTHBRIDGE_DIR      the authbridge Go module root (default: $CORTEX_DIR).
#                       Override only for a clone whose module root is not the
#                       clone root
#   CLUSTER_NAME        kind cluster name                 (default: rossoctl)
#   RELEASE_NAME        helm release name                 (default: rossoctl)
#   RELEASE_NAMESPACE   namespace the chart is installed in (default: rossoctl-system)
#   AGENT_NAMESPACE     namespace to restart agent pods in (default: team1)
#   IMAGE_TAG           local tag for the authbridge proxy-sidecar image built
#                       from cmd/cortex (default: localhost/authbridge:local).
#                       The tag name stays "authbridge" because it feeds the
#                       chart's operator-chart.defaults.images.authbridge.
#   OPERATOR_IMAGE      local operator image built + loaded by Step 1. This
#                       single image carries /manager, /bundle-service and
#                       /token-broker, so there is no separate bundle-service
#                       image to build       (default: localhost/operator:local)
#   CONTAINER_RUNTIME   docker | podman                   (default: docker, auto-falls back to podman)
#   AUTHBRIDGE_PROFILE  plugin profile for the Step 2 build (default: full — the
#                       proxy-sidecar set, the only one carrying the opa plugin)
#   GO_BUILD_TAGS       explicit include_plugin_* tag list, bypassing the
#                       profile-tags helper entirely (default: derived from
#                       AUTHBRIDGE_PROFILE with a local `go`, or in a golang
#                       container when go is absent)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OPERATOR_DIR="${OPERATOR_DIR:-$(cd "$REPO_ROOT/../operator" 2>/dev/null && pwd || echo "")}"
ROSSOCTL_DIR="${ROSSOCTL_DIR:-$(cd "$REPO_ROOT/../rossoctl" 2>/dev/null && pwd || echo "")}"
# The authbridge source built in Step 2 lives in the cortex monorepo, not in
# this extracted repo — default to a sibling ../cortex clone, override with
# CORTEX_DIR.
CORTEX_DIR="${CORTEX_DIR:-$(cd "$REPO_ROOT/../cortex" 2>/dev/null && pwd || echo "")}"
# The authbridge Go module root is the cortex clone root. Both the image build
# and the profile-tags helper run against AUTHBRIDGE_DIR, and the cmd/cortex
# Dockerfile COPYs core/ and cmd/cortex/ relative to it.
#
# NOTE: an older clone may still have an untracked authbridge/ directory left
# behind (stale compiled binaries, go.work.sum, __pycache__). Its presence does
# NOT mean the module root is there.
AUTHBRIDGE_DIR="${AUTHBRIDGE_DIR:-$CORTEX_DIR}"
CLUSTER_NAME="${CLUSTER_NAME:-rossoctl}"
RELEASE_NAME="${RELEASE_NAME:-rossoctl}"
RELEASE_NAMESPACE="${RELEASE_NAMESPACE:-rossoctl-system}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-team1}"
IMAGE_TAG="${IMAGE_TAG:-localhost/authbridge:local}"

if [ -z "$OPERATOR_DIR" ] || [ ! -f "$OPERATOR_DIR/operator/Dockerfile" ] || [ ! -d "$OPERATOR_DIR/charts/operator/templates/bundleservice" ]; then
  echo "ERROR: Set OPERATOR_DIR to point to your rossoctl/operator repo clone" >&2
  echo "       (Step 1 needs \$OPERATOR_DIR/operator/Dockerfile and the bundle-service" >&2
  echo "        Helm templates in \$OPERATOR_DIR/charts/operator/templates/bundleservice/)" >&2
  echo "       OPERATOR_DIR is resolved against your current directory, not this script —" >&2
  echo "       pass an absolute path if you are not running from the repo root." >&2
  if [ -n "$OPERATOR_DIR" ] \
    && [ -f "$OPERATOR_DIR/operator/cmd/bundle-service/Dockerfile" ]; then
    echo "       (that clone predates bundle-service being folded into the operator" >&2
    echo "        image — update it, or use an older revision of this script)" >&2
  fi
  exit 1
fi
if [ -z "$ROSSOCTL_DIR" ] || [ ! -d "$ROSSOCTL_DIR" ]; then
  echo "ERROR: Set ROSSOCTL_DIR to point to your rossoctl/rossoctl repo clone" >&2
  exit 1
fi
if [ -z "$AUTHBRIDGE_DIR" ] || [ ! -f "$AUTHBRIDGE_DIR/cmd/cortex/Dockerfile" ]; then
  echo "ERROR: Set CORTEX_DIR to point to your rossoctl/cortex repo clone" >&2
  echo "       (Step 2 builds the authbridge proxy-sidecar image from" >&2
  echo "        \$CORTEX_DIR/cmd/cortex/Dockerfile, which lives in the cortex" >&2
  echo "        monorepo, not in this repo. Override AUTHBRIDGE_DIR if the Go module" >&2
  echo "        root is not the clone root)" >&2
  if [ -n "$AUTHBRIDGE_DIR" ] \
    && [ -f "$AUTHBRIDGE_DIR/authbridge/cmd/authbridge-proxy/Dockerfile" ]; then
    echo "       (that clone predates authbridge/ being flattened into the repo root" >&2
    echo "        and cmd/authbridge-proxy being renamed to cmd/cortex — update it, or" >&2
    echo "        use an older revision of this script)" >&2
  fi
  exit 1
fi
OPERATOR_IMAGE="${OPERATOR_IMAGE:-localhost/operator:local}"
AUTHBRIDGE_PROFILE="${AUTHBRIDGE_PROFILE:-full}"

# Split OPERATOR_IMAGE into the repository + tag the chart takes as two separate
# values. Only a colon AFTER the last slash is a tag separator — the registry
# host may itself carry a port (localhost:5000/operator).
case "${OPERATOR_IMAGE##*/}" in
  *:*)
    OPERATOR_IMAGE_REPO="${OPERATOR_IMAGE%:*}"
    OPERATOR_IMAGE_TAG="${OPERATOR_IMAGE##*:}"
    ;;
  *)
    OPERATOR_IMAGE_REPO="$OPERATOR_IMAGE"
    OPERATOR_IMAGE_TAG="latest"
    ;;
esac

VALUES_FILE="${ROSSOCTL_DIR}/charts/rossoctl/values.yaml"
CHART_DIR="${ROSSOCTL_DIR}/charts/rossoctl"
if [ ! -f "$VALUES_FILE" ]; then
  echo "ERROR: ${VALUES_FILE} not found — check ROSSOCTL_DIR" >&2
  exit 1
fi

if [ "${KIND_EXPERIMENTAL_PROVIDER:-}" = "podman" ]; then
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
elif ! command -v docker &> /dev/null && command -v podman &> /dev/null; then
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"
else
  CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
fi

# Track every temp file we create and remove them on exit, so an early failure
# (set -e) under any step still cleans up. Trailing-X templates only (no suffix
# after the Xs) for portability across GNU and BSD/macOS mktemp.
TMPFILES=()
cleanup() { [ "${#TMPFILES[@]}" -gt 0 ] && rm -f "${TMPFILES[@]}"; }
trap cleanup EXIT

load_image_to_kind() {
  local image_name="$1"
  if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    local tar_file
    tar_file="$(mktemp "${TMPDIR:-/tmp}/opa-kind-enable-image.XXXXXX")"
    TMPFILES+=("$tar_file")
    "$CONTAINER_RUNTIME" save "$image_name" -o "$tar_file"
    kind load image-archive "$tar_file" --name "$CLUSTER_NAME"
    rm -f "$tar_file"
  else
    kind load docker-image "$image_name" --name "$CLUSTER_NAME"
  fi
}

OVERLAY_FILE="$(mktemp "${TMPDIR:-/tmp}/opa-kind-enable-overlay.XXXXXX")"
TMPFILES+=("$OVERLAY_FILE")

echo "==> Step 1/6: deploying bundle-service from the operator clone (${OPERATOR_DIR}, image ${OPERATOR_IMAGE})"
# The bundle service is not its own image: one operator image carries
# /manager, /bundle-service and /token-broker, and the manifests live as Helm
# templates in charts/operator/templates/bundleservice/ gated on
# `bundleService.enabled`, with the binary selected per-Deployment by `command:`
# against the image's ENTRYPOINT ["/manager"].
#
# Those templates are rendered from the LOCAL clone rather than by enabling
# bundleService on the rossoctl chart's operator-chart subchart, because the
# operator chart version that subchart pins carries no bundleservice templates.
# `--set operator-chart.bundleService.enabled=true` against it would render
# nothing, silently, leaving OPA with no bundle source (Step 6's verify would
# then fail on the missing bundle-service).
#
# `helm template --show-only` rather than a second `helm install` of the clone's
# chart: templates/manager/manager.yaml and templates/rbac/role.yaml carry no
# enabled flag, so installing it as its own release would stand up a duplicate
# controller-manager and collide on the cluster-scoped operator ClusterRole.
# Rendering only the five bundleservice templates keeps the installed operator
# (from the pinned subchart) exactly as it is.
( cd "$OPERATOR_DIR/operator" \
  && "$CONTAINER_RUNTIME" build -t "$OPERATOR_IMAGE" -f Dockerfile . )
load_image_to_kind "$OPERATOR_IMAGE"
# The CRD must exist, and be established, before default-policy.yaml (an
# AuthorizationPolicy CR) is applied in the same stream below.
kubectl apply -f "$OPERATOR_DIR/operator/config/crd/bases/agent.rossoctl.dev_authorizationpolicies.yaml"
kubectl wait --for=condition=established --timeout=60s \
  crd/authorizationpolicies.agent.rossoctl.dev
# A Deployment's selector is immutable. Older raw manifests selected on
# `app: bundle-service` alone, while the chart template adds
# chart.selectorLabels (app.kubernetes.io/name + app.kubernetes.io/instance), so
# a bundle-service left behind by an older run of this script — or by a run
# under a different RELEASE_NAME — must be deleted before the rendered manifest
# can be applied. Comparing the instance label covers both cases: it is absent
# on the old raw Deployment and differs on a renamed release.
if kubectl get deployment bundle-service -n "$RELEASE_NAMESPACE" >/dev/null 2>&1 \
  && [ "$(kubectl get deployment bundle-service -n "$RELEASE_NAMESPACE" \
        -o jsonpath='{.spec.selector.matchLabels.app\.kubernetes\.io/instance}' \
        2>/dev/null)" != "$RELEASE_NAME" ]; then
  kubectl delete deployment bundle-service -n "$RELEASE_NAMESPACE" --wait=true
fi
# pullPolicy: Never so Kind runs the image just built instead of trying to pull
# it (the chart defaults to IfNotPresent, and a `:latest` tag would imply
# Always).
#
# networkpolicy.yaml is deliberately NOT rendered: it admits only pods labelled
# rossoctl.dev/authbridge=true, and nothing (operator webhook, chart, AuthBridge)
# sets that label today. On a CNI that enforces NetworkPolicy it would block
# every AuthBridge bundle fetch. Kind's default CNI does not enforce it, so the
# chart's own SECURITY note treats a kind cluster as having no access control
# either way.
helm template "$RELEASE_NAME" "$OPERATOR_DIR/charts/operator" \
  --namespace "$RELEASE_NAMESPACE" \
  --set bundleService.enabled=true \
  --set bundleService.container.image.repository="$OPERATOR_IMAGE_REPO" \
  --set bundleService.container.image.tag="$OPERATOR_IMAGE_TAG" \
  --set bundleService.container.image.pullPolicy=Never \
  --show-only templates/bundleservice/serviceaccount.yaml \
  --show-only templates/bundleservice/rbac.yaml \
  --show-only templates/bundleservice/service.yaml \
  --show-only templates/bundleservice/deployment.yaml \
  --show-only templates/bundleservice/default-policy.yaml \
  | kubectl apply -f -
kubectl rollout status deployment/bundle-service -n "$RELEASE_NAMESPACE" --timeout=180s
kubectl get pods -n "$RELEASE_NAMESPACE" -l app=bundle-service

echo "==> Step 2/6: building + loading the authbridge proxy-sidecar — cortex (${IMAGE_TAG}) via ${CONTAINER_RUNTIME}"
# AuthBridge plugins are opt-in build tags: an untagged build registers none and
# the Dockerfile refuses it. Use the "full" profile, as the cortex CI does for
# the authbridge image (scripts/profile-tags); AUTHBRIDGE_PROFILE overrides it.
# GOWORK=off: the profile tool is a
# standalone module, and the cortex go.work would want to write go.work.sum.
if [ -z "${GO_BUILD_TAGS:-}" ]; then
  if command -v go &> /dev/null; then
    GO_BUILD_TAGS="$(GOWORK=off go -C "$AUTHBRIDGE_DIR/scripts/profile-tags" run . "$AUTHBRIDGE_PROFILE")"
  else
    GO_BUILD_TAGS="$("$CONTAINER_RUNTIME" run --rm -e GOWORK=off -v "$AUTHBRIDGE_DIR:/src:ro" -w /src \
      docker.io/library/golang:1.26-alpine go -C scripts/profile-tags run . "$AUTHBRIDGE_PROFILE")"
  fi
fi
echo "    GO_BUILD_TAGS=${GO_BUILD_TAGS}"
( cd "$AUTHBRIDGE_DIR" && "$CONTAINER_RUNTIME" build -t "$IMAGE_TAG" -f cmd/cortex/Dockerfile \
    --build-arg GO_BUILD_TAGS="$GO_BUILD_TAGS" . )
load_image_to_kind "$IMAGE_TAG"

echo "==> Step 3/6: writing throwaway pipeline overlay (${VALUES_FILE} stays untouched)"
cat > "$OVERLAY_FILE" <<YAML
# Throwaway overlay — merged on top of the real values.yaml at helm-upgrade
# time, never written back to it. Adds OPA plus the full parser set
# (a2a-parser, mcp-parser, inference-parser) to both pipeline legs:
#   - Parsers run before jwt-validation/opa so their signals (input.a2a,
#     input.mcp, input.inference) are always populated, even if a later
#     gate denies the request.
#   - opa runs after jwt-validation on inbound so input.identity is set.
#   - On OUTBOUND, opa runs AFTER token-exchange so the delegation signal
#     is populated: token-exchange records the target audience + granted
#     scopes it minted a token for (RFC 8693) into the delegation chain,
#     and OPA exposes it as input.delegation (origin, actor, depth, and a
#     chain of {subject_id, audience, scopes, strategy, from_cache}). This
#     lets outbound policy reason about WHAT the agent's token was
#     exchanged for without re-parsing the minted token and without a fail-closed JWT
#     gate that would reject passthrough egress.
#     token-exchange ALSO synthesizes input.identity on this leg, even though
#     no JWT is validated here: a matched route yields
#     identity.{subject, client_id, service_id, scopes}, where service_id is
#     the route's target_audience and subject is the delegating end user, so
#     outbound policy can key on input.identity the same way as inbound. A
#     host with NO matching route gets no exchange and therefore no identity,
#     so gates keyed on it go undefined and the policy's default applies.
#     input.delegation carries the complementary per-hop audit trail.
#   - token-exchange uses the chart's default shape (client-secret identity
#     from /shared, passthrough default policy). Per-destination routes
#     come from the authproxy-routes ConfigMap; hosts with no route fall
#     through unchanged and simply carry no delegation hop.
# NOTE: the rossoctl chart reads the pipeline from \`.Values.authBridge.pipeline\`
# (a multiline string rendered via tpl() into the namespace
# authbridge-runtime-config ConfigMap — see charts/rossoctl/templates/
# _helpers.tpl "rossoctl.authbridge-runtime-config-yaml"). The operator webhook
# then uses that ConfigMap's \`pipeline:\` verbatim as the base for each per-agent
# authbridge-config-<agent> ConfigMap. So the override MUST be nested under
# \`authBridge.pipeline\` — a top-level \`pipeline:\` key is silently ignored.
authBridge:
  pipeline: |
    inbound:
      plugins:
        - name: a2a-parser
        - name: mcp-parser
        - name: inference-parser
        - name: jwt-validation
          config:
            issuer: "http://keycloak.localtest.me:8080/realms/rossoctl"
            keycloak_url: "http://keycloak-service.keycloak.svc:8080"
            keycloak_realm: "rossoctl"
        - name: opa
          config:
            bundle_url: "http://bundle-service.${RELEASE_NAMESPACE}.svc.cluster.local:8080"
    outbound:
      plugins:
        - name: a2a-parser
        - name: mcp-parser
        - name: inference-parser
        - name: token-exchange
          config:
            keycloak_url: "http://keycloak-service.keycloak.svc:8080"
            keycloak_realm: "rossoctl"
            default_policy: "passthrough"
            identity:
              type: "client-secret"
        - name: opa
          config:
            bundle_url: "http://bundle-service.${RELEASE_NAMESPACE}.svc.cluster.local:8080"
YAML

echo "==> Step 4/6: helm upgrade (base values.yaml + overlay — base file not modified)"
( cd "$CHART_DIR" && helm dependency build )
helm upgrade "$RELEASE_NAME" "$CHART_DIR" -n "$RELEASE_NAMESPACE" \
  -f "$VALUES_FILE" \
  -f "$OVERLAY_FILE" \
  --set openshift=false \
  --set featureFlags.agentSandbox=true \
  --set operator-chart.defaults.images.authbridge="$IMAGE_TAG" \
  --set operator-chart.featureGates.injectTools=true \
  --wait --timeout 5m

echo "==> Step 5/6: restarting authbridge pods in ${AGENT_NAMESPACE}"
# --ignore-not-found so this no-ops cleanly when the namespace has no agent pods yet.
kubectl delete pods -n "$AGENT_NAMESPACE" -l rossoctl.io/type=agent --ignore-not-found

echo "==> Step 6/6: verifying (opa-kind-verify.sh)"
NS="$AGENT_NAMESPACE" SYS_NS="$RELEASE_NAMESPACE" IMAGE_TAG="$IMAGE_TAG" KIND_CLUSTER="$CLUSTER_NAME" \
  "$SCRIPT_DIR/opa-kind-verify.sh"

cat <<EOF
==> Done.

Re-check later with:
  ./k8s/opa-kind-verify.sh
Restore the original pipeline with:
  ./k8s/opa-kind-restore.sh
EOF
