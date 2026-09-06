# UC-1 Integration Runbook — live onboarding trigger + live enforcement (Phase 2)

> Companion to [`aiac/demo/use-cases/uc1-onboarding/demo.md`](../uc1-onboarding/demo.md) (Phase 1)
> and [`aiac/k8s/opa-kind-runbook.md`](../../k8s/opa-kind-runbook.md) (the OPA-only enforcement
> proof). This runbook is the AIAC-scoped companion for
> [rossoctl/cortex#646](https://github.com/rossoctl/cortex/issues/646) — it upgrades the
> already-working UC-1 onboarding demo along the two axes #646 asks for, using exactly the same
> scenario (`github-agent`, `github-tool`, users `dev-user`/`test-user`/`devops-user`):
>
> - **Live trigger** — registering `github-agent`/`github-tool` as Keycloak clients fires an
>   admin event that reaches AIAC over NATS and triggers onboarding automatically. **No**
>   `POST /apply/service/{id}` call (i.e. no `make onboard-agent`/`make onboard-tool` from the
>   Phase 1 demo).
> - **Live enforcement** — a real HTTP request through the live AuthBridge OPA plugin decides
>   allow/deny, instead of the Phase 1 demo's offline `opa eval`.
>
> The underlying implementation for both is already merged to `main` —
> [#752](https://github.com/rossoctl/cortex/pull/752) (OPA plugin integration + live enforcement)
> and [#754](https://github.com/rossoctl/cortex/pull/754) (Event Broker + Keycloak SPI listener) —
> but per #754's own description, both the event broker and the Keycloak SPI listener are
> **opt-in and inactive by default**. This runbook is what turns them on and proves the live path
> end to end.

## Prerequisites

- Everything [`opa-kind-runbook.md`'s Prerequisites](../../k8s/opa-kind-runbook.md#prerequisites)
  lists (Kind cluster `rossoctl`, `OPERATOR_DIR`/`ROSSOCTL_DIR` sibling clones, `kubectl`/`helm`/
  `kind`/`docker`-or-`podman`, the Keycloak realm/user fix-up for `dev-user`/`alice`) — **and**
  its OPA pipeline already wired in (`./aiac/k8s/opa-kind-enable.sh`, or confirm with
  `kubectl get configmap authbridge-runtime-config -n team1 -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'`
  → expect `2`).
- The Phase 1 demo's `github-agent`/`github-tool` workloads deployed
  (`aiac/demo/assets/install.sh`, or `aiac/demo/use-cases/uc1-onboarding`'s `make prereqs`).
- `mvn` and `java` on `PATH` (to build the Keycloak SPI jar — `keycloak-spi/README.md`'s own
  build instructions; this runbook automates that build, not a manual step here).
- An OpenAI-compatible LLM endpoint + API key for the AIAC Policy Rules Builder. Defaults to
  reusing the key already in `team1/openai-secret` (see `uc1-integration-enable.sh`'s
  `OPENAI_SECRET_NS`/`OPENAI_SECRET_NAME` env vars to point elsewhere).

Run everything from the repo root (`cortex/`), same convention as the OPA runbook.

---

## Step 1 — Deploy the AIAC stack

The AIAC agent, PDP interface, and Policy Model Store aren't deployed by default. Build+load the
four images and apply the manifests (`k8s/{pdp-interface-deployment,policy-model-store-statefulset,agent-deployment}.yaml`),
wiring the LLM secret first:

```bash
OPENAI_SECRET_NS=team1 OPENAI_SECRET_NAME=openai-secret \
  ./aiac/demo/use-cases/uc1-integration/uc1-integration-enable.sh --stack-only
```

Verify:

```bash
kubectl get deployment aiac-agent aiac-interface -n aiac-system
kubectl get statefulset aiac-policy-model-store -n aiac-system
```

## Step 2 — Deploy the NATS event broker

```bash
kubectl apply -f aiac/k8s/event-broker-deployment.yaml
kubectl rollout status deployment/aiac-event-broker -n aiac-system
```

Ephemeral JetStream storage (`emptyDir`) — fine, this broker is dev/opt-in per its own manifest
comments. The Keycloak SPI's default `NATS_URL` fallback
(`nats://aiac-event-broker-service:4222`) already matches this Service's name/port, so no env
var needs setting on either side.

## Step 3 — Build and install the Keycloak SPI listener

```bash
./aiac/demo/use-cases/uc1-integration/uc1-integration-enable.sh --spi-only
```

This: builds the shaded jar (`cd aiac/keycloak-spi && mvn package`), builds a small derived
Keycloak image (`FROM quay.io/keycloak/keycloak:26.5.2` + the jar dropped into
`/opt/keycloak/providers/` + `kc.sh build` — the same 3-stage pattern as
`keycloak-spi/Dockerfile`), `kind load`s it, and `kubectl set image`s the live `keycloak`
StatefulSet to point at it (a live, reversible patch — **not** a chart edit; a future
`helm upgrade` of the `rossoctl` release would revert it, same non-destructive spirit as
`opa-kind-enable.sh`'s pipeline overlay). Then it enables the listener on the `rossoctl` realm's
admin-events config via the Admin REST API.

Verify the provider loaded:

```bash
kubectl logs statefulset/keycloak -n keycloak | grep -i "aiac-event-listener\|providers changed"
```

> Running both Step 1-3 together: `./uc1-integration-enable.sh` with no flags does all of it.

## Step 4 — `make init` the Phase 1 demo harness

From `aiac/demo/use-cases/uc1-onboarding/`:

```bash
make keycloak && make prereqs && make clear && make setup
```

`make prereqs` will find `github-agent`/`github-tool` and the AIAC stack already deployed (Steps
1-3 above) and just verify + wait for Keycloak client registration. `make clear` resets any
leftover `AuthorizationPolicy` CR so what follows is a clean before/after. `make setup`
provisions `dev-user`/`test-user`/`devops-user`, mounts `policy.md`, and configures the Phase 1
demo's own direct RFC 8693 token-exchange proof (a **different** exchange path than AuthBridge's
own outbound leg — see Step 6).

## Step 5 — Force a fresh live trigger

`github-agent`/`github-tool` are **already** registered Keycloak clients from Step 4 (or an
earlier session) — their `CLIENT_CREATE` admin event fired **before** the listener existed in
Step 3, so leaving them alone proves nothing. The operator's `ClientRegistrationReconciler`
(`operator/internal/controller/clientregistration_controller.go`) calls
`RegisterOrFetchClientWithToken` unconditionally on every reconcile — it does not skip based on
an already-existing credentials Secret — so deleting the Keycloak client and forcing a reconcile
(a pod restart touches the Deployment's pod template, which the reconciler watches) reliably
produces a fresh `CLIENT_CREATE`.

```bash
./aiac/demo/use-cases/uc1-integration/uc1-integration-driver.sh --only-trigger
```

This: records the current Keycloak client UUIDs for `team1/github-agent` and `team1/github-tool`,
deletes both clients via the Admin API, deletes both pods, and polls until the operator
re-registers **new** client UUIDs. Then it polls `aiac-agent`'s logs for evidence it consumed
`aiac.apply.service.<new-uuid>` events for both workloads — **with no `make onboard-agent`/
`make onboard-tool` call** — and confirms the `github-agent` `AuthorizationPolicy` CR was
freshly (re)written (new `resourceVersion`, matching content).

## Step 6 — Wire the AuthBridge outbound leg

AIAC's own onboarding does **not** configure `authproxy-routes` or grant the tool's audience as
an *optional* client-scope on `github-agent`'s client — that's what makes AuthBridge's own
`client_credentials`-based token exchange work on the outbound leg, and it's a separate concern
from Step 4's `standard.token.exchange.enabled` + *default*-scope setup (which only proves RFC
8693 directly against Keycloak, the way the Phase 1 demo's `run-*.py` scripts do it — not through
AuthBridge). Same two sub-steps as `opa-kind-runbook.md` Part B.1/B.2:

```bash
./aiac/demo/use-cases/uc1-integration/uc1-integration-driver.sh --only-wire-outbound
```

## Step 7 — Live-enforce: reproduce the acceptance table

```bash
./aiac/demo/use-cases/uc1-integration/uc1-integration-driver.sh --only-enforce
```

Real HTTP probes, real decision logs — matching #646's acceptance table:

| Request | Inbound | Outbound (via the agent) |
|---|---|---|
| `dev-user` → `github-agent` | ✅ allowed | `source-read`, `source-write`, `issues-read` allowed; `issues-write` denied |
| `test-user` → `github-agent` | ✅ allowed | `issues-read`, `issues-write` allowed; `source-read`/`source-write` denied |
| `devops-user` → `github-agent` | ❌ denied (403) | never reached |

> **Known gap — "direct user → tool" is not enforced in this deployment.** The issue's table also
> lists a fourth row: `dev-user` calling `github-tool` **directly** (bypassing the agent) should be
> denied. The `github-tool` workload used here (`aiac/demo/assets/tools/github_tool/server.py`) is
> a bare FastMCP stub with **no authentication of its own** — no AuthBridge sidecar (deliberately;
> see `demo/assets/INSTALL.md`'s "do not add sidecars to this tool" invariant), no JWT/audience
> check in its own code. A direct in-cluster call to `github-tool.team1.svc.cluster.local:9090`
> succeeds unconditionally today. Enforcing that row would need either an inbound AuthBridge+OPA
> leg on the tool itself, or the tool doing its own audience check (both out of scope for the
> Phase 1 `github_tool` stub) — this runbook demonstrates the other three rows and calls this one
> out rather than fabricating a result.

## Step 8 — Report

```bash
./aiac/demo/use-cases/uc1-integration/uc1-integration-driver.sh
```

With no flags, the driver runs Steps 5-7 end to end and prints a final summary: the live-trigger
evidence (consumer log lines + the fresh CR, with no manual onboarding call in between) and the
live-enforcement decision logs for every row of the table above.

---

## Cleanup

```bash
./aiac/demo/use-cases/uc1-integration/uc1-integration-restore.sh
```

Reverts, in reverse order: the outbound-leg wiring (Step 6), the forced-fresh `github-agent`
`AuthorizationPolicy` CR (Step 5, so a re-run starts clean), the Keycloak realm's admin-events
listener config (Step 3), and the Keycloak StatefulSet's image (Step 3 — back to the stock
`quay.io/keycloak/keycloak:26.5.2`). It does **not** tear down the AIAC stack or the NATS broker
(additive infra, same principle as `opa-kind-restore.sh` leaving `bundle-service` deployed) —
delete the `aiac-system` namespace by hand if you want a fully clean slate.

## Troubleshooting

- **Step 5 never sees a new client UUID.** The reconciler is triggered by a *watch* on the
  Deployment/pod-template, not a periodic resync — if a bare pod restart doesn't trigger it,
  restart the operator itself (`kubectl rollout restart deployment/rossoctl-controller-manager -n
  rossoctl-system`), which re-lists every `AgentRuntime` on startup.
- **`aiac-agent` never logs the consumed event.** Check the listener actually attached
  (`kubectl logs statefulset/keycloak -n keycloak | grep -i aiac-event-listener`) and that the
  realm's admin-events config still lists it (`GET .../admin/realms/rossoctl/events/config` —
  a `helm upgrade`/Keycloak restart between Step 3 and here would need Step 3 re-run).
- **Outbound probe returns `ALLOWED_RESULT` when it should deny (or vice versa).** Same bundle-poll
  timing caveat as `opa-kind-runbook.md` — the OPA SDK's bundle poller can take up to ~120s after
  a fresh CR write; the driver's probes retry with the same window `opa-kind-driver.sh` uses
  (`POLL_SECS`, default 150s).
