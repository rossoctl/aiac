# UC-1 E2E Runbook — deploying the agent IS the live trigger

> Companion to [`aiac/demo/use-cases/uc1-onboarding/demo.md`](../uc1-onboarding/demo.md) (Phase 1)
> and [`aiac/demo/use-cases/uc1-integration/uc1-integration-runbook.md`](../uc1-integration/uc1-integration-runbook.md)
> (Phase 2). This is a separate, self-contained demo for
> [rossoctl/cortex#646](https://github.com/rossoctl/cortex/issues/646)'s "live trigger" claim —
> `uc1-integration`'s files are untouched by this one.
>
> **The difference from `uc1-integration`:** that demo proves the live-trigger path by *deleting*
> the already-registered `team1/github-agent`/`team1/github-tool` Keycloak clients via the Admin
> REST API and restarting the pods so the operator re-creates them — a forced replay against
> workloads that were already onboarded. This demo proves the same path with a **genuine new-agent
> onboarding**: `github-agent`/`github-tool` are deployed for the very first time, and that single
> `kubectl apply` (via the existing, unmodified `demo/assets/install.sh`) is the entire trigger.
> No curl-based client deletion, no cloned agent, no manual `POST /apply/service/{id}` call
> anywhere in this demo.
>
> **Why deploying is the real trigger:** the operator's `AgentRuntimeReconciler` stamps
> `rossoctl.io/type=agent|tool` onto a Deployment's pod-template labels the first time its
> `AgentRuntime` CR resolves. That label is exactly what the `ClientRegistrationReconciler`'s watch
> predicate keys on, and *that* is what fires `RegisterOrFetchClientWithToken` — a genuine Keycloak
> `CLIENT_CREATE` admin event. So the first-ever apply of the workload + its `AgentRuntime` CR (both
> already checked into `demo/assets/`) already is the trigger; nothing else needs to create it.

## Prerequisites

- Everything [`opa-kind-runbook.md`'s Prerequisites](../../k8s/opa-kind-runbook.md#prerequisites)
  lists (Kind cluster `rossoctl`, `OPERATOR_DIR`/`ROSSOCTL_DIR` sibling clones, `kubectl`/`helm`/
  `kind`/`docker`-or-`podman`, the Keycloak realm/user fix-up for `dev-user`/`alice`) — **and**
  its OPA pipeline already wired in (`./aiac/k8s/opa-kind-enable.sh`, or confirm with
  `kubectl get configmap authbridge-runtime-config -n team1 -o jsonpath='{.data.config\.yaml}' | grep -c 'name: opa'`
  → expect `2`).
- `github-agent`/`github-tool` **NOT** already deployed in `team1` — this demo's whole point is
  proving a first-time deploy triggers onboarding, so it needs a clean slate. If you've already run
  `uc1-onboarding` or `uc1-integration` in this cluster, run `./uc1-e2e-restore.sh` first (it tears
  down the workloads and their Keycloak clients; see Cleanup below).
- `mvn` and `java` on `PATH` (to build the Keycloak SPI jar — `keycloak-spi/README.md`'s own build
  instructions; `uc1-e2e-enable.sh` automates the build).
- An OpenAI-compatible LLM endpoint + API key for the AIAC Policy Rules Builder. Defaults to
  reusing the key already in `team1/openai-secret` (see `uc1-e2e-enable.sh`'s
  `OPENAI_SECRET_NS`/`OPENAI_SECRET_NAME` env vars to point elsewhere).

Run everything from the repo root (`cortex/`), same convention as the other runbooks in this
family.

---

## Step 1 — Turn on the opt-in infra (AIAC stack, NATS broker, Keycloak SPI)

```bash
OPENAI_SECRET_NS=team1 OPENAI_SECRET_NAME=openai-secret \
  ./aiac/demo/use-cases/uc1-e2e/uc1-e2e-enable.sh
```

This deploys the AIAC agent/PDP-interface/Policy-Model-Store, the NATS event broker, and builds +
installs the Keycloak SPI jar into a derived Keycloak image (same 3-stage pattern as
`keycloak-spi/Dockerfile`: `FROM quay.io/keycloak/keycloak:26.5.2` + the jar dropped into
`/opt/keycloak/providers/` + `kc.sh build`), then enables the listener on the realm. It
deliberately does **not** deploy `github-agent`/`github-tool` — those stay undeployed so the next
step is a genuine first-time trigger.

Verify:

```bash
kubectl get deployment aiac-agent aiac-interface -n aiac-system
kubectl get deployment aiac-event-broker -n aiac-system
kubectl logs statefulset/keycloak -n keycloak | grep -i "aiac-event-listener\|providers changed"
```

## Step 2 — Deploy, verify the live trigger, wire outbound, enforce

```bash
./aiac/demo/use-cases/uc1-e2e/uc1-e2e-driver.sh
```

With no flags this runs, in order:

1. **DEPLOY** — runs `demo/assets/install.sh` to build+load the images and `kubectl apply`
   `github-agent`/`github-tool`'s manifests (ServiceAccount + Deployment + Service + `AgentRuntime`
   each) for the first time. **This is the trigger** — nothing else in this script creates a
   Keycloak client.
2. **VERIFY-TRIGGER** — polls Keycloak until `team1/github-agent`/`team1/github-tool` appear (first
   registration ever, no before/after diffing needed), polls `aiac-agent`'s logs for evidence it
   consumed `aiac.apply.service.<uuid>` for both over NATS, and polls for the fresh
   `authorizationpolicies.agent.rossoctl.dev/github-agent` CR AIAC writes in response — printing its
   content.
3. **WIRE** — wires AuthBridge's own outbound leg (`authproxy-routes` + the optional client-scope
   grant on `github-agent`) — same two sub-steps as `opa-kind-runbook.md` Part B.1/B.2; AIAC's own
   onboarding does not configure this.
4. **ENFORCE** — real HTTP probes through the live AuthBridge OPA plugin, reproducing #646's
   acceptance table:

| Request | Inbound | Outbound (via the agent) |
|---|---|---|
| `dev-user` → `github-agent` | ✅ allowed | `source-read`, `source-write`, `issues-read` allowed; `issues-write` denied |
| `test-user` → `github-agent` | ✅ allowed | `issues-read`, `issues-write` allowed; `source-read`/`source-write` denied |
| `devops-user` → `github-agent` | ❌ denied (403) | never reached |

Individual phases can be re-run on their own:

```bash
./aiac/demo/use-cases/uc1-e2e/uc1-e2e-driver.sh --only-deploy
./aiac/demo/use-cases/uc1-e2e/uc1-e2e-driver.sh --only-wire-outbound
./aiac/demo/use-cases/uc1-e2e/uc1-e2e-driver.sh --only-enforce
```

> **Known gap — "direct user → tool" is not enforced in this deployment.** Same gap as
> `uc1-integration`: #646's acceptance table also lists `dev-user` calling `github-tool`
> **directly** (bypassing the agent), which should be denied. `github-tool`
> (`aiac/demo/assets/tools/github_tool/server.py`) is a bare FastMCP stub with no auth of its own
> (deliberately — see `demo/assets/INSTALL.md`'s "do not add sidecars to this tool" invariant). A
> direct in-cluster call succeeds unconditionally today; this runbook demonstrates the other three
> acceptance-table rows and calls this one out rather than fabricating a result.

---

## Cleanup

```bash
./aiac/demo/use-cases/uc1-e2e/uc1-e2e-restore.sh
```

Unlike `uc1-integration-restore.sh` (which leaves `github-agent`/`github-tool` running so a later
re-run of that demo's curl-based forced trigger has something to act on), this restore removes
`github-agent`/`github-tool` **completely** — Deployments, Services, ServiceAccounts, `AgentRuntime`
CRs, their Keycloak clients, credentials Secrets, and the `AuthorizationPolicy` CR AIAC wrote — so
that a later `./uc1-e2e-driver.sh` run's DEPLOY phase is a genuine first-time trigger again, not a
no-op. It also reverts the outbound-leg wiring (Step 2.3 above).

It does **not** tear down the AIAC stack, the NATS broker, or the Keycloak SPI listener (additive
infra, same principle as every other `*-restore.sh` in this demo family) — delete the
`aiac-system` namespace by hand if you want a fully clean slate:

```bash
kubectl delete namespace aiac-system
```

## Troubleshooting

- **`uc1-e2e-driver.sh` refuses to run DEPLOY, saying github-agent/github-tool already exist.**
  That guard exists specifically so this demo never silently degrades into `uc1-integration`'s
  forced-replay shape. Run `./uc1-e2e-restore.sh` first, then re-run the driver.
- **Keycloak never registers the new clients.** Check the operator actually reconciled the
  `AgentRuntime` CRs: `kubectl logs deployment/rossoctl-controller-manager -n rossoctl-system`, and
  confirm the pod-template picked up `rossoctl.io/type=agent`/`tool`:
  `kubectl get deployment github-agent -n team1 -o jsonpath='{.spec.template.metadata.labels}'`.
- **`aiac-agent` never logs the consumed event.** Check the SPI provider actually attached
  (`kubectl logs statefulset/keycloak -n keycloak | grep -i aiac-event-listener`) and that the
  realm's admin-events config still lists it (`GET .../admin/realms/rossoctl/events/config` — a
  `helm upgrade`/Keycloak restart between Step 1 and here would need Step 1's `--spi-only`
  re-run).
- **Outbound probe returns `ALLOWED_RESULT` when it should deny (or vice versa).** Same bundle-poll
  timing caveat as `opa-kind-runbook.md` — the OPA SDK's bundle poller can take up to ~120s after a
  fresh CR write; the driver's probes retry with the same window `opa-kind-driver.sh` uses
  (`POLL_SECS`, default 150s).
