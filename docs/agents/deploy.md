# Deploy parameters

Names the deploy-time parameters of this repo for the `deploy` skill. The deploy
flow and its platform preconditions (OPA on the Kind platform, the Keycloak
event-listener SPI) are in `k8s/aiac-deployment-guide.md` → Platform
preconditions. Check them before every deploy, also a parameter-only deploy. The
commands for each parameter are in the linked doc — this file copies none of
them.

## `ac-side` — access-control scheme (enforcement side)

| | |
|---|---|
| Alias | `enforcement-side` |
| Values | `agent-side` (inbound **and** outbound Rego rules), `target-side` (inbound Rego rules only). Mutually exclusive. |
| Short forms | `agent`, `target` — only in `ac-side=<short>`, never as a bare word |
| Default | `target-side` |
| Setting | `AIAC_ENFORCEMENT_SIDE` in the `aiac-agent-config` ConfigMap, namespace `aiac-system` |
| Read, apply, verify | `k8s/opa-kind-runbook.md` → Set the enforcement side |

Usage: `/deploy ac-side=agent`, `/deploy agent-side`.

- **A change is a clean redeploy.** A live switch is not supported. To change
  the value, run the clean redeploy of the runbook section: it deletes every
  AIAC CR and the `aiac-system` namespace (with the Policy Model Store), deploys
  AIAC again and sets the side. Never patch the value on a running AIAC and
  restart the Controller.
- **Trap:** `kubectl apply -f k8s/agent-deployment.yaml` writes `target-side`
  back. On an `agent-side` deployment, after that apply, patch the live value
  back into the ConfigMap **before** the Controller restarts (this puts back
  the same value, and runbook step 5 sets it on an empty store; neither is a
  side change). Else the restart starts the Controller under the other side.
