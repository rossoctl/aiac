# Deploy parameters and preconditions

Names the deploy-time parameters and preconditions of this repo for the `deploy`
skill. The deploy flow is in `k8s/aiac-deployment-guide.md`. The commands for each
parameter are in the linked doc — this file copies none of them.

## Precondition: OPA on the Kind platform

AIAC needs OPA in the AuthBridge pipeline, `bundle-service`, and the changed
global combiner (D20). Without them the AIAC Controller does not start.

| | |
|---|---|
| Applies to | Every deploy of an AIAC unit in `aiac-system`, and a parameter-only deploy |
| Check | `./k8s/opa-kind-verify.sh` (read-only, exits non-zero on the first failed check) |
| Install | `OPERATOR_DIR=… ROSSOCTL_DIR=… CORTEX_DIR=… ./k8s/opa-kind-enable.sh`, from the repo root. Details: `k8s/opa-kind-runbook.md` → Enable |
| Install warning | Two image builds (a few minutes). It runs `helm upgrade` on the rossoctl chart and restarts the agent and tool pods in `team1`. |
| Inputs | Sibling clones `operator`, `rossoctl`, `cortex`. Defaults are `../operator`, `../rossoctl`, `../cortex`, relative to the repo root. If one is missing, stop and ask for its path. |
| Re-check | After any `kubectl apply` of a platform manifest or an operator-chart upgrade. The check also fails when the stock combiner is back. |

Enable runs the verify script as its last step, so after an install the check
has already passed once.

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
- **Precondition:** the AIAC global combiner must exist (`k8s/opa-kind-enable.sh`
  applies it), or the Controller does not start.
