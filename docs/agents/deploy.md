# Deploy parameters

Names the deploy-time parameters of this repo for the `deploy` skill. The deploy
flow is in `k8s/aiac-deployment-guide.md`. The commands for each parameter are in
the linked doc — this file copies none of them.

## `ac-side` — access-control scheme (enforcement side)

| | |
|---|---|
| Alias | `enforcement-side` |
| Values | `agent-side` (inbound **and** outbound Rego rules), `target-side` (inbound Rego rules only). Mutually exclusive. |
| Short forms | `agent`, `target` — only in `ac-side=<short>`, never as a bare word |
| Default | `target-side` |
| Setting | `AIAC_ENFORCEMENT_SIDE` in the `aiac-agent-config` ConfigMap, namespace `aiac-system` |
| Read, apply, verify | `k8s/opa-kind-runbook.md` → Switch the enforcement side |

Usage: `/deploy ac-side=agent`, `/deploy agent-side`.

- **Trap:** `kubectl apply -f k8s/agent-deployment.yaml` writes `target-side`
  back. Apply the parameter after that apply.
- **Precondition:** the AIAC global combiner must exist (`k8s/opa-kind-enable.sh`
  applies it), or the Controller does not start.
