# Deploy parameters

Names the deploy-time parameters of this repo for the `deploy` skill. The deploy
flow and its platform preconditions (OPA on the Kind platform, the Keycloak
event-listener SPI) are in `k8s/aiac-deployment-guide.md` → Platform
preconditions. Check them before every deploy. The commands are in the linked
docs — this file copies none of them.

This repo has no deploy-time parameter.

## Preconditions

- **Precondition:** the AIAC global combiner must exist (`k8s/opa-kind-enable.sh`
  applies it), or the Controller does not start.
- **Precondition:** each tool pod needs the AuthBridge sidecar
  (`injectTools=true`), and the namespace inbound pipeline needs
  `jwt-validation`, `mcp-parser` and `opa` (`k8s/opa-kind-enable.sh` sets both),
  or the onboarding of the tool fails with `409` (check #1 or #2, D30).
