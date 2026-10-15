# AIAC — AI-based Access Control

AIAC is a Rossoctl platform extension that automates access control policy enforcement for AI agents
running on Kubernetes. It continuously translates natural-language access-control policy into
concrete permission rules on the active Policy Decision Point (OPA), using an identity provider
(currently Keycloak) for roles, scopes, and services.

## Architecture

![AIAC Architecture image](docs/presentations/aiac-architecture.drawio.png)

Source: [docs/presentations/aiac-architecture.drawio](docs/presentations/aiac-architecture.drawio)
(open it in [draw.io](https://app.diagrams.net/)).

AIAC enforces a strict three-layer model:

| Layer | Component | Role |
|---|---|---|
| **Policy Management** | AIAC Agent | Translates natural-language policy into PDP configuration on every trigger |
| **Policy Decision (PDP)** | OPA | Evaluates LLM-generated Rego rules; decides what a caller may access |
| **Policy Enforcement (PEP)** | AuthBridge | Intercepts traffic; exchanges tokens; carries no policy knowledge |

The AIAC Agent subscribes to an event stream (NATS JetStream) and reacts to entity lifecycle
events — new services, role changes, policy updates — by consulting a Policy Rules Builder
(LangGraph, LLM-backed) and applying the minimal resulting diff through a two-layer policy stack
(policy model + Policy Computation Engine). Policy intent lives entirely in the PDP, never in
per-pod configuration.

Each trigger maps to a use case under `src/aiac/agent/uc/`: service onboarding, policy update,
role update and offboarding. Onboarding, policy update and role update have specs in
[docs/specs/components/aiac-agent/](docs/specs/components/aiac-agent/); offboarding is described in
the [PRD](docs/specs/PRD.md).

## Repository layout

Discover the current concrete layout live rather than relying on this snapshot:

```bash
find src/aiac -maxdepth 2 -type d
```

## Getting started

Requirements: Python >= 3.12, [uv](https://docs.astral.sh/uv/).

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[test]"
```

Always use `.venv` for Python execution, tests, and dependency checks (`.venv/bin/python`,
`.venv/bin/pytest`).

## Running tests

`pytest` collects both `test/` and `eval/`. Selection is **marker-only** — never pass a path. A
bare run is the offline unit lane (the default `addopts` deselects `integration`, `system`, `llm`
and `eval`); a command-line `-m` opts into another lane:

```bash
.venv/bin/pytest                    # unit lane — offline, needs nothing
.venv/bin/pytest -m integration     # several AIAC units in one process — offline, needs nothing

set -a; . .env; set +a              # LLM_* / KEYCLOAK_* for the live lanes
.venv/bin/pytest -m llm             # live-LLM Policy Rules Builder suite — LLM endpoint only
.venv/bin/pytest -m system          # real OPA loop through AuthBridge — wired Kind cluster
.venv/bin/pytest -m eval            # policy-pipeline evaluation suite under eval/
```

| Lane | Needs |
|---|---|
| unit | Nothing |
| integration | Nothing (fakes stand in for Keycloak, the Policy Model Store and the Kubernetes API) |
| llm | `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` |
| system | A rossoctl/Kind cluster wired by `k8s/opa-kind-enable.sh`, the event path (the NATS broker and the `aiac-event-listener` Keycloak SPI), Keycloak admin creds, an LLM endpoint — see [docs/agents/test.md](docs/agents/test.md) |
| eval | Keycloak, an LLM endpoint, `opa` on `PATH` for the e2e level |

Live lanes skip cleanly when their env or cluster is missing — a skip is not a pass. Full lane
contract: [docs/agents/test.md](docs/agents/test.md); where to put a new test:
[docs/testing/testing-strategy.md](docs/testing/testing-strategy.md).

## Deploying to Kubernetes

Build/load the per-service images and apply the manifests under [k8s/](k8s/); full instructions
are in [k8s/aiac-deployment-guide.md](k8s/aiac-deployment-guide.md). To wire the AuthBridge OPA
plugin and the AIAC global combiner into Kind, see [k8s/opa-kind-runbook.md](k8s/opa-kind-runbook.md).

The enforcement side is a deploy-time setting — `AIAC_ENFORCEMENT_SIDE` in the
`aiac-agent-config` ConfigMap (`target-side`, the default: each callee checks its own inbound; or
`agent-side`: each callee still checks its inbound, and the agent also checks its outbound calls).
There is no live switch; changing it is a clean redeploy. See [docs/agents/deploy.md](docs/agents/deploy.md).

## Demo — onboarding an agent and a tool

[demo/use-cases/onboarding/](demo/use-cases/onboarding/) is a fully live, end-to-end demo: AIAC
discovers a `github-agent` and a `github-tool` deployed into `team1`, reads a two-line
plain-English policy, and writes one `AuthorizationPolicy` CR per service. Real HTTP requests
through the deployed AuthBridge OPA plugin are then allowed or denied by that generated Rego. It
proves two claims:

- **AIAC is triggered by onboarded workloads** — no one runs an onboarding command.
- **AIAC enforced a natural language policy in rossoctl** — verdicts come from the live OPA plugin, not from
  evaluating a file on the side.

Prerequisites: a Kind cluster named `rossoctl` with the rossoctl platform (SPIRE, Keycloak, the
operator), the `team1` namespace, `kubectl`, `helm`, `kind`, `curl`, `python3` and `docker` or
`podman` on `PATH`, sibling clones of `rossoctl/operator`, `rossoctl/rossoctl` and
`rossoctl/cortex`, and two secrets (`team1/openai-secret` and `aiac-system/keycloak-admin-secret`).
`github-agent` and `github-tool` must **not** already be deployed in `team1`: their first-time deploy
is the trigger. If you ran the demo or the system lane before, run `make restore` first.
Then, from that directory, in this order — the AIAC Controller does not start until `make opa` has
applied the changed combiner:

```bash
make opa        # wire the OPA plugin into both AuthBridge legs, apply the combiner (one-time)
make enable     # install the AIAC stack, NATS broker, Keycloak SPI listener
make users      # create the demo users and roles, mount policy.md
make e2e        # deploy the workloads (the trigger), then probe the live OPA plugin
```

The agent ships with its outbound route to `github-tool` already set. Before the probe, `make e2e`
grants the agent's Keycloak client the tool's audience scope and restarts the agent (phase PREP).

After `make e2e`, `make demo` walks the same scenario step by step for inspection; it needs the
workloads already deployed. `make restore` / `make teardown` clean up; `make help` lists every
target. The full narrative, verification and troubleshooting are
in [demo/use-cases/onboarding/demo.md](demo/use-cases/onboarding/demo.md). The demo workloads live
under [demo/assets/](demo/assets/) — see [demo/assets/INSTALL.md](demo/assets/INSTALL.md) and their
specs in [docs/specs/demo/](docs/specs/demo/).

## Documentation

- [docs/specs/PRD.md](docs/specs/PRD.md) — master PRD
- [docs/specs/components/](docs/specs/components/) — per-component specs (design decisions live embedded here)
- [CONTEXT.md](CONTEXT.md) — domain glossary
- [demo/use-cases/onboarding/demo.md](demo/use-cases/onboarding/demo.md) — end-to-end onboarding demo
- [k8s/aiac-deployment-guide.md](k8s/aiac-deployment-guide.md) — Kubernetes install guide
- [k8s/opa-kind-runbook.md](k8s/opa-kind-runbook.md) — local OPA/Kind integration setup
- [docs/agents/](docs/agents/) — test lanes, deploy parameters, issue tracker
- [docs/testing/](docs/testing/) — testing strategy and per-pipeline test docs
- [docs/evaluation/](docs/evaluation/) — policy-pipeline evaluation framework

## Contributing

Pre-commit hooks (formatting, linting via ruff, YAML/JSON checks) are configured in
[.pre-commit-config.yaml](.pre-commit-config.yaml):

```bash
pre-commit install
```

CI runs on every PR — see [.github/workflows/](.github/workflows/).
