# AIAC — AI-based Access Control

AIAC is a Rossoctl platform extension that automates access control policy enforcement for AI agents
running on Kubernetes. It continuously translates natural-language access-control policy into
concrete permission rules on the active Policy Decision Point (OPA), using an identity provider
(currently Keycloak) for roles, scopes, and services.

## Architecture

![AIAC Architecture image](docs/presentations/aiac-architecture.drawio.png)

The image is also the source: it embeds the diagram, so open
[docs/presentations/aiac-architecture.drawio.png](docs/presentations/aiac-architecture.drawio.png)
in [draw.io](https://app.diagrams.net/) to edit it.

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

The use cases live under `src/aiac/agent/uc/`. Service onboarding, policy update and role update
each have an event trigger and a spec in
[docs/specs/components/aiac-agent/](docs/specs/components/aiac-agent/). A role-membership change
(`aiac.apply.role-members.*`, D32) is a trigger with no use case: the consumer sends it to the
Policy Computation Engine's `rerender_role`, which gives the role's CRs the current holders and
does not run the Policy Rules Builder. Offboarding is also a use
case, but it has no event trigger: it is HTTP-only (`POST /apply/offboard/{service_id}`), and a
deleted workload does not start it. Offboarding is described in the [PRD](docs/specs/PRD.md).

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

```bash
.venv/bin/pytest                    # unit lane — offline, needs nothing
```

Selection is by marker (`-m integration`, `-m llm`, `-m system`, `-m eval`), never by path. The
lanes, what each one needs and their env are in [docs/agents/test.md](docs/agents/test.md); where to
put a new test: [docs/testing/testing-strategy.md](docs/testing/testing-strategy.md).

## Deploying to Kubernetes

The build and deploy flow is in [k8s/aiac-deployment-guide.md](k8s/aiac-deployment-guide.md).
Every deploy has two preconditions, the OPA pipeline with the AIAC combiner and the Keycloak
event-listener SPI, and one deploy-time parameter, the enforcement side. All three are in
[docs/agents/deploy.md](docs/agents/deploy.md).

## Demo — onboarding an agent and a tool

[demo/use-cases/onboarding/](demo/use-cases/onboarding/) is a fully live, end-to-end demo: AIAC
discovers a `github-agent` and a `github-tool` deployed into `team1`, reads a two-line
plain-English policy, and writes one `AuthorizationPolicy` CR per service. Real HTTP requests
through the deployed AuthBridge OPA plugin are then allowed or denied by that generated Rego. It
proves two claims:

- **AIAC is triggered by onboarded workloads** — no one runs an onboarding command.
- **AIAC enforced a natural language policy in rossoctl** — verdicts come from the live OPA plugin, not from
  evaluating a file on the side.

Before you start, make sure that you have:

- A Kind cluster named `rossoctl` with the rossoctl platform (SPIRE, Keycloak, the operator).
- The `team1` namespace.
- `kubectl`, `helm`, `kind`, `curl`, `python3`, and `docker` or `podman` on `PATH`. `make demo`
  also needs the `opa` binary on `PATH` (or `OPA_BIN`).
- The project `.venv` with its dependencies installed (see [Getting started](#getting-started)).
  The Makefile's Python targets run `../../../.venv/bin/python`, not `python3`.
- Sibling clones of `rossoctl/operator`, `rossoctl/rossoctl` and `rossoctl/cortex`.
- Two secrets: `team1/openai-secret` and `aiac-system/keycloak-admin-secret`. Create the
  `aiac-system` namespace and its Secret yourself, before you install AIAC: the install creates the
  namespace and, in the same run, a Deployment that mounts the Secret. Without it, `aiac-interface`
  stays in `ContainerCreating`. The commands are in
  [Two secrets to create first](demo/use-cases/onboarding/demo.md#two-secrets-to-create-first).
- An LLM endpoint for the key in `team1/openai-secret`. `make enable` uses
  `LLM_BASE_URL=https://api.openai.com/v1` and `LLM_MODEL=gpt-4o-mini` by default. For a different
  endpoint, set both: `LLM_BASE_URL=... LLM_MODEL=... make enable`. If they do not match the key,
  onboarding fails with a 401 error.
- On a new realm, the one-time
  [Keycloak realm fix-up](demo/use-cases/onboarding/demo.md#one-time-keycloak-realm-fix-up)
  (Direct Access Grants on the `rossoctl` client). Without it, token minting fails with
  `unauthorized_client`.
- No `github-agent` or `github-tool` deployed in `team1`. Their first-time deploy is the trigger. A
  clean system-lane run removes them at teardown. After an earlier demo run or an aborted
  system-lane run, run `make restore` first.

Then run the steps of [demo/use-cases/onboarding/demo.md](demo/use-cases/onboarding/demo.md), in
the order it gives, from that directory. Each step is a `make` target, and `make help` lists them
all. The full narrative, verification and troubleshooting are also there.

`make demo` is a separate, narrated walkthrough of the same scenario. It is not an inspection of
the live path's result: it first resets the state, then onboards by hand, and gets its verdicts
from an offline `opa eval`, not from the live OPA plugin. It needs the workloads already deployed.
The reset deletes the `github-agent.*` and `github-tool.*` Keycloak roles and client scopes, the
Policy Store and both AuthorizationPolicy CRs. Under the changed combiner (D20) a pod with no CR is
denied, so from the reset until its manual onboarding finishes (or for good, if `make demo` stops
before then) the live workloads deny every request. `make restore` and `make teardown` clean up.
The demo workloads live
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
