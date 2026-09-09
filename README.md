# AIAC — AI-based Access Control

AIAC is a Rossoctl platform extension that automates access control policy enforcement for AI agents
running on Kubernetes. It continuously translates natural-language access-control policy into
concrete permission rules on the active Policy Decision Point (OPA), using an identity provider
(currently Keykloak) for roles, scopes, and services.

See [docs/specs/PRD.md](docs/specs/PRD.md) for the full product requirements.

## Architecture

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
.venv/bin/pytest test/
```

Bare `pytest` runs unit tests only — every live-infra marker (`integration`, `llm`,
`eval_extended`, `eval_consistency`, `eval_robustness`, `eval_correctness_prb`,
`eval_correctness_e2e`) is excluded by default. Opt into a marker explicitly to run it, e.g.:

```bash
set -a; . .env; set +a          # LLM_BASE_URL / LLM_MODEL / LLM_API_KEY
.venv/bin/pytest test/ -m llm   # live-LLM Policy Rules Builder suite, no cluster needed
```

Integration tests additionally need a live rossoctl/Kind cluster with the AuthBridge OPA pipeline
wired in, plus Keycloak admin creds. Stand it up with `k8s/opa-kind-enable.sh` — see
[k8s/opa-kind-runbook.md](k8s/opa-kind-runbook.md) for prerequisites and manual probe commands.

## Deploying to Kubernetes

Build/load the per-service images and apply the manifests under [k8s/](k8s/); full instructions
are in [k8s/aiac-deployment-guide.md](k8s/aiac-deployment-guide.md).

To try the end-to-end onboarding flow against a demo agent/tool, see
[demo/assets/INSTALL.md](demo/assets/INSTALL.md).

## Documentation

- [docs/specs/PRD.md](docs/specs/PRD.md) — master PRD
- [docs/specs/components/](docs/specs/components/) — per-component specs
- [docs/adr/](docs/adr/) — architecture decision records
- [CONTEXT.md](CONTEXT.md) — domain glossary
- [k8s/aiac-deployment-guide.md](k8s/aiac-deployment-guide.md) — Kubernetes install guide
- [k8s/opa-kind-runbook.md](k8s/opa-kind-runbook.md) — local OPA/Kind integration setup

## Contributing

Pre-commit hooks (formatting, linting via ruff, YAML/JSON checks) are configured in
[.pre-commit-config.yaml](.pre-commit-config.yaml):

```bash
pre-commit install
```

CI runs on every PR — see [.github/workflows/](.github/workflows/).
