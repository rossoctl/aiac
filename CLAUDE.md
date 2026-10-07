# AIAC Codebase Guide

All paths below are relative to the repository root.

## Requirements / PRD docs

`docs/specs/PRD.md` — master PRD.
`docs/specs/components/` — per-component specs.

For current file list, `ls docs/specs/` and `ls docs/specs/components/`.

## Handoffs

Per-task handoff documents live under `docs/handoffs/` — one markdown file per task, numeric-prefixed (e.g. `01-update-issues.md`, `02-update-source-and-tests.md`). When asked to generate a handoff, write it here (not a scratch/temp path). Each handoff must be self-contained — background, task, exact files, and acceptance criteria — so a fresh session can execute it without the originating conversation.

## Source code

`src/aiac/` — Python package root (`__init__.py` is empty). It is organized by
subsystem: an IdP configuration layer, a PDP policy-writer layer, the AIAC Agent
layer (built on the SPM/APM model — a Controller dispatching to use-case
sub-agents and a policy-rules builder), and a two-layer policy stack (models, a
model store, and the Policy Computation Engine).

Discover the concrete layout live rather than relying on a memorized tree:

```bash
find src/aiac -maxdepth 2 -type d      # subsystems and their immediate children
ls src/aiac/<subsystem>/               # drill into any layer
```

## Tests

Two trees: `test/` (testing) and `eval/` (evaluation). Selection is
**marker-only**: never give `pytest` a path. A bare `.venv/bin/pytest` runs the
offline unit lane.

- To run a lane (unit, integration, llm, system, eval), see `docs/agents/test.md`.
- To write a new test (placement, markers, clean-skip), see
  `docs/testing/testing-strategy.md`.

## Python environment

Virtual environment: `.venv`

Activate: `source .venv/bin/activate`
Run directly: `.venv/bin/python` / `.venv/bin/pytest`

Always use this venv for any Python execution, test runs, or dependency checks.

## Kubernetes & builds

Config: `k8s/`, `pyproject.toml`, `pyrightconfig.json`. Each service has a
`Dockerfile` next to its code under `src/` (`find src -name Dockerfile`).

- Build and deploy: `k8s/aiac-deployment-guide.md`. The OPA pipeline on Kind:
  `k8s/opa-kind-runbook.md`.
- Deploy parameters (for example the access-control scheme,
  `ac-side=agent|target`): `docs/agents/deploy.md`.
- Hardening rules for Dockerfiles and manifests (non-root UID 10001, `fsGroup`,
  `securityContext`, probes, limits): `.claude/rules/container-hardening.md`.
  Claude Code loads it when you work on those files.

## External references

- [Kagenti Developer Guide](https://github.com/kagenti/kagenti/blob/main/docs/dev-guide.md) — upstream Kagenti dev guide: per-persona workflows (agent, tool, extensions developers, MCP gateway operators), Git/PR process, pre-commit hooks, feature flags, local Kagenti UI v2 development (React frontend + FastAPI backend, building/deploying images to Kubernetes), and HyperShift-based testing on ephemeral OpenShift clusters (cluster lifecycle, cost management, troubleshooting).

## Agent skills

### Issue tracker

GitHub issues in this repo's own remote (`rossoctl/aiac`), filtered by the `aiac` label; org-level Project board **AIAC #12** on `rossoctl`, triage state on its custom `Triage Status` field. Migrated from `s-and-p-team/cortex` on 2026-09-09. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context, scoped to `aiac/` (`CONTEXT.md` glossary at the `aiac/` root; design decisions documented in the relevant PRD/spec under `docs/specs/`). Consult decisions on demand, not up front. See `docs/agents/domain.md`.
