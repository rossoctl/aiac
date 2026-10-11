# AIAC Codebase Guide

All paths below are relative to the repository root.

## Requirements / PRD docs

`docs/specs/PRD.md` — master PRD.
`docs/specs/components/` — per-component specs.

## Handoffs

Per-task handoff documents live under `docs/handoffs/` — one markdown file per task, numeric-prefixed (e.g. `01-update-issues.md`, `02-update-source-and-tests.md`). When asked to generate a handoff, write it here (not a scratch/temp path). Each handoff must be self-contained — background, task, exact files, and acceptance criteria — so a fresh session can execute it without the originating conversation.

## Tests

Two trees: `test/` (testing) and `eval/` (evaluation). Selection is
**marker-only**: never give `pytest` a path. A bare `.venv/bin/pytest` runs the
offline unit lane.

- To run a lane (unit, integration, llm, system, eval), see `docs/agents/test.md`.
- To write a new test (placement, markers, clean-skip), see
  `docs/testing/testing-strategy.md`.

## Python environment

Always use the `.venv` virtual environment (`.venv/bin/python`, `.venv/bin/pytest`)
for any Python execution, test runs, or dependency checks.

## Kubernetes & builds

- Build and deploy: `k8s/aiac-deployment-guide.md`. The OPA pipeline on Kind:
  `k8s/opa-kind-runbook.md`.
- Deploy parameters (for example the access-control scheme,
  `ac-side=agent|target`): `docs/agents/deploy.md`.

## External references

- [Kagenti Developer Guide](https://github.com/kagenti/kagenti/blob/main/docs/dev-guide.md) — upstream Kagenti dev guide: per-persona workflows (agent, tool, extensions developers, MCP gateway operators), Git/PR process, pre-commit hooks, feature flags, local Kagenti UI v2 development (React frontend + FastAPI backend, building/deploying images to Kubernetes), and HyperShift-based testing on ephemeral OpenShift clusters (cluster lifecycle, cost management, troubleshooting).

## Agent skills

### Issue tracker

GitHub issues in this repo's own remote (`rossoctl/aiac`), filtered by the `aiac` label; org-level Project board **AIAC #12** on `rossoctl`, triage state on its custom `Triage Status` field. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context (`CONTEXT.md` glossary at the repo root; design decisions documented in the relevant PRD/spec under `docs/specs/`). Consult decisions on demand, not up front. See `docs/agents/domain.md`. Where a skill says `GLOSSARY.md` or `docs/adr/`, use `CONTEXT.md` and the specs instead; never create either.
