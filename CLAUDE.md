# AIAC Codebase Guide

## Requirements / PRD docs

Read these before you change a component's behavior or requirements:
`docs/specs/PRD.md` — master PRD.
`docs/specs/components/` — per-component specs.

## Handoffs

Write each per-task handoff document to `docs/handoffs/`: one markdown file per task, named with the next free number prefix (e.g. `01-update-issues.md`, `02-update-source-and-tests.md`).
Make each handoff self-contained: background, task, exact files, and acceptance criteria. A fresh session must be able to execute it without the originating conversation.
This overrides the `handoff` skill's temp-dir default.

## Tests

- Before you run any `pytest` command, even for one file, read
  `docs/agents/test.md` (selection, lanes, env).
- Before you write or change a test or its harness, read
  `docs/testing/testing-strategy.md` (placement, markers, clean-skip,
  dependency direction).

## Python environment

Use the `.venv` virtual environment (`.venv/bin/python`, `.venv/bin/pytest`) for any
Python execution, test runs, or dependency checks. If `.venv` is missing, tell the
user and wait.

## Kubernetes & builds

Read these when a task builds images or deploys to a cluster:
- Build, deploy, and platform preconditions: `k8s/aiac-deployment-guide.md`.
  Deploy parameters (for the `deploy` skill): `docs/agents/deploy.md`.

## External references

- [Kagenti Developer Guide](https://github.com/kagenti/kagenti/blob/main/docs/dev-guide.md) — read it when a task touches upstream Kagenti (its PR process, pre-commit hooks, UI v2, or HyperShift test clusters).

## Agent skill overrides

- **Issue tracker**: GitHub issues in `rossoctl/aiac`. Before you create or change an issue, read `docs/agents/issue-tracker.md`.
- **Triage labels**: every state label has the `status:` prefix and is mirrored on the board's `Triage Status` field. See `docs/agents/triage-labels.md`.
- **Domain docs**: single-context. `GLOSSARY.md` is the glossary; design decisions live in the specs under `docs/specs/`. See `docs/agents/domain.md`.
