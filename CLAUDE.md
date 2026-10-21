# AIAC Codebase Guide

All paths below are relative to the repository root.

## Requirements / PRD docs

Read these before you change a component's behavior or requirements:
`docs/specs/PRD.md` — master PRD.
`docs/specs/components/` — per-component specs.

## Handoffs

Write each per-task handoff document to `docs/handoffs/`: one markdown file per task, named with the next free number prefix (e.g. `01-update-issues.md`, `02-update-source-and-tests.md`).
Make each handoff self-contained: background, task, exact files, and acceptance criteria. A fresh session must be able to execute it without the originating conversation.

## Tests

Two trees: `test/` and `eval/`. Select tests with markers only, never with a
path. A bare `.venv/bin/pytest` runs the offline unit lane.

- To run a lane (unit, integration, llm, system, eval), see `docs/agents/test.md`.
- To write a new test (placement, markers, clean-skip), see
  `docs/testing/testing-strategy.md`.

**Dependency direction.** "Depend" means import, read, or link. Tests of any type
(`test/`, `eval/`) and their harness (fixtures, helpers, `conftest.py`) must not
depend on `demo/` or on a demo doc (for example `demo.md`); they set up what they
need themselves. The demo may use the harness.
One exception: the system tests deploy the `github-agent` and `github-tool`
workloads, so they may depend on `demo/assets/` and on nothing else under `demo/`.

## Python environment

Use the `.venv` virtual environment (`.venv/bin/python`, `.venv/bin/pytest`) for any
Python execution, test runs, or dependency checks. If `.venv` is missing, tell the
user and wait.

## Kubernetes & builds

Read these when a task builds images or deploys to a cluster:
- Build and deploy: `k8s/aiac-deployment-guide.md`. Deploy preconditions:
  `docs/agents/deploy.md`.

## External references

- [Kagenti Developer Guide](https://github.com/kagenti/kagenti/blob/main/docs/dev-guide.md) — read it when a task touches upstream Kagenti (its PR process, pre-commit hooks, UI v2, or HyperShift test clusters).

## Agent skill overrides

- **Issue tracker**: GitHub issues in `rossoctl/aiac`. Label every new issue `aiac` plus the `area:<path>` label of its component. Add it to board **AIAC #12** and set its `Triage Status`. See `docs/agents/issue-tracker.md`.
- **Triage labels**: every state label has the `status:` prefix and is mirrored on the board's `Triage Status` field. See `docs/agents/triage-labels.md`.
- **Domain docs**: single-context. `GLOSSARY.md` is the glossary; design decisions live in the specs under `docs/specs/`. Consult a design decision only when the task touches its area. See `docs/agents/domain.md`.
