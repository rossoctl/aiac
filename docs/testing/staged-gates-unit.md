# Unit tests: the staged gates of the UC-1 harness — `test_uc1_staged_gates.py`

> **One spec among several.** This document specifies a **single** test file of the `unit` lane.
> Test specs live **one spec per test** under `docs/testing/`; the taxonomy is in
> [testing-strategy.md](testing-strategy.md), and the PRD's *Test & evaluation specifications*
> section ([../specs/PRD.md](../specs/PRD.md#test--evaluation-specifications)) is the index.

## Location

`test/unit/agent/uc/onboarding/test_uc1_staged_gates.py`. The file has no marker, so the default
`addopts` selects it and a bare `.venv/bin/pytest` runs it. It sits under `test/unit/agent/uc/onboarding/`
and covers the system harness `test/system/uc1_onboard.py`, which has no `src/` module to mirror. The
placement follows the precedent of `test_uc1_cr_capture.py`.

## Description

The system harness (`onboarded_stack`) gates each workload on positive facts, in the order the
platform makes them. The tests pin the pure deciders of those gates, with no cluster. Each decider
takes the observed objects and returns no problem (`None`, or an empty list for the CR-content
deciders) or a reason that names what is missing. Two gates do I/O; their tests replace that I/O with a
monkeypatch.

The file checks:

- **The final template.** A Deployment template is final only with the operator's type label and
  the credentials annotation of the matching type; a template of another type, or one without the
  annotation, is not final.
- **The rollout.** A rollout is complete only when the controller has observed the generation and
  no replica is old or unavailable. `rollout_counters` names every counter and the template marks.
- **The pods.** A live pod without the AuthBridge sidecar is named; a terminating pod does not count;
  no live pod is not ready.
- **The operator log.** The operator change note is empty when the operator is the same. A container
  restart in the same pod, a new pod (even with a lower restart count), or a lease change is noted.
  A missing operator pod is noted. A failed read is not reported as a restart and saves no log.
  A changed operator saves its logs, selected by the operator Deployment's own selector. An unchanged
  operator saves none (`capture_operator_logs`, with its I/O monkeypatched).
- **The AgentCard.** A legacy card named after the workload is found. A card with `Synced=True` wins
  over a stale legacy card.
- **The CR content.** `rego_binding_value` reads a list and a map. An agent CR with the per-skill
  scopes has no problem; an agent CR whose only scope is the default access scope, an agent CR with no
  agent scopes binding, or no agent CR at all, is a problem. A tool CR with the agent roles, or with some of them, has no
  problem; a tool CR with no calling-agent role is a problem, a tool CR that grants the default access
  role is named, and a tool CR with other owned tools is a problem.
- **The inbound hint.** `probe_hint` names the cause from the answer: a 503 from an OPA
  with no bundle points at the bundle service; an OPA 403 points at the CR; a 403 that is not from OPA
  says so; no answer points at the probe pod or the service; another 503 names its plugin; a 200 has
  no hint.
- **The report.** `signals_report` prints the last observation with its raw answer and hint. A signal
  that the poll never observed says so.
- **The onboarding log lines.** `onboarding_lines` keeps the last `keep` lines of this client, with the
  dead-letter move last, and ignores the lines of another client. With nine naks and `keep=3`, it keeps
  the last three, and the dead-letter move is the last of them.

It does not check the cluster behaviour of the gates. That is the system lane's job
([uc1-onboarding-pipeline.md](uc1-onboarding-pipeline.md)).

## Dependencies

The file imports the system harness (`from test.system import uc1_onboard`) and the scenario module
(`from test.system import scenario_uc1`). This is a known exception: the system harness links to
`demo/assets/` at import time, and the rule in [testing-strategy.md](testing-strategy.md) allows the
system tests to depend on `demo/assets/`. Fourteen existing unit files also import `test.system`, so this
file repeats an existing pattern (for example `test_uc1_cr_capture.py`). The harness does no cluster I/O at import time.

## Acceptance

The file passes with no cluster and no `.env`:

```bash
.venv/bin/pytest -m "not integration and not system and not llm and not eval" -k uc1_staged_gates
```
