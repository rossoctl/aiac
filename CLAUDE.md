# AIAC Codebase Guide

All paths below are relative to the repository root.

## Requirements / PRD docs

`docs/specs/PRD.md` — master PRD.
`docs/specs/components/` — per-component specs.

For current file list, `ls docs/specs/` and `ls docs/specs/components/`.

## Requirements directory — link-following policy

When a document under `docs/specs/` contains a markdown link to another file, use the AskUserQuestion tool to ask before reading it — present "Yes" and "No" as clickable options. If the user picks Yes, read the file normally. If No, treat the link as a label and continue without reading it.

## Issue tracking — codebase inspection policy

When working on an issue would benefit from inspecting the relevant source code, use the AskUserQuestion tool to ask before doing so — present "Yes" and "No" as clickable options. If the user picks Yes, inspect the codebase normally. If No, work from the issue description and existing context only.

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

The suite splits into two top-level trees: **Testing** (`test/`) and
**Evaluation** (`eval/`). Selection is **marker-only** — never pass a path to
`pytest`. `testpaths` in `pyproject.toml` already collects both trees, and the
default `addopts` deselects every live-infra / eval marker
(`-m "not integration and not system and not llm and not eval"`), so a bare
`pytest` is the offline unit suite. A command-line `-m` overrides that default
(last `-m` wins).

Testing has three scope-based levels:

- **`unit`** (untagged) — `test/unit/` mirrors `src/aiac/`; in-process, single
  unit, no external services **except a real LLM endpoint when the test also
  carries the orthogonal `llm` tag** (see below). This is what a bare `pytest`
  runs (the `llm`-tagged ones are deselected by default).
- **`integration`** (`-m integration`) — several AIAC units cooperating
  in-process on a laptop, **no cluster**. Marker reserved; no such tests exist
  yet (the directory is intentionally absent).
- **`system`** (`-m system`) — needs a live Kind cluster / Rosso / deployed
  AIAC. Lives under `test/system/`.

Orthogonal to those, **`llm`** tags a test that calls a real external LLM but
needs no cluster. An `llm`-tagged test keeps the placement of its scope level —
a single-unit `llm` test still lives under `test/unit/` — so the "no external
services" rule for the unit tree is read as "no external services beyond an LLM
endpoint the `llm` tag opts into", and only that tag reaches a live LLM.

Use `ls test/` / `find test -type d` to discover current test directories.

### Authoring a new test — where and how

Placement follows what the test **touches**, not what it is about. Decide with
this ladder (first match wins):

1. **One unit, in-process, no external service** → **unit**. Put it under
   `test/unit/` at the path that **mirrors** the module under test — e.g. a test
   for `src/aiac/pdp/policy/…` goes in `test/unit/pdp/policy/`. Leave it
   **untagged** (no `pytestmark`); a bare `pytest` then runs it. Create the
   mirroring directory if it does not exist yet.
2. **Several AIAC units cooperating in-process, still no cluster** →
   **integration**. Tag the module `pytestmark = pytest.mark.integration` (or the
   single test with `@pytest.mark.integration`). The directory is intentionally
   absent — create `test/integration/` mirroring `src/aiac/` when you add the
   first one.
3. **Needs a live Kind cluster / Rosso / deployed AIAC** → **system**. Put it in
   `test/system/` and tag it `@pytest.mark.system`. It **must skip cleanly** when
   the cluster/env is missing — gate on the env with `require_env_or_skip`
   (never `require_env`, which hard-exits), so it never false-passes offline.
4. **Heavy policy-pipeline evaluation** → **eval**. Put it under `eval/` and tag
   it `@pytest.mark.eval`. Same clean-skip discipline.

Then, **orthogonally**: if the test calls a real external LLM but needs no
cluster, add the `llm` tag as well (a unit or integration test can be
`llm`-tagged). Combine markers on one test with
`pytestmark = [pytest.mark.system, pytest.mark.llm]`.

Rules of thumb: prefer the **lowest** level that still exercises what you need
(most tests are unit); never `import` by a hard-coded path — derive the repo root
with `Path(__file__).resolve().parents[N]` and **count the levels from the file's
actual location** (a `test/unit/pdp/policy/` file is 4 levels below the repo
root); any test above the unit level skips cleanly when its infra is absent.

**Unit tests** (the default, offline):

```bash
.venv/bin/pytest
```

**Live-LLM PRB tests** (`-m llm`) run the **real** LLM end-to-end through the
Policy Rules Builder (`test/unit/agent/policy_rules_builder/test_graph_live_llm.py`)
and assert the emitted `(name, effect)` rule set matches the policy text — for
allow-only policies and for policies with explicit / description-driven /
exclusivity denies. Only the role/scope **descriptions** and the **policy
source** are mocked in-process (the `_structured_call` LLM seam is left live), so
the suite needs **no Kubernetes and no Keycloak** — only an LLM endpoint. It
reuses the same `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` env as the system
suite and **skips cleanly** when they are unset. Run it opt-in:

```bash
set -a; . .env; set +a   # or export LLM_BASE_URL / LLM_MODEL / LLM_API_KEY
.venv/bin/pytest -m llm
```

**System tests** (`-m system`) close the **real OPA evaluation loop** — they onboard
through the in-cluster Controller, then drive real HTTP requests **through AuthBridge** and assert the
**deployed OPA plugin's** allow/deny (no `opa eval`, no `.rego` dump, so `opa` on PATH is no longer
needed). They therefore need a live **rossoctl/Kind cluster with the AuthBridge OPA pipeline wired
into both legs** (the demo `github-agent`/`github-tool` deployed + registered), plus Keycloak admin
creds and an LLM endpoint for onboarding. Stand the pipeline up with `k8s/opa-kind-enable.sh`;
the full prerequisites, wiring, and manual probe commands are in `k8s/opa-kind-runbook.md`, and the
per-loop shape is documented in `test/system/uc1_onboard.py`. Config lives in
the repo-root `.env` (gitignored): `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`, `KEYCLOAK_URL`,
`KEYCLOAK_ADMIN_USERNAME`, `KEYCLOAK_ADMIN_PASSWORD`. Source it before running:

```bash
k8s/opa-kind-enable.sh          # one-time: wire the OPA plugin into the Kind cluster
set -a; . .env; set +a
.venv/bin/pytest -m system
```

When the cluster is not wired or the env is unset, the suite **skips cleanly** (it never false-passes).

**Evaluation** (`-m eval`) is the heavy, live-infra policy-pipeline evaluation
suite under `eval/`. Needs `KEYCLOAK_URL` + admin creds + `LLM_*` (and `opa` on
PATH for the e2e level); skips cleanly when unset. Run it opt-in:

```bash
set -a; . .env; set +a
.venv/bin/pytest -m eval
```

**Smoke test** (requires live service at `AIAC_PDP_CONFIG_URL`, default `http://127.0.0.1:7071`):

```bash
.venv/bin/python test/unit/idp/configuration/show_keycloak_data.py
```

Exercises all `Configuration` methods — run `ls test/unit/idp/configuration/` to see current coverage.

### Running a specific cluster of tests

Selection stays **marker-only** (never pass a directory path). A command-line
`-m` overrides the default and picks exactly one lane; `-m` accepts boolean
expressions, and `-k` narrows **within** a lane by name substring:

```bash
.venv/bin/pytest                              # unit lane (the default addopts)
.venv/bin/pytest -m system                    # only the system lane
.venv/bin/pytest -m "system or eval"          # union of two lanes
.venv/bin/pytest -m system -k uc1_onboard     # system lane, narrowed by name substring
```

There is **no literal `unit` marker** — the unit lane is *untagged*, selected by
the exclusion `-m "not integration and not system and not llm and not eval"`
(the default `addopts`). So `-m "unit or llm"` does **not** add the untagged unit
tests (`unit` matches nothing there); to run untagged unit tests **plus** the llm
lane, drop `llm` from the exclusion:
`-m "not integration and not system and not eval"`. Use `--collect-only -q` to
preview exactly which tests a selection resolves to before running the live ones.
The `system`/`llm`/`eval` lanes need their env (`set -a; . .env; set +a`) and skip
cleanly without it.

## Python environment

Virtual environment: `.venv`

Activate: `source .venv/bin/activate`
Run directly: `.venv/bin/python` / `.venv/bin/pytest`

Always use this venv for any Python execution, test runs, or dependency checks.

## Kubernetes & builds

Config: `k8s/`, `pyproject.toml`, `pyrightconfig.json`

Docker images: each service ships a `Dockerfile` next to its service code (build
context is `src/`, except `rag-ingest/`, which is a separate top-level
directory). Discover the current set of images and their Dockerfiles live:

```bash
find src -name Dockerfile          # per-service Dockerfiles under src/
ls rag-ingest/                     # the out-of-tree ingest image
```

Image names and build contexts are declared in the build/CI config and the
`k8s/` manifests — grep there for the authoritative name→Dockerfile mapping.

### Non-root container / volume-ownership pattern

All AIAC service images run as **non-root UID 10001**. Each service Dockerfile
adds the user before `CMD`, matching the `authbridge/sparc-service` pattern:

```dockerfile
# Drop privileges.
RUN useradd --no-create-home --uid 10001 aiac
USER 10001
```

A Dockerfile `chown` of a directory is **masked once a volume is mounted over
it** (the mounted volume, not the image layer, is what the container sees), and
the kubelet leaves emptyDir/PVC volumes root-owned by default. So any service
that writes to a mounted volume also needs pod-level `securityContext` in its
k8s manifest so the kubelet chowns the volume to the non-root user:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001   # makes the mounted volume group-writable by UID 10001
```

This applies to any service that writes to a mounted volume (a PVC or an
emptyDir). Find them live by grepping the manifests for volume mounts / claims:

```bash
grep -rlniE 'volumeMounts|volumeClaimTemplates|emptyDir|persistentVolumeClaim' k8s/
```

Services that mount no volumes still need the Dockerfile `USER` directive; the
pod-level `fsGroup`/volume-chown block above is only required for those that
write to a mounted volume.

### Pod-security hardening baseline

Beyond non-root, every workload in `k8s/` and the demo manifests carries a
hardened `securityContext`. Pod level (omitted on the demo `github-agent`, whose
injected AuthBridge sidecar runs as UID 1337 — hardening there is set per
container instead so a pod-level `runAsUser` can't clobber the sidecar):

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001        # 1001 for the demo github-agent
    seccompProfile:
      type: RuntimeDefault
```

Container level, on each app container:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

With `readOnlyRootFilesystem: true` the container gets a writable `/tmp`
`emptyDir` (and its real data mount — `/data`, `/rego`) so runtime temp writes
have somewhere to land. The demo `github-agent` **omits** `readOnlyRootFilesystem`
because its runtime (`uv` / `litellm` / `crewai`) writes caches under `HOME=/app`.
All core workloads also carry both readiness **and** liveness probes (`httpGet
/health` where the service exposes one; `tcpSocket` for the Controller and the
demo workloads, which don't) and CPU/memory requests + limits.

## External references

- [Kagenti Developer Guide](https://github.com/kagenti/kagenti/blob/main/docs/dev-guide.md) — upstream Kagenti dev guide: per-persona workflows (agent, tool, extensions developers, MCP gateway operators), Git/PR process, pre-commit hooks, feature flags, local Kagenti UI v2 development (React frontend + FastAPI backend, building/deploying images to Kubernetes), and HyperShift-based testing on ephemeral OpenShift clusters (cluster lifecycle, cost management, troubleshooting).

## Agent skills

### Issue tracker

GitHub issues in this repo's own remote (`rossoctl/aiac`), filtered by the `aiac` label; org-level Project board **AIAC #12** on `rossoctl`, triage state on its custom `Triage Status` field. Migrated from `s-and-p-team/cortex` on 2026-09-09. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context, scoped to `aiac/` (`CONTEXT.md` glossary at the `aiac/` root; design decisions documented in the relevant PRD/spec under `docs/specs/`). Consult decisions on demand, not up front. See `docs/agents/domain.md`.
