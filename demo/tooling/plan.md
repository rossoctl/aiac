# Plan: Pixie-instrumented capture of the UC-1 onboarding demo → JSONL

## Goal

Re-run `demo/use-cases/uc1-onboarding/demo.md` end to end (already confirmed clean in
Pass 1, step by step, no Pixie) while recording every command/API-call and its
response into a structured JSONL file. That file, plus the narration already
validated in Pass 1, is the raw material for the demo video. This plan file itself
is written generically enough to become a reusable "capture a demo into JSONL" skill
later — the UC-1 specifics are the first worked example, not the point.

## Output schema

One JSON object per line, one line per **task** (a logical unit of the demo):

```json
{
  "task": "<what work is being done — logical, and technically specific>",
  "steps": [
    {"cmd": "<the request, exactly as issued>",
     "output": "<the response, exactly as received>",
     "explain": "<optional: why this step exists / what to notice>",
     "sent": "<optional: the request body, when the payload is the substance>",
     "elapsed_ms": 0}
  ],
  "summary": "<what this task achieved>"
}
```

### The recording replays these steps — so `cmd` and `output` must be real

The video simulates a developer typing each `cmd` and receiving each `output`. That is
the whole reason this file exists, and it constrains the schema absolutely:

- **`cmd` must be executable as written.** A real HTTP request, `kubectl`, or `opa eval`.
  Never a `make` target that wraps the work, never an invented label like
  `(inbound / outbound grants tables)`, never a summary of several calls
  (`118× GET idp-config lookup`). If it cannot be typed and run, it is not a step.
- **`output` must be the byte-exact response.** Not a paraphrase, not a truncation, and
  never the demo's own narration (`✓ onboarding call returned 200`). If a call genuinely
  returns an empty body — the onboarding POST answers `200` with `content-length: 0` — that
  is the true output and it stays as-is; the substance then lives in `sent`.
- **A step with no captured response is not a step.** The local `opa eval` calls are real
  work, but the demo never prints their stdout, so there is nothing to replay. Their
  meaning goes in `task`/`summary`/`explain`, not into a fabricated `output`.
- **Derived views are dropped.** Grants tables, Rego diffs and result tables are computed
  summaries, not commands. Earlier versions emitted them with a `[derived]` prefix; they
  are now excluded, because a replay cannot type them.

**Free text lives only in `task`, `summary` and `explain`.** Those three carry all
narration; `cmd`, `output` and `sent` carry only captured bytes.

### The captured story starts at the onboarding, not the setup

`keycloak`/`prereqs`/`clear`/`setup` are scaffolding that gets the cluster to a clean
baseline; they are not the demo. The assembler still runs and logs them (a clean baseline
matters), but `--from-agent` emits only from the first onboarding task onward. That flag is
the default way to build the artifact.

### Show the work, not the product

The demo's point is the complexity of doing this by hand — so a label names *the work to be
done*, never the tool doing it. "Classify the workload and read its declared skills", not
"AIAC discovers what the agent is". A task whose only content is *activating* AIAC has been
removed outright: "we called the onboarding endpoint" demonstrates nothing.

Labels are simultaneously **logical and technically specific**, because the audience is a
developer. Say which mechanism is authoritative (the pod's `rossoctl.io/type` label), where
capabilities come from (the AgentCard CR's `status.card`, synced from the A2A card), and what
contract a call honours (`{approved, reason}`, retried up to 3 times).

### Two things that hide the substance

Both were invisible until the artifact was read closely:

- **The request body is often the point, not the response.** The Policy Writer POST answers
  `204` with no body while carrying the entire computed policy model (~5 KB) in its request.
  61 of 298 records in a run have a meaningful request body. `sent` carries it; without that
  field those steps read as `POST /policy -> 204` and say nothing.
- **A structured LLM decision is buried in an escaped envelope.** The verdict lives in
  `choices[0].message.content` as JSON-escaped text, so `"approved": false` appears on the
  wire as `\"approved\":false` several hundred characters in. `output` keeps the verbatim
  envelope — it is what a replay would show — and the decoded decision goes to `explain`.
  (Searching the raw text for the unescaped form finds nothing, which briefly made a captured
  audit rejection look absent when it was there all along.)

### A state change needs its verification shown

A mutating call often answers with a bare status and no body, which on its own proves
nothing to a viewer. The run already contains the follow-up reads that prove it — that
read-back is what makes re-running the onboarding idempotent — but the pattern is invisible
unless labelled, so each mutation carries a note saying what confirms it:

- `201` **with the created object in the body** — self-evidencing; the response *is* the proof.
- a bare `204` — the note points at the GET that follows and checks the state took effect.
- when nothing in the run reads it back, the note says so rather than implying otherwise.
  The Policy Writer POST is the honest example: its verification is the `kubectl get
  authorizationpolicies` step later in the demo, not an adjacent call.

`POST` alone does not mean "mutation": the LLM chat-completions and MCP `tools/list` calls
are queries that happen to use POST, and are never labelled as state changes.

### Split tasks by concern, from the observed traffic

Task boundaries are drawn where a developer would draw them, and derived from what the run
actually did rather than from what the code looks like. Two lessons paid for by getting it
wrong:

- **Do not merge distinct concerns.** One "discover" task held 118 calls that turned out to
  be four separate things: provisioning writes, a full-realm candidate sweep, subject reads,
  and per-candidate re-reads during evaluation. Merged, the artifact hid that provisioning
  happens at all.
- **Do not split on HTTP method.** GET-vs-POST looked tidy but misrepresents the run: each
  write is preceded by a read-back that makes it idempotent, so a method split reorders
  reality. Split on *concern*, and find the boundaries in the traffic (the
  `POST /services/{id}/type` stamp, the first and last `/subjects` read).

Repetition is evidence, not noise. Sweeping all 12 realm clients — many answering `[]` — is
exactly the tedium a human would face, so those calls are shown individually.

### Prose lives in storyline.md, structure lives here

This file governs **structure**: the schema, which traffic becomes which task, what may
appear in `cmd`/`output`. The narration itself — every `summary` line — lives in
`demo/tooling/storyline.md`, one `###` heading per task caption, and `assemble.py` reads
it at assemble time via `storyline_loader.py`. Editing the script is therefore a markdown
edit, reviewable as English, with no Python change.

Two guard rails keep the two from drifting apart: a task the assembler emits with no
heading in `storyline.md` is a hard error, and a `{placeholder}` the capture cannot fill
is a hard error rather than a silently empty sentence. Placeholders are substituted from
the run's own captured traffic, so a summary cannot claim a value the run did not produce.

### Field length

`task` is an on-screen caption, so it stays subtitle-tight (~90 chars). `summary` and
`explain` aim for the same brevity but are **not hard-capped**: a developer-facing detail is
worth more than a clean line length. The assembler reports what exceeds the hint and emits it
anyway — an earlier hard cap truncated an `explain` field to `"✓…"`.

## Task breakdown

One task per bullet. `(*)` marks tasks that get sub-split further than "one make
target" because they cover the onboarding black box.

1. `make keycloak` — discover/port-forward Keycloak
2. `make prereqs` — verify cluster/CRDs/namespace/SPIRE/Keycloak + AIAC stack + workloads
3. `make clear` — reset to clean baseline
4. `make setup` — provision users/roles, mount policy.md, configure token exchange
5. `make show` (Pause 1) — confirm clean baseline
6. **`make agent`**, split into `(*)`:
   1. Resolve `github-agent` service id (Keycloak client UUID lookup)
   2. Service Provision: classify the workload as an agent, discover roles/scopes from
      its AgentCard CR (Controller pod → k8s API + idp-config service)
   3. PRB propose: LLM call proposing grants/denies per role/scope pair against
      `policy.md` (Controller pod → external LLM endpoint)
   4. PRB audit: second LLM call auditing the propose step's output (same target,
      separate request/response)
   5. Policy Writer: render Rego, `PATCH` the `AuthorizationPolicy` CR via the k8s API
      (Controller → aiac-interface pod → k8s API server)
   6. Policy Model Store: persist the computed policy (Controller → policy-model-store
      pod)
   7. Capture generated Rego from the CR (`kubectl get authorizationpolicies...`)
7. `make show` (Pause 2) — confirm inbound populated, outbound empty
8. **`make tool`**, split into `(*)`:
   1. Resolve `github-tool` service id
   2. Service Provision: classify as a tool, discover scopes via live MCP `tools/list`
      call (Controller pod → `github-tool` pod, real pod-to-pod HTTP — Pixie-visible)
   3. PRB propose (re-run against newly discovered tool scopes)
   4. PRB audit
   5. Policy Writer: re-render `github-agent`'s CR (outbound gate retroactively
      completed) — no CR written for the tool itself, it's a pure target
   6. Policy Model Store: persist
   7. Capture generated Rego (agent's CR, now outbound-populated)
   8. Assign the tool-audience default scope to the agent client (Keycloak plumbing)
9. `make diff PRIOR=01-after-agent` (Pause 3) — outbound gate's grants filling in
10. `make dev` — dev-user driven through inbound + RFC 8693 exchange + per-intent outbound
11. `make test` — test-user, same shape
12. `make devops` — devops-user, blocked at inbound (expected)

This is 12 top-level tasks, with #6 and #8 each expanding into 7–8 finer sub-tasks —
so the JSONL will have roughly 25 objects total for one full run.

## Capture mechanism (two sources merged per task)

**Source A — terminal narration (all tasks).** Every task's existing `cmd()` calls
already print the literal command about to run; wrap the demo's own scripts (or a
thin driver around them) to also capture that same command plus whatever this
process's stdout/stderr was for the operation that followed, appending a `{"cmd":
..., "output": ...}` step. This needs no new instrumentation — the commands are
already literal strings in `_lib.py` and the numbered scripts (`say`/`explain`/`cmd`/
`ok`/`note`/`pause`).

**Source B — in-process HTTP client instrumentation (tasks 6 and 8 sub-steps, where
the real network hops are).** Confirmed call trace for `/apply/service/{id}` (see
"Internal call trace" below): the sub-steps in tasks 6 and 8 are real pod-to-pod
HTTP calls made by the Controller with plain `httpx`/`requests`. We capture them
**at the call site inside the `aiac-agent` process, before TLS**, rather than off
the wire — see "Capture tooling (reassessed 2026-09-10)" below for why every
network-level option was ruled out.

This single source covers **all** the hops uniformly, including the two PRB LLM
calls (propose + audit) to the external `LLM_BASE_URL`, which a network-level tool
could only see as opaque TLS. No Controller-log fallback is needed for them.

## Internal call trace (why the task split above is what it is)

Traced from `src/aiac/agent/controller/routes.py` through to the Policy Writer and
Policy Model Store (see `aiac/CLAUDE.md`'s subsystem layout for context):

- **Service Provision** — runs inside the `aiac-agent` pod (Controller process), not a
  separate service. Agent path: k8s API calls (`list_pods`, `list_agentcards`) +
  HTTP to `aiac-pdp-config-service:7071` (idp-config). Tool path: real MCP call,
  `POST http://<workload>.<namespace>.svc.cluster.local:<port>/mcp` (`tools/list`),
  Controller pod → tool pod. **Crosses into the `team1` ambient mesh — mTLS on the
  wire**, which is why this hop drove the move to in-process capture.
- **PRB propose / audit** — two separate LLM round-trips from the `aiac-agent` pod to
  an external `LLM_BASE_URL` (no in-cluster proxy pod). External TLS; captured
  in-process like every other hop.
- **Policy Writer** — two hops: `POST` from `aiac-agent` to
  `aiac-pdp-policy-service.aiac-system.svc:7072` (the `aiac-interface` pod), which
  itself does a real k8s API-server call (`CustomObjectsApi.patch_namespaced_custom_object`,
  server-side-apply) to write the `AuthorizationPolicy` CR — not a shelled-out
  `kubectl`, but an equivalent PATCH the k8s API server sees, and Pixie can see the
  HTTP leg into the aiac-interface pod.
- **Policy Model Store** — `GET`/`POST` from `aiac-agent` to
  `aiac-policy-model-store-service.aiac-system.svc:7074`, network.

All 6 conceptual sub-steps per onboarding call are outbound HTTP from the
`aiac-agent` process, so in-process client instrumentation captures every one of
them from a single vantage point — the 4 in-cluster hops and the 2 external LLM
calls alike. (Under the previously-planned network capture these would have split
4/2, with the LLM calls needing a Controller-log fallback and the MCP `tools/list`
hop unreadable under mesh mTLS.)

## Capture tooling (reassessed 2026-09-10)

Three network-level tools were tried or evaluated against this cluster and **all
were ruled out on hard evidence**, not preference:

| Tool | Outcome |
|---|---|
| **Pixie** | Dead. `px deploy`'s own precheck refuses Kind unconditionally: *"We don't currently support Kind clusters… use minikube instead."* Bypass exists (`--check=false`) but was not attempted, per Pixie's explicit unsupported-config warning. |
| **kubeshark** | Dead. Deployed successfully under a rootful Podman VM, but its `sniffer` fails CO-RE relocation on this kernel (`bad CO-RE relocation: invalid func unknown#…` loading `kp_tcp_sendmsg`) and its `tracer` is hardcoded x86-64 (`only x86-64 binaries are supported by the runtime extractor: got EM_AARCH64`). Node is genuinely ARM64. Architectural, not fixable by config. |
| **tcpdump / ksniff** | Ruled out on capability, not compatibility. `team1` is in the **Istio ambient mesh** (`istio.io/dataplane-mode=ambient`, ztunnel running), so the Controller→`github-tool` MCP `tools/list` hop — the demo's centerpiece — is **mTLS ciphertext on the wire**. tcpdump yields TCP metadata only for exactly the hop that matters most, and requires manual stream→request/response pairing for the rest. |

**Decision: instrument the HTTP client inside the `aiac-agent` process.** The
Controller makes every outbound call with plain `httpx`/`requests`
(`src/aiac/agent/uc/onboarding/provision/nodes.py:69`, `init/wait_and_provision.py:39`),
and the image already ships the OTel SDK (`opentelemetry-sdk`,
`opentelemetry-exporter-otlp-proto-grpc`) though **nothing is currently
instrumented** — no OTel env vars on the Deployment, no `get_tracer` calls in
`src/aiac/`. An `otel-collector` is already running in `rossoctl-system`
(ports 4317/4318).

Why this is the right fit, not just the last option standing:
- **mTLS is irrelevant** — capture happens pre-TLS, at the call site
- **Request/response are inherently paired** — no stream reassembly or correlation heuristics
- **Covers the external LLM calls too** — the two PRB round-trips, uniformly, from the same source
- **No eBPF, no privileged pods, no kernel/arch dependency** — works on ARM64 Kind, rootful or not
- **Structured output** maps near-directly onto this plan's `{"cmd", "output"}` schema

Cost, stated honestly: it requires a **code change** to the agent image (an
instrumentation hook + rebuild). Bodies are not captured by OTel's HTTP
instrumentation by default (method/URL/status only), so a small request/response
hook is needed to record them. Work happens on branch **`demo-movie`**.

Sequencing (user-directed): branch first → confirm a **clean uninstrumented run**
of the demo on the rebuilt cluster → only then add instrumentation. That way any
later breakage is unambiguously attributable to the instrumentation.

## Output location

`demo/out/<demo_name>_<datetime>/capture.jsonl`

For this run: `demo/out/uc1-onboarding_<YYYYMMDD-HHMMSS>/capture.jsonl`
(directory created at the start of the run below). This directory is the
self-contained bundle for one capture run — if a rerun is requested after review,
it gets its own new `<demo_name>_<datetime>` sibling rather than overwriting the
prior one, so previous attempts remain available for comparison.

"Self-contained" has to be **made** true, not assumed. The Rego the demo writes lands
in the live `use-cases/uc1-onboarding/generated/` tree, which the next run overwrites
and `make clear` empties — so reading it at assemble time made an artifact depend on
whatever ran last. Observed: a September 14 run quoted Rego written on September 15,
and a `make clear` in between silently dropped two tasks (22 became 20). Snapshot it
into the run directory as the final step of capture:

```bash
assemble.py demo/out/<run> --snapshot-generated
```

`rego_steps` then resolves from `<run>/generated/` and only falls back to the live tree
for older bundles, warning on stderr when it does.

## The JSONL is the hard boundary

This run of the actual demo application (`make ...` against the live cluster,
Keycloak, LLM, Pixie) is the **only** step in the whole pipeline that touches the
running system. Everything downstream — review, edits, and eventually the video
script/recording prep — consumes `capture.jsonl` alone and never re-touches the
cluster.

The one exception: the user reviewing `capture.jsonl` may request changes (a task
split differently, more/less detail in a step, a different summary) that require
**rerunning the demo application itself** — e.g. if a requested change needs new
data that only exists by re-executing a step live (a fresh instrumented capture, a
different LLM trace). That rerun produces a new dated directory under
`demo/out/`; it is still "the capture step," just invoked again. Once the
user confirms a `capture.jsonl` is correct, it is treated as final and frozen —
no further reruns happen on that demo's behalf, and all later work (video script,
recording notes, anything else built from it) is pure JSONL-in, artifact-out with
no access to the cluster.

## Execution order

1. **This plan file** — `demo/tooling/plan.md` (updated 2026-09-10 with the tooling
   reassessment)
2. **Branch `demo-movie`** off `uc1-demo` — instrumentation is a code change, so it
   does not land on the demo branch itself *(done)*
3. **Confirm a clean, UNINSTRUMENTED run** of the demo on the rebuilt cluster
   (`make keycloak` → `make devops`). This is the baseline gate: no instrumentation
   work starts until the demo is known-good here, so any later breakage is
   unambiguously attributable to the instrumentation.
4. Add HTTP client instrumentation to the `aiac-agent` image; rebuild, `kind load`,
   roll out. Verify with a trivial smoke onboarding that cmd/output pairs are being
   emitted before trusting it for the real run.
5. Create `demo/out/uc1-onboarding_<datetime>/`
6. `make clear` — reset to a clean slate (Pass 2 needs its own clean baseline,
   independent of Pass 1's already-torn-down state)
7. Re-run the full sequence from `make keycloak` through `make devops`, task by
   task per the breakdown above, this time:
   - capturing each task's terminal narration into the JSONL as before
   - folding the instrumented cmd/output pairs into the matching sub-steps of
     tasks 6 and 8
   - writing a `summary` line per task once its steps are captured
   - appending each finished task as one line to that run's `capture.jsonl`
8. Hand `capture.jsonl` to the user for review. If changes are requested that need
   live data, rerun from step 5 into a fresh dated directory; otherwise edit the
   JSONL directly. Repeat until the user confirms it's correct.
9. Once confirmed: `capture.jsonl` is frozen. All later steps (video script,
   recording notes, etc.) read only from it — no further application runs.

## Open questions to resolve as we go (not blocking the plan, deferred per the user)

- Exact instrumentation seam: OTel `opentelemetry-instrumentation-httpx`/`-requests`
  with a body-capture hook (exporting to the existing `otel-collector`), versus a
  simpler direct `httpx`/`requests` wrapper that appends `{cmd, output}` JSONL at
  the source. The latter needs no collector and lands in this plan's exact schema;
  decide once we see how much the OTel route's body hook actually costs.
- Where cmd/output truncation limits go for large bodies (e.g. the full generated
  Rego, or a full LLM prompt) — likely truncate with a note, keep full content only
  where it's the point of the step (e.g. the Rego diff)
- How this plan generalizes into a reusable skill once this first pass is done —
  revisit after we've actually produced one JSONL end to end
