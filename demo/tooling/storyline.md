# Storyline — UC1 onboarding

The narrative layer of the UC1 onboarding demo: for each task, the on-screen caption
(`task`) and the developer-facing explanation (`summary`) that appears beneath it.

`plan.md` governs **structure** — the `task`/`steps`/`summary` schema, how traffic is
split into tasks, field-length hints. This file governs **prose**. Review the story
here; `plan.md` stays the spec for how the capture is shaped.

`assemble.py` **reads this file at assemble time** — it is the source of every `summary`
in `capture.jsonl`, not a copy of it. Edit the prose here and the next run picks it up;
no Python change needed. A task the assembler emits with no heading here is a hard
error, so the script and the capture cannot drift apart silently.

## Conventions

- **`task`** is a caption read on screen. Subtitle-tight, ~90 chars (`SUBTITLE_HINT`,
  hard-capped at `TASK_MAX = 90`).
- **`summary`** is developer-facing and **not** hard-capped. A useful detail beats a
  clean line length; the assembler reports what exceeds the hint and emits it anyway.
- Lead with **what is being determined**, then the mechanism. A summary that opens on
  calling discipline makes the reader learn the *how* before the *what*.
- Name concrete values where they are the point — the resolved UUID, the label read,
  the count of clients swept.
- Prefer the system's own vocabulary (`kind=Agent`, `actorIds`, `tools/list`,
  `grant_is_exclusive`) over paraphrase, so the prose matches what a reader greps for.
- **Cite real values with `{placeholders}`.** They are substituted from this run's own
  captured HTTP traffic, so the script shows what actually happened rather than a
  plausible-looking constant. Available names:

  | Placeholder | Value |
  |---|---|
  | `{agent_spiffe}` / `{agent_uuid}` | the agent's clientId and resolved Keycloak UUID |
  | `{tool_spiffe}` / `{tool_uuid}` | the tool's clientId and resolved UUID |
  | `{client_count}` | how many clients the realm sweep actually returned |
  | `{agent_roles}` / `{agent_role_count}` | the roles provisioned for the agent |
  | `{tool_scopes}` | the client scopes discovered for the tool |
  | `{policy_text}` | the scenario policy, lifted from the prompt the run actually sent |

  A placeholder the capture cannot fill fails the build — a demo script that claims a
  value must be able to show it.

---

## Act I — Baseline

### `make keycloak` — discover Keycloak and port-forward it
Port-forwarded the in-cluster Keycloak to localhost:18080 and read the admin credentials
from the keycloak-admin-secret, so every later target can reach it.

### `make prereqs` — verify the cluster, the services, and the workloads
Confirmed the cluster, the policy services, and the agent and tool workloads are all
running, both are registered in the IdP, and the tool's Service carries the label that
makes its capabilities discoverable.

### `make clear` — reset to a clean slate
Removed provisioned roles/scopes, deleted the AuthorizationPolicy CR, and cleared local
generated/ snapshots, so this run starts from a known-empty baseline.

### `make setup` — provision users/roles, mount policy.md, configure token exchange
Provisioned dev-user/test-user/devops-user with their realm roles, resolved both workloads'
Keycloak client UUIDs, and enabled RFC 8693 token exchange on the agent's client. The whole
access policy is four lines of English — no YAML, no per-scope tables: "{policy_text}"

### Starting point: no access rules exist
Three users with job titles. No rules about what they may reach.

---

## Act II — Onboarding the agent

### Resolve the agent's identity in the IdP
The agent is registered under its SPIFFE name `{agent_spiffe}`, but everything that
follows refers to it by the UUID Keycloak assigned it: `{agent_uuid}`.

### Classify the workload, then create a role + scope per declared skill
Read `rossoctl.io/type` on the pod to determine whether this workload is an agent or a
tool — the two are discovered differently: an agent's skills come from its AgentCard
resource, a tool's from querying `tools/list`. Each declared skill then becomes one realm
role plus one client scope, bound to the client — here {agent_role_count} of them:
`{agent_roles}`.

### Find every existing client that could invoke this agent
Any client already defined in the system is a potential caller, so all {client_count} are
read and their roles collected — that is the population the policy gets judged against.
The agent's own roles are left out: it is not a caller of itself.

### Read the relevant users and their role assignments
Roles are flattened first, so a role held through a parent role counts the same as one
assigned directly. A role counts as a user's only if someone actually holds it and no
service owns it.

### Merge per-client role ownership into the realm-wide role list
A role's `kind` says whose it is — held by a human, or owned by an agent. The realm-wide
list leaves that field at its default, so agent-owned roles arrive looking like human ones;
only the per-client read carries the truth. Merging the two is what tells them apart.

### Proposer pass: an LLM grants per role/scope pair against policy.md
Determines, for each (role, scope) pair, whether the policy authorizes it. The policy is
the whole of the input — "{policy_text}" — and every grant below is derived from it. One call
per focal entity rather than per pair: a single role is judged against all candidate scopes (or
a single scope against all candidate roles), and the model is told to stay strictly scoped
to that focal and ignore everything else, so evidence about one entity cannot leak into
another's decision. Deny by default — a pair is granted only on evidence about the focal
itself, and policy silence is a silent non-grant (no rule at all), not an explicit
prohibition.

### Evaluator pass: a second LLM independently judges each proposal
A separate call re-derives the same decision under the same rules, so an omission or an
over-grant has to survive being checked twice. A rejection sends it back with the reason
attached, up to 3 attempts.

### Compile the decisions to OPA Rego and apply the agent's AuthorizationPolicy
The request body is the resolved rule set — allow/deny rules per gate, the subject->role
and target->scope maps, default_effect Deny. The writer compiles it to Rego and patches the
AuthorizationPolicy that AuthBridge's OPA plugin evaluates.

### Persist the computed policy to the Policy Model Store
The same path answered 404 before the write and returns the stored policy after. The stored
model is what a later onboarding reads instead of recomputing this one.

### The generated OPA policy, read back from the cluster
Two independent gates, both `default allow := false`: inbound answers who may call the
agent, outbound what the agent may then do on its behalf.

### State after the agent alone: inbound populated, outbound empty
No tool is onboarded yet, so every outbound map is still empty.

---

## Act III — Onboarding the tool

### Resolve the tool's identity in the IdP
Same lookup for the tool: `{tool_spiffe}` resolves to `{tool_uuid}`. It is registered as a
Tool rather than an Agent, which sends it down a different onboarding path.

### Call the tool's live MCP endpoint for `tools/list`
Capabilities are discovered by asking the running tool, not read from a manifest someone
maintains — so the policy is judged against what the tool actually exposes today.

### Proposer pass over the discovered tool scopes
Same policy text and the same focal-entity isolation, now applied to capabilities that were
discovered at runtime rather than declared anywhere.

### Evaluator pass over the tool proposals
Every tool-scope decision independently re-derived before it is trusted.

### Recompile the AGENT's Rego to fill in its outbound gate
A design decision: enforcement lives on the agent's outbound gate, not the tool's inbound.
The tool gets no policy of its own — the caller is what gets constrained.

### Persist the updated policy model
The store now holds both workloads' policies, so the agent-plus-tool relationship survives
beyond this run.

### The completed OPA policy, read back from the cluster
Both gates are now populated and the agent and tool are fully configured. Everything below
stops changing the system and just exercises it.

### Diff of the two snapshots: the outbound gate filling in
target_allow_scopes keyed by SPIFFE id; grants from two lines of English.

---

## Act IV — Exercising the gates

### Test: a user in the developer role exercises the configured system
Logs in, exchanges a token for the tool, then each intent is checked: source read and write
and issue reads allowed, closing an issue denied.

### Test: a user in the tester role, same flow
The mirror image: issue reads and writes allowed, reading source denied.

### Test: a user in a role the policy never mentions
Refused at the inbound gate before any tool call is attempted — no role they hold sources a
single scope the agent exposes.

---

## Applying changes

This file is read by `assemble.py` via `storyline.py`. To revise the script, edit the prose
under the relevant `###` heading and re-run the assembler — nothing else. The heading text
must match the task caption the assembler emits (matching ignores backticks, dash style and
whitespace).

    python3 demo/tooling/assemble.py demo/out/<run-dir>

Two failure modes are deliberately loud rather than silent:

- **A task with no heading here** aborts the assemble, naming the caption. Add the heading.
- **A `{placeholder}` the capture cannot fill** aborts too, listing what was available.
  A script that cites a value must be able to show it.

Values come from the run's own `raw-capture.jsonl` / `driver-capture.jsonl`, so re-running
against a rebuilt realm updates every cited UUID automatically.
