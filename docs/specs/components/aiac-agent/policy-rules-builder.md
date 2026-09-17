# Sub-PRD: AIAC Agent — Policy Rules Builder

## Description

The **Policy Rules Builder** (PRB) is a shared module at `agent/policy_rules_builder/`. It
exposes two module-level functions that producing sub-agents call directly. Each function
internally runs a LangGraph `StateGraph`; callers are decoupled from LangGraph mechanics. The
PRB fetches its own policy context (see **Policy source** below), reasons over it with an LLM,
and emits `list[PolicyRule]` scoped to the input — both grants (`ALLOW`) and explicit prohibitions
(`DENY`). It does **not** call
`aiac.pdp.policy.library` or `aiac.policy.model_store.library` directly; only the PCE does.

---

## Entry points

```python
def build_role_rules(role: Role, scopes: list[Scope]) -> list[PolicyRule]: ...
def build_scope_rules(roles: list[Role], scope: Scope) -> list[PolicyRule]: ...
```

**`build_role_rules`** — role-centric: "given this role, which scopes does it get?"
Used for UC3 (Role Update). Called once per role with the full set of scopes relevant to the trigger.

**`build_scope_rules`** — scope-centric: "given this scope, which roles may access it?"
Used as one of the calls for UC1 (Service Onboarding). See the Controller sub-PRD for the full UC1 dispatch pattern.

Each call handles exactly **one focal entity** (the singular argument) against a list of
candidate counterparts; the caller (UC handler) does all iteration.

---

## Policy source (two phases)

Policy context is fetched behind a `PolicySource` seam, so the retrieval mechanism can change
without touching the rest of the graph.

- **Phase 1 (current):** the entire access-control policy lives in a **single file** — the
  **digested** policy (see [digested-policy.md](../../digested-policy.md)); the PRB reads the whole
  file into the proposer prompt. No ChromaDB, no domain-knowledge collection. Located via
  `AIAC_POLICY_FILE` (default `/etc/aiac/policy.md`), read as UTF-8; a missing/unreadable file raises.
  The PRB is **unaware of provenance** — it consumes the digested artifact exactly as it once
  consumed source prose; wiring `AIAC_POLICY_FILE` to the stored digest is the standalone unit's job
  (#2555 / #2559), not the PRB's.
- **Phase 2 (later issue):** policy **and** domain knowledge live in a ChromaDB vector store;
  the PRB does RAG retrieval over the `aiac-policies` and `aiac-domain-knowledge` collections
  (query text derived from the focal entity), respecting `CHROMA_N_RESULTS`. This swaps in a
  `ChromaPolicySource` at the same seam.

---

## Contract

| Aspect | Decision |
|---|---|
| Structure | LangGraph `StateGraph` — nodes `fetch → propose → precheck → audit → build`; `audit → propose` retry edge plus an `audit → RAISE` contradiction exit; two typed graphs (role / scope) sharing node helpers |
| Context retrieval | Two-phase via a `PolicySource` seam — Phase 1 whole-file read; Phase 2 ChromaDB RAG (both collections). See **Policy source** |
| Realm parameter | None — inputs are pre-resolved typed objects; the policy source is not realm-scoped |
| Trigger type in state | None — the function name encodes the direction; no routing field in state |
| Output shape | Proposer emits **names** — granted **and** denied (explicit prohibitions) — via `with_structured_output`; the PRB rebuilds `PolicyRule`s from the **typed inputs** filtered by name, never from LLM-produced fields. Result is a single mixed `list[PolicyRule]` (`effect` `ALLOW`/`DENY`), **allows-then-denies in candidate order**. DENYs = the explicit `denied_names` only — no exclusivity flag, no derived complement (digested input carries no "only"; see the design decision below) |
| Dedup | PRB generates a full rule set; the PCE's additive merge handles dedup on write |
| LLM call pattern | **Propose → LLM auditor** (2 structured calls). The auditor is **three-way**: approve → build; reject → feed its reason back into propose (bounded fix-and-retry, `MAX_AUDIT_RETRIES = 3`); **genuine grant/deny contradiction → raise**. Raises on retry exhaustion |
| Empty result | An auditor-**approved** empty selection is a valid `[]` (deny-by-default). An **all-deny** result (`granted=[]`, `denied≠[]`) is a **first-class valid output** — a durable prohibition is meaningful with no current grant. Empty proposals are still audited |
| Error contract | Raises on policy-source failure, LLM failure, audit-budget exhaustion, or a genuine grant/deny **contradiction** — no silent empty-list returns. See **Exceptions** for the full taxonomy |

---

## Exceptions

The PRB raises a small, closed hierarchy. Every message is **sanitized**: it never contains the
LLM endpoint, host, or API key. The HTTP column is the status a **single-entity caller** returns.
The async **retry class** is a separate axis — see the decoupling note below the table.

| Exception | Where raised | HTTP (single-entity) | Async class | Notes |
|---|---|---|---|---|
| `PolicyRulesBuilderBaseError` | Base of the hierarchy — **never raised directly** | 500 | — | A safety net at the HTTP boundary |
| `PolicyRulesBuilderError` | `_audit`, after `MAX_AUDIT_RETRIES` (3) ordinary rejections | 422 | permanent | The audit budget is exhausted |
| `LLMAccessError` | `_structured_call`, when **transient** failures (5xx / connect / timeout) are **exhausted** | 502 | **retryable** | Wraps the original error; message sanitized |
| `UnparseableLLMResponseError` | `_structured_call`, when the LLM is **reachable but the response is unparseable / schema-invalid** | 502 | permanent | A non-transient parse or validation error; message sanitized |
| `PolicyContradictionError` | `_audit`, on a **genuine** intra-focal grant/deny contradiction | 422 | permanent | Carries the focal entity + all contradictions; short-circuits past retry. UC1 aggregates it — see **Contradiction contract** |
| `PolicyConflictError` | `ServicePolicyBuilder.build` (UC1, `conflict_detection.py`) — **not** the graph | 422 | permanent | Carries a `ConflictReport`; aggregates per-focal contradictions across a UC1 run |

**HTTP status is decoupled from the async retry class.** `LLMAccessError` and
`UnparseableLLMResponseError` both map to **502**, but only `LLMAccessError` is **retryable** — the
unparseable case is **permanent**. A caller must read the async class, not the HTTP code, to decide
whether to retry.

---

## Internal graph design

Both entry points compile the same node shape (two typed graphs sharing pure node helpers):

```
fetch ─► propose ─► precheck ─► audit ─┬─ approved ────────────► build ─► END
          ▲                            │
          └───────── retry ────────────┤   (audit feeds its reason back to propose)
                                        │
              rejected & budget exhausted ─────► RAISE  (PolicyRulesBuilderError)
                                        │
              genuine grant/deny contradiction ─► RAISE  (PolicyContradictionError)
```

- **fetch** — `PolicySource.fetch()` → `policy_text` (Phase 1: the whole **digested** policy file).
- **propose** — proposer messages (policy + focal + candidates + any `audit_feedback`);
  `with_structured_output(Selection)` → granted names, **denied names** (explicit prohibitions), and
  reasoning. No exclusivity flag (digested policy carries no "only" — see the design decision below).
- **precheck** — deterministic: filter **both** the granted and denied name lists to the candidate
  set (drop hallucinated names; log drops — symmetric on both lists). Compute and store
  `conflict_names = granted_names ∩ denied_names`. Because denies are now purely the explicit
  `denied_names`, an overlap arises only from a `denied_names` entry that also appears in
  `granted_names` (direct conflict or coarse-scope mismatch) — the genuine contradiction signal. No LLM.
- **audit** — auditor messages (both name sets + `conflict_names`);
  `with_structured_output(AuditVerdict)` → `{approved, reason, contradictions}`. **Three-way route:**
  `contradictions` non-empty → `raise PolicyContradictionError(focal, contradictions)`; else
  approved → build; else feed the reason back and retry, or raise `PolicyRulesBuilderError` once
  `MAX_AUDIT_RETRIES` is exhausted. When `conflict_names` is present the auditor adjudicates each
  name: a **genuine** both-grant-and-prohibit lands in `contradictions`; a proposer **generation
  error** is an ordinary rejection (reason fed back, re-propose on the shared budget). Empty
  proposals are audited too.
- **build** — reconstruct `PolicyRule`s from the typed inputs: `ALLOW` from the granted names, `DENY`
  from the explicit `denied_names`. Return the single mixed list, allows-then-denies in candidate order.

### Structured-output schemas

```python
class RoleSelection(BaseModel):     # build_role_rules (role focal, scope candidates)
    granted_scope_names: list[str]
    denied_scope_names: list[str]     # explicit prohibitions (digested deny direct grants)
    reasoning: str

class ScopeSelection(BaseModel):    # build_scope_rules (scope focal, role candidates)
    roles_with_access_names: list[str]
    roles_denied_access_names: list[str]   # explicit prohibitions (digested deny direct grants)
    reasoning: str

class Contradiction(BaseModel):
    candidate_name: str
    description: str                  # which policy statements collide; names the kind

class AuditVerdict(BaseModel):
    approved: bool
    reason: str | None = None
    contradictions: list[Contradiction] = []
```

The PRB rebuilds rules from the typed inputs, never from LLM string fields — `ALLOW` from the
granted names, `DENY` from the explicit `denied_names`:

```python
allows = [PolicyRule(role=role, scope=s) for s in scopes if s.name in granted_scope_names]
denies = [PolicyRule(role=role, scope=s, effect=RuleEffect.DENY)
          for s in scopes if s.name in denied_scope_names]
return allows + denies   # allows-then-denies, each in candidate order
```

> **Deny extraction (ALLOW/DENY model, digested input).** With two-sided rules in the policy model
> (`PolicyRule.effect`, `RuleEffect.ALLOW` / `DENY` — see [`../policy-model.md`](../policy-model.md)),
> the PRB emits **both grants and prohibitions**. A **DENY** is emitted **only** for an **explicit
> prohibition** — never for mere silence or absence of a grant (those stay deny-by-default non-grants:
> *no rule at all*). The single trigger:
> - **Direct prohibition** about a specific pair — "must not", "cannot", "may not", "is forbidden",
>   "never", "except", "but not", "read-only" → `DENY(focal, that candidate)`.
>
> **No exclusivity / "only" handling.** The digested-policy language (see
> [digested-policy.md](../../digested-policy.md)) forbids exclusive language *and* open-ended
> exceptions: exclusivity is restated at the authoring layer as **explicit deny direct grants**
> (*"Only technical personnel may access issues"* becomes *"Technical personnel may access issues"* +
> *"Non-technical personnel may not access issues"*). Because the PRB now consumes only digested
> policy, every prohibition arrives as an **explicit** deny it reads per-pair; there is no
> exclusivity flag and no derived complement. See
> [Design decision: digested input retires exclusivity handling and Door B](#design-decision-digested-input-retires-exclusivity-handling-and-door-b).
>
> A DENY has exactly **two sources**: (1) the scenario digested policy prohibiting a pair, and (2) the
> **focal entity's own** description prohibiting its own access — a prohibition stated in the *focal*
> role/scope description (e.g. a focal role described as *"does not manage the issue tracker"*) denies
> that candidate, just as a positive description is a valid grant signal (capability projection, Rule
> 3). A **candidate's** description that merely disclaims a domain (its job scope) is **context, not a
> prohibition** — it yields a silent non-grant (deny-by-default), never a durable DENY; inferring a
> cross-DENY for a candidate from its own job description would over-reach and collide with the
> deny-by-default baseline the scenarios assume. (This is why grants read focal **and** candidate
> descriptions, but description-driven *denies* bind to the **focal** side only; policy-stated
> prohibitions still deny any pair.) The generic **baseline** (`generic_policy.md`) contributes
> **grants only** and is never a source of denials. A DENY's whole purpose is to be a **durable
> prohibition** that survives a later, broader grant under deny-overrides.

### State fields

```python
class _PRBWorking(TypedDict):
    policy_text: str
    selected_names: list[str]         # granted names (candidate-filtered)
    denied_names: list[str]           # explicit prohibitions (candidate-filtered)
    conflict_names: list[str]         # granted ∩ denied — the contradiction signal
    reasoning: str
    approved: bool
    audit_feedback: str | None
    retry_count: int
    rules: list[PolicyRule]

class RoleRulesState(_PRBWorking):   # role: Role; scopes: list[Scope]
    ...
class ScopeRulesState(_PRBWorking):  # roles: list[Role]; scope: Scope
    ...
```

### Prompts

Lean — task framing, the structured-output contract, two **safety** meta-rules
(**deny-by-default / policy-silence** — grant a pair only if the policy supports it — and
**scope-strictly-to-focal**), and the **deny** rules below. The proposer's task framing
is *"you map access policy to concrete grants **and prohibitions**."*

**Digest-aware framing.** The prompts consume **digested** policy (see
[digested-policy.md](../../digested-policy.md)), organized into its statement kinds plus domain
knowledge. The prompts tell both sides how to read each kind — without hard-requiring section
headings, so the reasoning degrades gracefully:

- **Direct grants** (allow / deny) → the primary evidence for `ALLOW` / `DENY`.
- **Attribute invariants** → **interpretive context only** — they constrain a single entity's
  attributes and inform overlap reasoning, but map to **no `PolicyRule` field** (the model has no
  condition field; deferred — see the deferrals note below).
- **Role-assignment constraints** (separation of duties) → **no `(role, scope)` rule** — they limit
  how users map to roles, which the `(role, scope, effect)` model cannot express (deferred).
- **Domain knowledge** → context that resolves references (role→domain membership, resource
  attributes) so the proposer/auditor can judge grants; it maps to no rule of its own.

**Policy-layer labeling.** `_policy_block()` labels the layers `BASELINE POLICY (grants only — never
a source of denials):` … then `SCENARIO POLICY:` …. The bundled `generic_policy.md` baseline is
**expressed in the digested-policy language** (as direct grants), still grants-only — an out-of-domain
pair stays a silent non-grant, never an explicit prohibition, so the baseline never contributes a DENY.

**Deny rules** (shared by proposer AND auditor — see share note below):

- **Direct-prohibition** trigger as in the deny-extraction callout above; a DENY comes only from the
  **scenario digested policy** (any pair) or the **focal entity's own** description (its own access) —
  a **candidate's** job-scope description is context, never a durable DENY; the **baseline** contributes
  grants only, and silence imposes nothing. **No exclusivity / "only" rule** — the digested language
  forbids exclusive language, so every prohibition is an explicit deny direct grant (see the design
  decision below).
- The two name lists (granted / denied) are **mutually exclusive except** when the policy genuinely
  establishes both a grant and a prohibition for the same candidate (direct conflict or coarse-scope)
  — that overlap is the **contradiction signal**, not a normal proposal.

On top of those, two shared **mapping** rules (`_MAPPING_RULES`) govern how evidence becomes a grant
or a deny:

- **Capability projection (Rule 3, symmetric)** — a scope names a *set* of operations. **Grant
  side:** any one covered operation established for a candidate grants the whole scope, so partial
  (e.g. read-only) access still earns it. **Deny side:** any one covered operation explicitly
  *prohibited* for a candidate denies the whole scope. A coarse scope that is **both** partly
  permitted and partly prohibited for the same pair legitimately lands in **both** lists → surfaced
  as a **contradiction** (a scope-granularity mismatch, not silently resolved).
- **Relationship scoping (Rule 4)** — a policy may state several access relationships over the same
  entities; each grant is judged only by evidence about *that* candidate and the focal entity, and a
  statement about an entity that is neither the focal nor a candidate (even a same-theme one) is a
  different relationship that never counts either way. With exclusivity removed, Rule 4 carries **no
  exceptions** — there is no longer a sanctioned cross-candidate inference (its former "only …"
  exception is gone, because a digested policy states each prohibition explicitly per pair).

No worked examples or domain heuristics; all substantive reasoning is deferred to the
(user-authored) policy content and the entity descriptions. The **proposer and auditor share the
same rule set** — both make the same grant/deny decision, so a rule on only one side lets the two
diverge (they did: see issue 3.20 *Follow-up: cross-variant convergence*). The auditor adds only its
framing: approve only if every granted pair is policy-supported and every denied pair is a genuine
explicit-prohibition deny — and, when `conflict_names` is present, adjudicate each as a genuine
contradiction (→ `contradictions`) vs a proposer generation error (→ ordinary rejection).
`build_proposer_messages` / `build_auditor_messages` carry both name sets (the auditor also gets
`conflict_names`).

**Deferrals.** Attribute invariants (→ rule conditions) and role-assignment constraints (separation
of duties) are **not** turned into rules here — neither is representable in the unchanged
`(role, scope, effect)` model. They are consumed as context / ignored for rule output, deferred until
the model supports them (attribute conditions) or a dedicated mechanism exists (SoD). Recorded so a
future reader does not mistake the omission for an oversight.

### LLM + retries

`ChatOpenAI(base_url=LLM_BASE_URL, model=LLM_MODEL, api_key=LLM_API_KEY, temperature=0,
max_retries=0, timeout=LLM_REQUEST_TIMEOUT)`. The client does **no** retries of its own
(`max_retries=0`); the `_structured_call` seam owns all LLM retry logic. Two retry layers stay
distinct:

- **`MAX_AUDIT_RETRIES`** (module constant, default `3`) — the semantic fix-and-retry loop
  between audit and propose. This is the **audit** budget. It is distinct from the LLM transport
  budget below.
- **LLM transport retries** — a single seam-level tenacity `Retrying` in `_structured_call`,
  driven by **dedicated LLM knobs** (not the shared `UPSTREAM_MAX_RETRIES`): `LLM_MAX_RETRIES`
  (default `3`), `LLM_RETRY_BACKOFF_MIN` (`1`) and `LLM_RETRY_BACKOFF_MAX` (`30`). `is_transient`
  classifies which failures retry (5xx / connect / timeout). `LLM_REQUEST_TIMEOUT` (default `120`)
  bounds each request. The Phase-1 file read does **not** retry; it raises directly.

`_structured_call` has two raise outcomes:

- **Transient failures exhausted** → raise `LLMAccessError` (502, **retryable**). It wraps the
  original error and sanitizes the message.
- **Reachable but the response is unparseable / schema-invalid** (a non-transient parse or
  validation error) → raise `UnparseableLLMResponseError` (502, **permanent**), sanitized.

See **Exceptions** for the full taxonomy and the HTTP-vs-retry-class decoupling.

---

## Contradiction contract

The policy model *assumes* no `(role, scope)` is ever both `ALLOW` and `DENY` for the same subject.
The PRB is the producer that must **guarantee** this — it must never pass a contradiction
downstream. Detection and reporting live here; the **treatment** of a reported contradiction (surface
to a human, partial-apply, re-author the policy, split the scope) is a **separate, deferred** task.

> **Collect-all diagnostic (folded into `/apply`).** The collect-all, quote-bearing form of that
> treatment — surveys a candidate policy, records **all** genuine conflicts at once (never aborting on
> the first), and returns a `ConflictReport` with verbatim quotes — is **folded into the `/apply` path**
> and returned as the HTTP `422` body on a genuine conflict ([identify conflicts, never reconcile](#design-decision-identify-conflicts-never-reconcile) / #2503).
> It reuses this module's proposer / precheck / audit machinery as a separate diagnostic assembly. The
> earlier standalone read-only `POST /policy/check` route is **retired**.

- **Detection is deterministic** (in `precheck`): `conflict_names = granted_names ∩ denied_names`,
  after candidate-set filtering. Precheck resolves nothing; it only stores the overlap. Because denies
  are now purely the explicit `denied_names`, overlap can arise **only** from a `denied_names` entry
  that also appears in `granted_names` — a direct policy conflict or a coarse-scope mismatch, exactly
  the genuine signal we want.
- **Adjudication is by the auditor** (three-way). For each name in `conflict_names` the auditor
  decides whether the policy **genuinely** both grants and prohibits it, or whether it's a proposer
  **generation error**:
  - **Genuine** → the audit node raises `PolicyContradictionError(focal, contradictions)`.
  - **Generation error** → treated as an ordinary rejection: feed the reason back, re-propose,
    reusing the shared `MAX_AUDIT_RETRIES` budget.
- **Report shape.** `PolicyContradictionError` carries `focal: str` and
  `contradictions: list[Contradiction]`, reporting **all** genuine contradictions in a **single**
  raise. **Any** genuine contradiction short-circuits past retry (retrying can't fix a real conflict;
  the call fails closed regardless). Generation errors are **never** reported (LLM noise, not a policy
  finding). The entry-point signature stays `-> list[PolicyRule]`; **the raise is the report**.
- **Fail-closed.** The focal entity's whole rule set is withheld (whether to salvage the
  non-conflicting rules is a treatment decision — deferred). A **genuine** `PolicyContradictionError`
  short-circuits past retry — retrying cannot fix a real conflict.
- **Multi-focal aggregation (UC1).** One PRB call raises for **one** focal entity. UC1's
  `ServicePolicyBuilder.build` iterates many focal entities, so it **aggregates** the per-focal
  `PolicyContradictionError`s into a single `PolicyConflictError` (`conflict_detection.py`) carrying
  a `ConflictReport`. That aggregated error is the multi-focal treatment — permanent, 422. It is
  raised by the UC1 builder, **not** by the graph. See the Controller / Service Policy Builder
  sub-PRD for the aggregation contract.
- **Bounded to the overlap signal.** The PRB is **not** hunting for every latent contradiction in the
  policy independently — only the grant/deny overlap it produced.
- **`Contradiction.description`** names the *kind* — direct policy conflict vs coarse-scope
  granularity mismatch — so the deferred treatment task knows whether to re-author policy or split the
  scope.

---

## Design decision: identify conflicts, never reconcile

**Governing principle.** When the assembled `PolicyRule`s for a service carry both
an `Allow` and a `Deny` on the same `(role, scope)` pair (a **conflict**), the
Policy Rules Builder **surfaces** it and refuses to apply — it never picks a
winner. We deliberately reject deny-overrides, allow-overrides, precedence
ordering, and silent merging: a conflict means the policy prose is genuinely
ambiguous, and resolving it in code would bury that ambiguity behind a rule the
author never stated. This is the engine-layer counterpart to the authoring-layer
conflict semantics in
[digested-policy.md](../../digested-policy.md#design-decision-authoring-vs-engine-conflict-semantics),
which explains why only the authoring layer may ever evolve past
identify-and-report.

### Consequences

- There is a **single entry point, `/apply`**: no conflict → rules are built and
  applied; conflict → an exception is raised and nothing is applied. A separate
  read-only `/policy/check` is **not** part of this model.
- Detection is a pure `(role.id, scope.id)` allow∩deny set-intersection over the
  assembled `list[PolicyRule]`, run **inside the build** before any compute/apply
  — so a conflict leaves persisted state untouched (atomic-by-construction).
- A found conflict is raised as a single `ConflictReport`-carrying exception and
  mapped to HTTP 422 with the structured report as the body.
- Scope is **within one service's build** (Q13). Cross-service conflicts — rules
  written by different `build()` calls colliding only in the persisted store —
  were originally left as a follow-up gap here; they are now detected (still
  identify-never-reconcile) — see the `#2504` addendum below.
- The intra-pass `PolicyContradictionError` (the LLM auditor's grant∩deny within
  one pass) is a separate, disjoint mechanism and keeps failing that pass closed;
  it is not merged into the cross-pass detector, only re-shaped to the same 422
  report body at the boundary (Q15).

### Addendum (#2503): verbatim-quoted reports on `/apply` — reversing handoff-07 Q15/Q16

Handoff 07 settled the on-`/apply` conflict report as **quote-less / no-LLM**:

- **Q15** ("Boundary unification") decided to *"unify the report shape, not the
  payload"* — one new structural exception carrying a `ConflictReport`, and
  mapping `PolicyContradictionError` to that shape *"(shallow, **no LLM**)"* at
  the 422 handler.
- **Q16** ("`Conflict.focal` for a structural conflict") anchored the structural
  conflict on the **SCOPE** side (`FocalType.SCOPE`) and, together with #2502's
  structural detector, produced each `Conflict` with **empty
  `granting_quotes`/`prohibiting_quotes` and `quotes_verified=False`** — a
  deterministic, LLM-free report.

**#2503 reverses the quote-less / no-LLM decision for the structural path.** The
`/apply` conflict report is now the **rich, verbatim-quoted** `ConflictReport`:
when — and **only when** — the deterministic `detect_conflicts` finds a structural
conflict, an LLM explain/quote pass (`conflict_enrichment.enrich_report`, reusing
the re-homed diagnostic `explain` machinery) runs over exactly the pairs the
detector surfaced, classifying each `kind` (`direct`/`coarse_scope`) and
extracting **substring-validated** quotes from the candidate policy text. A clean
apply stays fast and **LLM-free** (the explain seam never fires), so the gating —
not the report's fidelity — is what preserves handoff 07's performance intent.

Unchanged from handoff 07: the SCOPE-side focal anchoring (Q16), the identify-
never-reconcile principle above, and Q15's *shape* unification — both
`PolicyConflictError` (now enriched) and `PolicyContradictionError` (mapped
shallow, still **no LLM** at the boundary, `quotes_verified=false`) yield one 422
`ConflictReport` body. On any quote-validation failure the conflict is **kept**
with `quotes_verified=false` and a description fallback — never dropped.

### Addendum (#2504): cross-service conflicts are detected (closing the Q13 gap)

The Q13 consequence above scoped detection to **one service's build** and left
cross-service conflicts — an `Allow` in the current build colliding with a `Deny`
another service already persisted (or vice versa) on the same `(role.id,
scope.id)` — as a follow-up gap. `#2504` closes that gap **without** changing the
principle: still identify-never-reconcile, still no precedence/merge.

`ServicePolicyBuilder.build` now widens the detector's input to the **combined**
state — this build's assembled rules **plus** the already-applied inbound rules of
the other services that own the touched scopes, read from the Policy Store
(`applied_rules_for_scopes`). The **same** `#2502` `(role.id, scope.id)`
allow∩deny intersection then surfaces an overlap that a single build's own rules
could never reveal. The store read is **read-only** and the raise still happens
**before** `compute_and_apply`, so the atomic-by-construction guarantee holds: a
cross-service conflict leaves persisted state untouched. Detection stays
order-independent (keyed on ids), so tool-first vs agent-first onboarding yields
the identical outcome, and the result is emitted in the same 422 `ConflictReport`
shape. (The single-writer basis of "atomic-by-construction" is unchanged;
transactional safety across *concurrent* applies remains a separate follow-up.)

---

## Design decision: digested input retires exclusivity handling and Door B

**Governing principle.** The PRB now consumes only **digested** policy (#2540, epic #2537).
The digested-policy language (see
[digested-policy.md](../../digested-policy.md)) **forbids exclusive language ("only")** and
open-ended exceptions, requiring exclusivity to be restated at the authoring layer as **two explicit
direct grants** — an allow and a per-pair deny (*"Only technical personnel may access issues"* →
*"Technical personnel may access issues"* + *"Non-technical personnel may not access issues"*).
Because every prohibition therefore arrives as an **explicit** deny the proposer reads per pair, the
PRB **removes** its exclusivity machinery — the `grant_is_exclusive` / `access_is_exclusive` flags,
the `exclusive` state field, and the **derived-complement** deny path — and **deletes Door B**, the
user-role-focal deny-only pass whose sole purpose was deriving that complement.

### Why this is safe

- **Denies are not lost.** Door B (`build_role_denies` / the `deny_only` role graph, and the UC1
  builder's `RoleKind.USER` loop) existed because the scope-focal pass structurally could not infer a
  *role's* exclusivity (*"R may access only S"* → deny R on every other scope) — that is a
  cross-candidate inference Rule 4 forbids. In digested policy that same intent is stated as an
  **explicit** prohibition per pair (*"R may not access S2"*), which the scope-focal pass reads
  directly as a Rule-5 explicit-prohibition `DENY(R, S2)` when focal on `S2`. The role-focal
  derivation is thus redundant.
- **Gated on parity (two layers).** A silently dropped user-role deny would be a **broadening** of
  access — the failure mode this removal must guard against — so it is pinned twice. The
  **deterministic plumbing** (an explicit `(user_role, own_scope)` prohibition the proposer surfaces
  survives precheck and is built as a `DENY`) is a **hermetic unit test**
  (`test_graph.test_scope_focal_emits_user_role_deny_from_explicit_prohibition`) that fails a bare
  offline `pytest` if a precheck/build regression drops it. That the **prompt** actually elicits the
  deny from an explicit policy prohibition is verified end-to-end by the live-LLM
  `test_graph_live_llm.test_user_role_explicit_deny_captured_by_scope_focal_pass` (opt-in `-m llm`).
  A *prompt* regression is inherently only catchable in the live lane — no offline test can assert
  the LLM still emits the name — so the two layers are complementary, not redundant.
- **Durable user-role denies are policy-stated.** A durable user-role `DENY` must come from an
  **explicit prohibition in the (digested) policy** — the scope-focal pass reads it as a Rule-5
  policy prohibition on that `(user_role, scope)` pair. A prohibition left *only* in a user role's
  IdP **description** (a job-scope disclaimer such as *"works in issues, not source"*) is treated as
  a **silent non-grant** (deny-by-default), not a durable `DENY`: since user roles are only ever
  *candidates* (never focal) in the remaining passes, and a candidate's description is context (not a
  deny source — see the deny-extraction callout), such a disclaimer never becomes a durable
  prohibition. This is deliberate and matches the scenario model (`scenario_uc1` documents `devops`
  as deny-by-default with no pair-list entry; the denyworld scenario states every user-role deny in
  the *policy*, never relying on a description-only durable deny). It is a behavioral change from the
  pre-digested PRB, where Door B ran each user role **role-focal** and could turn its own
  description prohibition into a durable deny; under the digested model a prohibition that must be
  durable belongs in the policy, not a description.

### Description neutrality (precondition)

The "durable user-role denies are policy-stated" property above rests on a
**precondition**: an entity's IdP **description** (its *agentic role/scope*) and
the policy's own **domain-knowledge** roles/accesses (its *policy role/access*
definitions) state **identity, never authorization effect** — they carry no
approve/deny language. Allow/deny effect lives solely in the policy's grant/deny
statements. A prohibition left only in a description (e.g. *"works in issues, not
source"*) is therefore **malformed input**, not a lost deny — which is why
rossoctl/rossoctl#2562 resolves as *keep-as-is* rather than restoring a
role-focal user-role deny pass (that pass would derive a durable deny *from a
description*, precisely what the precondition forbids).

This leaves one **known asymmetry** with the deny-extraction rule above: a
*focal* entity's own description prohibition (e.g. an agent role *"does not manage
the issue tracker"*) still yields a durable `DENY`, while a *candidate* user
role's disclaimer is a non-grant. Under the neutrality precondition the focal
phrasing is *also* malformed input, so the focal-description deny path is the
anomaly. Per rossoctl/rossoctl#2562 the code is **left unchanged for now**;
enforcing the precondition (linting both namespaces) and making focal denies
policy-only are deferred to the neutrality-guard follow-up.

### Trade-off considered

The alternative was to *keep* Door B but strip it to explicit-denies-only (a conservative
belt-and-suspenders that re-emits the same denies the scope-focal pass produces, deduped by the PCE's
additive merge). It was rejected: it leaves a redundant LLM pass per user role and a code path whose
reason no longer exists. Removal is the honest end state, and the parity eval closes the only risk.

### Deferrals (not this issue)

- **Attribute invariants → conditions.** `PolicyRule` is `(role, scope, effect)` with no condition
  field, so attribute invariants are consumed as **context only** and map to no rule; conditions wait
  on a model change (see #2554).
- **Role-assignment constraints (separation of duties).** A `(user, role)` constraint is not
  expressible in the `(role, scope, effect)` model, so it produces **no rule**; a dedicated mechanism
  is out of scope here.

Both deferrals are recorded so the omission is not mistaken for an oversight. The `PolicyRule` /
`RuleEffect` model is **unchanged**, and the engine remains `identify-never-reconcile`.

---

## Testing

Two layers, distinguished by whether the LLM is real:

- **Mocked-boundary unit tests** (default `pytest`, no marker) — patch `graph._structured_call`
  (the sole LLM seam) and stub `graph.get_policy_source`, so no endpoint is touched. These pin the
  deterministic mechanics: candidate-set precheck/drop, `conflict_names` computation, the three-way
  audit route, explicit-deny extraction, and allows-then-denies rebuild order. They are the
  fast, hermetic regression net and must stay green with no environment.

- **Live-LLM verification tests** (new **`llm`** marker) — run the **real** LLM defined in the
  environment (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`) end-to-end through `build_role_rules` /
  `build_scope_rules`, and assert the emitted rule set matches the policy text. These verify the
  **prompt engineering itself** (that grants, direct-prohibition denies, and description-driven denies
  are extracted correctly from digested policy), which the mocked tests — feeding canned
  proposer output — cannot.
  - **Only the LLM is real.** Descriptions and policy are **mocked in-process**: inline `Role`/`Scope`
    objects carry the descriptions, and the `PolicySource` seam is stubbed to return an inline policy
    string. No Kubernetes, no Keycloak, no cluster — the `llm` marker gates on the three `LLM_*` vars
    only and **skips cleanly** when they are unset (same pattern as `require_env_or_skip`), so it never
    false-passes and never requires the integration stack.
  - **Assertion:** exact set equality of the emitted `(candidate_name, effect)` pairs against the
    hand-verified expected set for each fixture (not a subset check — an over- or under-grant fails).
  - **Fixture matrix** (minimal but representative): allow-only in **both** directions
    (`build_role_rules`, `build_scope_rules`); a **direct-prohibition** deny ("must not" / "read-only");
    a **description-driven** deny (a prohibition stated only in an entity description, e.g. "does not
    manage the issue tracker"); and an **explicit user-role deny** — the fixture that proves the
    scope-focal pass captures `(user_role, own_scope)` denies now that **Door B is removed** (see the
    design decision above). The former "only …" exclusivity fixture is **dropped** — digested policy
    carries no exclusive language, so there is no derived complement to assert. The **contradiction**
    path (`PolicyContradictionError`) is **excluded** — a real LLM's adjudication of a genuine
    grant/deny collision is non-deterministic and belongs to focused mocked tests.

The `llm` marker is registered in `pyproject.toml` alongside `integration`; unlike `integration` (which
needs the full onboarding stack), `llm` needs only an LLM endpoint. Both are deselected by the default
`-m "not integration"` unit run — the `llm` suite is opt-in via `-m llm` with the `LLM_*` env sourced.

**Faithfulness / parity gate (eval).** The corpus-level "digested output is unchanged or improved vs
prose" acceptance criterion lives in `eval/test_policy_pipeline_faithfulness.py`: it runs the PRB over
each scenario's **digested** policy and gates on **zero over-grants** (a digest that broadens access
fails). It is live-LLM, opt-in (`-m eval`, part of the Evaluation suite), and skips cleanly without
`LLM_*`. The additional **recall-floor** assertion (digested recall ≥ a committed per-scenario prose
baseline, so digestion + the rewritten prompts may not regress grant coverage) is planned in **#2541**
and is **not yet enforced** here.

---

## Use-case dispatch

| Use Case | Caller | Function(s) called |
|---|---|---|
| UC1 — Service Onboarding | Service Policy Builder sub-agent | `build_scope_rules(other_roles, scope)` per agent/tool scope + `build_role_rules(role, other_scopes)` per agent role (agent path only) |
| UC2 — Policy Update (Build) | Build sub-agent | TBD |
| UC3 — Role Update | Role sub-agent | `build_role_rules(role, all_scopes)` — one call |
| Conflict diagnostic (folded into `/apply`, [identify conflicts, never reconcile](#design-decision-identify-conflicts-never-reconcile) / #2503) | Apply path | A parallel diagnostic assembly reusing propose / precheck / audit (record-not-raise + a terminal `explain` node); returns a `422` `ConflictReport` |

> **Door B removed (#2540).** UC1 previously also ran a user-role-focal **deny-only** pass
> (`build_role_denies` over each `RoleKind.USER` candidate role, alongside the scope-focal pass) to
> derive user-role exclusivity denies. Under digested input that pass is redundant and has been
> deleted — the scope-focal pass reads the explicit per-pair denies directly. See
> [Design decision: digested input retires exclusivity handling and Door B](#design-decision-digested-input-retires-exclusivity-handling-and-door-b).

---

## Configuration

| Variable | Used for | Phase |
|---|---|---|
| `AIAC_POLICY_FILE` | Path to the whole-file access policy (default `/etc/aiac/policy.md`) | 1 |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | LLM calls | 1 |
| `LLM_REQUEST_TIMEOUT` | Per-request LLM timeout, in seconds (default `120`) | 1 |
| `LLM_MAX_RETRIES` | Transient-failure retry budget for the LLM seam (tenacity `stop_after_attempt`, default `3`) | 1 |
| `LLM_RETRY_BACKOFF_MIN` | Minimum exponential backoff for the LLM seam, in seconds (default `1`) | 1 |
| `LLM_RETRY_BACKOFF_MAX` | Maximum exponential backoff for the LLM seam, in seconds (default `30`) | 1 |
| `UPSTREAM_MAX_RETRIES` | Transport retry budget for ChromaDB calls (tenacity, default `3`). **Superseded for the LLM seam** by the dedicated `LLM_*` knobs above | 2 |
| `AIAC_CHROMADB_URL` | ChromaDB endpoint | 2 |
| `CHROMA_N_RESULTS` | Number of results per ChromaDB query (default `10`) | 2 |

`MAX_AUDIT_RETRIES` (default `3`) is a module constant, not an env var.

The three `LLM_*` retry knobs **replace** the shared `UPSTREAM_MAX_RETRIES` for the LLM seam. They
are named **identically** to the agent spec, so one set of values configures both.
