# AIAC

The AIAC agent turns natural-language authorization policy into applied
PolicyRules. It surveys IdP roles and scopes, drives an LLM-backed Policy Rules
Builder over focal entities, and computes/applies the resulting rules through a
two-layer policy stack. This glossary fixes the vocabulary for how the builder
grants, prohibits, and reports collisions.

## Language

**Focal entity**:
The single role or scope a Policy Rules Builder pass is centred on for one
`build()` run. Every pass fans candidates against exactly one focal per run.
_Avoid_: subject, principal, target.

**Scope-focal pass**:
The pass centred on a scope, fanning candidate roles over it. It is the sole
**grant authority** for that scope.
_Avoid_: scope pass, forward pass.

**User-role-focal pass** (a.k.a. **Door B**) — _retired (#2540)_:
Formerly a pass centred on a `kind=User` role, fanning it over the focus
service's own scopes to emit the **deny** rules a user's exclusivity ("Testers
may access **only** issues") implied — prohibitions the scope-focal pass
structurally could not express. **Removed** once the PRB consumes only
**digested** policy: the digested language bans "only" and states each
prohibition as an explicit per-pair deny, which the scope-focal pass reads
directly, so the derivation is redundant. Retained here only because the term
appears in git history. See the PRB spec's _digested input retires exclusivity
handling and Door B_ decision.
_Avoid_: role pass (ambiguous with the agent-role-focal pass), Door B pass.

**Grant authority**:
The property that grants on a given scope come from exactly one place — the
scope-focal pass.
_Avoid_: owner, source of truth.

**Contradiction**:
An _intra-pass_ grant∩deny: one focal's own proposed rule set both grants and
prohibits the same candidate. Detected by the LLM auditor within a single pass,
which fails that pass closed. Modelled by `Contradiction` / raised as
`PolicyContradictionError`.
_Avoid_: using "conflict" for this — the two are distinct.

**Conflict**:
A _cross-pass_ grant∩deny: an `Allow` from one pass and a `Deny` from another on
the **same `(role, scope)`** pair. Structural (a pure id-level allow∩deny
set-intersection over the assembled rules), not LLM-audited. Modelled by
`Conflict` / `ConflictReport`.
_Avoid_: using "contradiction" for this.

**Within-batch conflict**:
A **conflict** whose two rules are produced in one `build()` call — i.e. one
`/apply` request. At the focus service's own-scope onboarding the scope-focal
pass emits both grants and explicit per-pair denies over those scopes, so a
grant and a deny colliding on the same `(role, scope)` are in hand in the same
build. In scope. (Formerly the Door B case, before that pass was retired — see
**User-role-focal pass**.)
_Avoid_: intra-request conflict.

**Cross-run conflict** (a.k.a. **cross-service conflict**):
A **conflict** whose two rules are produced in separate onboarding requests and
collide only in the persisted SPM store. Surfaced at `/apply` by the
cross-service check, which reads the already-applied rules of the services that
own the touched scopes and folds them into detection; the pure within-build
structural pass alone does not see it.
_Avoid_: cross-request conflict, store conflict.

**Identify-never-reconcile**:
The governing principle: a `(role, scope)` carrying both an `Allow` and a `Deny`
**is** a conflict — surface it, never resolve it. No precedence, no
"deny wins," no merge. See the engine-layer design decision
[identify conflicts, never reconcile](docs/specs/components/aiac-agent/policy-rules-builder.md#design-decision-identify-conflicts-never-reconcile).
_Avoid_: deny-overrides, conflict resolution.

**Source policy**:
The original human-authored authorization policy as provided — free
natural-language prose (e.g. the text held in the RAG knowledge base). The raw
input a digest is derived from.
_Avoid_: raw policy, input policy.

**Digested policy**:
A structured restatement of a source policy's intent in the digested-policy
language — domain knowledge plus three statement kinds (direct grants, attribute
invariants, role-assignment constraints). An authoring-layer artifact, upstream
of the engine's `PolicyRule`s. See `docs/specs/digested-policy.md`.
_Avoid_: parsed policy, normalized policy.

**Policy Digester**:
The LLM-backed conversion that rewrites a **source policy** into a **digested
policy**, guided by the digested-policy spec. It is _pure conversion_ — it
produces the digest and nothing else. Reading the source, storing the digest, and
detecting authoring-layer conflicts belong to other components, not the digester.
_Avoid_: converter, normalizer, parser, digest step.

**Faithfulness**:
The invariant a digest must uphold: it neither **adds**, **drops**, nor
**broadens** access relative to its source policy. A faithful digest yields
exactly the access its source granted — never more. Guarded by comparing the
rules the engine derives from a digest against the source's known-correct rule
set.
_Avoid_: correctness, accuracy, fidelity.

**Authoring-layer conflict**:
Two direct grants _within one digested policy_ with opposite effect whose
subjects, operations, and resources overlap. Distinct from the engine-level
**Conflict** (a cross-pass `(role, scope)` allow∩deny): this is among a digested
policy's own statements, before it becomes `PolicyRule`s. Currently reported,
never auto-resolved — deny-overrides reserved (see
[Design decision: authoring vs engine conflict semantics](docs/specs/digested-policy.md#design-decision-authoring-vs-engine-conflict-semantics)).
_Avoid_: using unqualified "Conflict" for this.

**Agentic role/scope** (a.k.a. **system role/scope**):
The identity an IdP role or scope carries in the running system — what a tool or
agent *is* or *does* — as stated in its IdP **description**. A **neutral
definition**: it names capability and domain, never authorization effect. The
PRB reads these descriptions as grant / context signals, but the allow/deny
*effect* comes from the policy, never from the description.
_Avoid_: permission, entitlement; calling the description itself a grant or deny.

**Policy role/access**:
A role or access category the **policy** defines in its own **domain-knowledge**
section (see **Digested policy**) — e.g. "technical personnel", "customer-facing".
Distinct from an **agentic role/scope**: a concept the policy reasons over, not an
IdP object. Also a **neutral definition** — domain knowledge describes what these
roles/accesses *are*; whether a subject may or may not do something lives only in
the policy's **direct grants**.
_Avoid_: conflating with agentic role/scope; encoding effect in the definition.

**Neutral definition** (a.k.a. **description neutrality**):
The precondition that any _definition_ — an **agentic role/scope** description or
a **policy role/access** in domain knowledge — states **identity, never effect**:
it must not carry approve/deny language ("approves", "denies", and the like).
Authorization effect lives solely in the policy's grant/deny **statements**. A
definition that leaks effect (e.g. a role described *"works in issues, not
source"*) is **malformed input**, not a deny source — which is why a
description-only prohibition yields no durable DENY (see the PRB spec's _digested
input retires exclusivity handling and Door B_ decision). Enforcement is tracked
in the neutrality-guard follow-up (`rossoctl/aiac`).
_Avoid_: description-driven deny, effect-in-description.
