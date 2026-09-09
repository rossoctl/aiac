# Authoring-layer vs engine-layer conflict semantics

The digested-policy spec (`docs/specs/digested-policy.md`) and the AIAC rule
engine (`docs/adr/0001-identify-never-reconcile.md`) both detect contradictions,
and **today both behave identically** — identify the contradiction, surface it,
apply nothing. This ADR records why they are nonetheless two distinct layers: the
**authoring layer** is the only one that may ever evolve past identify-and-report
to *resolve* conflicts (for example, by deny-overrides), while the **engine layer**
must remain `identify-never-reconcile` permanently. The distinction is an
asymmetry of *permitted future evolution*, not a difference in current behaviour.

The reason is **who owns the intent, and over what scope**:

- An **authoring-layer conflict** lives *within a single digested policy* — one
  authored artifact, one author. A combining rule like deny-overrides is itself a
  statement of that author's intent, so resolving an opposite-effect grant
  overlap by "deny wins" would honour a rule the author could legitimately state.
  Resolution here is therefore *conceivable* — reserved as future work rather
  than adopted, but conceivable.

- An **engine-layer Conflict** lives *across* independently authored sources and
  Policy Rules Builder passes (within-batch Door B, and cross-service) — an
  `Allow` from one pass and a `Deny` from another on the same `(role, scope)`
  pair. No single author ever stated how those pieces combine. Picking a winner
  there would, in ADR-0001's words, "bury that ambiguity behind a rule the author
  never stated." Resolution here is never legitimate.

So the same refuse-and-report behaviour that both layers show today rests on
different foundations: the engine refuses because reconciling un-authored
collisions would fabricate intent, and it always will; the authoring layer
refuses because we have not *yet* built the authored combining rule that would
let it resolve. A well-formed (conflict-free) digested policy is reported clean
before it is compiled to `PolicyRule`s, so it never itself produces an
engine-layer Conflict; the engine's detection then guards only the cross-source
collisions the authoring layer cannot see.

## Status

accepted

## Consequences

- The digested-policy spec's **Conflict resolution** section is deliberately a
  *reserved-future* section, not an unfinished one: it states a definite
  report-only decision for today and names deny-overrides as the reserved
  direction. It is complete.
- Any future deny-overrides (or other combining rule) is authored and applied
  **within the digest**, upstream of rule compilation — never in the engine, and
  never as a cross-source precedence. ADR-0001's `identify-never-reconcile` for
  the engine is unchanged and unaffected by this reservation.
- "Conflict" without qualification continues to mean the **engine-layer**
  `(role, scope)` collision (see `CONTEXT.md`). The within-policy notion is always
  written **authoring-layer conflict** to keep the two from being confused.
