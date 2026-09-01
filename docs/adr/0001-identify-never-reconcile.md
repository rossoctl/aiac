# Identify policy conflicts; never reconcile them

When the assembled PolicyRules for a service carry both an `Allow` and a `Deny`
on the same `(role, scope)` pair (a **conflict**), the Policy Rules Builder
**surfaces** it and refuses to apply — it never picks a winner. We deliberately
reject deny-overrides, allow-overrides, precedence ordering, and silent merging:
a conflict means the policy prose is genuinely ambiguous, and resolving it in
code would bury that ambiguity behind a rule the author never stated.

## Status

accepted

## Consequences

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
  are a pre-existing gap left as a follow-up, not reconciled here.
- The intra-pass `PolicyContradictionError` (the LLM auditor's grant∩deny within
  one pass) is a separate, disjoint mechanism and keeps failing that pass closed;
  it is not merged into the cross-pass detector, only re-shaped to the same 422
  report body at the boundary (Q15).

## Addendum (#2503): verbatim-quoted reports on /apply — reversing handoff-07 Q15/Q16

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
