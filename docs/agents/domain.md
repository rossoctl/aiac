# Domain Docs

How the engineering skills should consume this repo's domain documentation
when exploring the codebase. This is scoped to `aiac/` — treated as its own
single context, separate from other components in the `cortex` monorepo (e.g.
`authbridge/`).

## Before exploring, read this

- **`CONTEXT.md`** at the `aiac/` root (this directory).

If it doesn't exist, **proceed silently**. Don't flag its absence; don't suggest
creating it upfront. The producer skill (`/grill-with-docs`) creates it lazily
when terms actually get resolved.

## Design decisions — consult on demand, not up front

Design decisions are documented as a **"Design decision: …" section in the
relevant PRD/spec** under `docs/specs/`, co-located with the feature they govern.
There is no separate decision log — a decision worth recording is worth recording
where its feature lives. Record one when it is **hard to reverse**, **surprising
without context**, and **the result of a real trade-off**; otherwise leave it out.

**Do not read decisions up front.** Consult only the one that touches the area you
are about to work in — follow the reference from the PRD/spec you are already
reading. This keeps decisions for unrelated features out of your context.

## File structure

```
aiac/
├── CONTEXT.md
├── docs/
│   ├── specs/          ← PRD.md + components/ (see CLAUDE.md); design decisions live embedded here
│   └── agents/         ← this file and its siblings
└── src/aiac/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor
proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`.
Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either
you're inventing language the project doesn't use (reconsider) or there's a
real gap (note it for `/grill-with-docs`).

## Flag decision conflicts

If your output contradicts an existing design decision — a "Design decision: …"
section in a PRD/spec — surface it explicitly rather than silently overriding:

> _Contradicts "identify conflicts, never reconcile" in policy-rules-builder.md —
> but worth reopening because…_

## Relationship to `docs/specs/`

`aiac/CLAUDE.md` already documents `docs/specs/PRD.md` and
`docs/specs/components/` as the requirements source, with a link-following
policy for cross-references. `CONTEXT.md` is a different layer — domain
vocabulary, not requirements. Design decisions live **embedded in** the relevant
PRD/spec (a "Design decision: …" section); reading them still follows the
`docs/specs/` link-following policy.
