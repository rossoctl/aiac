# Domain Docs

How the engineering skills should consume this repo's domain documentation
when exploring the codebase. The repo (`rossoctl/aiac`) is a single context.

## Before exploring, read this

- **`CONTEXT.md`** at the repo root.

**Gotcha — the file names differ from the skills' defaults.** The engineering
skills (mattpocock-skills 1.3 and later, including `domain-modeling` and the
user-invoked `/grill-with-docs`) call the glossary `GLOSSARY.md` and record
decisions under `docs/adr/`. This repo does not. Wherever a skill says
`GLOSSARY.md`, read and edit `CONTEXT.md`; wherever it says ADR, record a
"Design decision: …" section in the relevant spec (next section). Never create
`GLOSSARY.md` or `docs/adr/`.

## Design decisions — consult on demand, not up front

Design decisions are documented as a **"Design decision: …" section in the
relevant PRD/spec** under `docs/specs/`, co-located with the feature they govern.
There is no separate decision log — a decision worth recording is worth recording
where its feature lives. Record one when it is **hard to reverse**, **surprising
without context**, and **the result of a real trade-off**; otherwise leave it out.

**Do not read decisions up front.** Consult only the one that touches the area you
are about to work in — follow the reference from the PRD/spec you are already
reading. This keeps decisions for unrelated features out of your context.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor
proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`.
Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either
you're inventing language the project doesn't use (reconsider) or there's a
real gap (resolve it with the `domain-modeling` skill).

## Flag decision conflicts

If your output contradicts an existing design decision — a "Design decision: …"
section in a PRD/spec — surface it explicitly rather than silently overriding:

> _Contradicts "identify conflicts, never reconcile" in policy-rules-builder.md —
> but worth reopening because…_

## Relationship to `docs/specs/`

`CLAUDE.md` documents `docs/specs/PRD.md` and `docs/specs/components/` as the
requirements source. `CONTEXT.md` is a different layer — domain vocabulary, not
requirements.
