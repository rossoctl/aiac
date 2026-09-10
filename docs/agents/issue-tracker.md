# Issue tracker: GitHub (AIAC convention)

Issues live as GitHub issues in this repo's own remote, **`rossoctl/aiac`**,
filtered by the `aiac` label. Use the `gh` CLI for all operations:
repository-scoped issue and label commands take `-R rossoctl/aiac`, while
Projects commands are account-scoped — they take `--owner rossoctl` (and
`--project-id` for item updates), and need the `project` scope on the token
(`gh auth refresh -s project`).

This file exists so the engineering skills (`to-tickets`, `to-spec`, and
`triage` when installed) have a single place to read the convention from.

> **Migration note (2026-09-09).** The `aiac`-labelled issues were migrated here
> from `s-and-p-team/cortex`. GitHub cannot transfer issues across orgs, so they
> were **copied** (authored by the migrating account, dated at copy time, with a
> provenance line linking each copy back to its `cortex` original); the originals
> in `cortex` were then closed with pointer comments. Issue numbers changed on
> copy, so `#NNN` cross-references in the migrated bodies/titles were rewritten to
> the new numbers. Full-URL links back to `cortex` were left intact.

## Conventions

- **Create an issue**: `gh issue create -R rossoctl/aiac --title "..." --body "..." --label aiac`.
  Use a heredoc for multi-line bodies. Always include the `aiac` label plus the
  relevant cumulative `area:<path>` label(s) for the component being touched.
  Create a missing `area:<path>` label lazily with
  `gh label create area:<path> -R rossoctl/aiac` the first time a component area
  comes up.
- **Read an issue**: `gh issue view <number> -R rossoctl/aiac --comments`.
- **List issues**: `gh issue list -R rossoctl/aiac --label aiac --state all`,
  narrowing with additional `--label area:<path>` filters as needed.
- **Comment on an issue**: `gh issue comment <number> -R rossoctl/aiac --body "..."`.
- **Apply / remove labels**: `gh issue edit <number> -R rossoctl/aiac --add-label "..."` / `--remove-label "..."`.
- **Close**: `gh issue close <number> -R rossoctl/aiac --comment "..."`.

## Hierarchy

Issues are filtered by `aiac` + cumulative `area:<path>` labels. Use native
sub-issues for container/leaf structure: a `Feature:`-prefixed umbrella issue
with `Task:`-prefixed children linked as native sub-issues. (`Feature`/`Task`
are a **title-prefix** convention — native GitHub *issue types* are not set, so
`issueType` reads `null`.) Set a child's parent with
`gh issue edit <child> -R rossoctl/aiac --parent <umbrella>`.

## Project board

The board is the org-level Project **AIAC**, project number **`12`** on the
`rossoctl` owner (id `PVT_kwDODC4bxc4Bi_vF`) —
<https://github.com/orgs/rossoctl/projects/12>. Note `rossoctl` also has a
separate, older **AIAC** Project **#11**, which is *not* this board; always
address the board by number `12` (its title alone is ambiguous). When you file
or update an `aiac` issue, add it to the board and set its status:

- **Add to the board**: `gh project item-add 12 --owner rossoctl --url <issue-url>`
  (returns the item id; requires the `project` OAuth scope).
- **Set the status**: the migrated triage state lives on a **custom
  single-select field named `Triage Status`** (field id
  `PVTSSF_lADODC4bxc4Bi_vFzhh1vWg`), **not** the board's built-in `Status` field
  (which is left unused / auto-driven by open-closed). Set it with
  `gh project item-edit --project-id PVT_kwDODC4bxc4Bi_vF --id <item-id>
  --field-id PVTSSF_lADODC4bxc4Bi_vFzhh1vWg --single-select-option-id <option-id>`.
  Discover item and option ids with
  `gh project item-list 12 --owner rossoctl --format json --limit 300` and
  `gh project field-list 12 --owner rossoctl --format json`.

The `Triage Status` field options are `needs-triage`, `needs-info`,
`ready-for-agent`, `ready-for-human`, `blocked`, `deferred`, `resolved`,
`wontfix`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue on `rossoctl/aiac` with the `aiac` label and the
appropriate `area:<path>` label(s).

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> -R rossoctl/aiac --comments`.

## When a skill mentions triage roles

The five canonical roles (`needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`) map to **both** a `status:<role>` issue label
**and** the matching option on the board's `Triage Status` field (see Project
board above); the board adds `blocked` / `deferred` / `resolved` beyond the five.
Apply the `status:<role>` label with `gh issue edit` and set the `Triage Status`
field to the same value. There is no `docs/agents/triage-labels.md` (the `triage`
skill is not installed here) — this section is the mapping.

Filtered web list:
<https://github.com/rossoctl/aiac/issues?q=is%3Aissue+label%3Aaiac>
