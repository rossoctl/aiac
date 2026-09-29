# Triage Labels (AIAC)

Repo-local mapping for the `triage` and `close-issue` skills. It overrides the
global default (`~/.claude/docs/agents/triage-labels.md`), which assumes
unprefixed labels. **This repo prefixes every state label with `status:`.**

Each state is recorded in **two places**, and both must be updated together:

1. The `status:<role>` issue label — `gh issue edit <n> -R rossoctl/aiac --remove-label "<old>" --add-label "<new>"`.
2. The **`Triage Status`** single-select field on Project board **#12**
   (`rossoctl`). This is a custom field (id `PVTSSF_lADODC4bxc4Bi_vFzhh1vWg`),
   **not** the board's built-in `Status` field, which is unused. `gh issue edit`
   does not move it — see `docs/agents/issue-tracker.md` → "Project board" for
   the `gh project item-edit` command and how to discover the option ids.

## State roles

| Canonical role    | Issue label              | `Triage Status` option | Meaning                                 |
| ----------------- | ------------------------ | ---------------------- | --------------------------------------- |
| `needs-triage`    | `status:needs-triage`    | `needs-triage`         | Maintainer needs to evaluate this issue |
| `needs-info`      | `status:needs-info`      | `needs-info`           | Waiting on reporter for more information |
| `ready-for-agent` | `status:ready-for-agent` | `ready-for-agent`      | Fully specified, ready for an AFK agent |
| `ready-for-human` | `status:ready-for-human` | `ready-for-human`      | Requires human implementation           |
| `wontfix`         | `status:wontfix`         | `wontfix`              | Will not be actioned                    |

Board-only extras beyond the five canonical roles:

| Value      | Issue label        | `Triage Status` option | Use                                               |
| ---------- | ------------------ | ---------------------- | ------------------------------------------------- |
| `blocked`  | `status:blocked`   | `blocked`              | Waiting on another issue                          |
| `deferred` | `status:deferred`  | `deferred`             | Parked; not in the current plan                   |
| `resolved` | `status:resolved`  | `resolved`             | **Terminal** — completed work (`close-issue` default) |

`status:needs-triage` does not exist yet on `rossoctl/aiac`. Create it the first
time it is needed: `gh label create status:needs-triage -R rossoctl/aiac`.

## Terminal values (for `close-issue`)

- Completed work → `status:resolved` + `Triage Status` = `resolved`.
- Closed as won't-do → `status:wontfix` + `Triage Status` = `wontfix`.

## Category roles

| Canonical role | Issue label   |
| -------------- | ------------- |
| `bug`          | `bug`         |
| `enhancement`  | `enhancement` |

A plain `wontfix` label also exists (GitHub default). Use `status:wontfix`
instead so the state stays in the `status:` family.
