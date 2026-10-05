# Sprint cadence and way of working

Owning epic: E42 (issue E42-01).

This is the runbook for one sprint. It turns the rules of `docs/PLAN.md` section 7 and `AGENTS.md` into steps, and it uses the names of the project board as they are recorded in `tools/project/board.json`. Where this page and those documents disagree, they win; correct this page.

The [project board](https://github.com/users/jatinsingh1603/projects/1) is the single source of truth for what is being worked on.

## 1. Sprint calendar

A sprint is one week, Monday to Sunday. The board's `Sprint` field has thirteen iterations.

| Sprint | Starts (Monday) | Ends (Sunday) | Milestone due in this sprint |
|--------|-----------------|---------------|------------------------------|
| Sprint 1 | 2026-09-21 | 2026-09-27 | M0 Foundations (2026-09-27) |
| Sprint 2 | 2026-09-28 | 2026-10-04 | |
| Sprint 3 | 2026-10-05 | 2026-10-11 | M1 Privacy layer MVP + Demo 1 (2026-10-05) |
| Sprint 4 | 2026-10-12 | 2026-10-18 | |
| Sprint 5 | 2026-10-19 | 2026-10-25 | |
| Sprint 6 | 2026-10-26 | 2026-11-01 | M2 Detection engine (2026-10-26) |
| Sprint 7 | 2026-11-02 | 2026-11-08 | M3 LLM reasoning (2026-11-02) |
| Sprint 8 | 2026-11-09 | 2026-11-15 | M4 Privacy hardening (2026-11-09) |
| Sprint 9 | 2026-11-16 | 2026-11-22 | |
| Sprint 10 | 2026-11-23 | 2026-11-29 | M5 Audit reporting (2026-11-23) |
| Sprint 11 | 2026-11-30 | 2026-12-06 | |
| Sprint 12 | 2026-12-07 | 2026-12-13 | M6 Platforms (2026-12-07) |
| Sprint 13 | 2026-12-14 | 2026-12-20 | M7 Evaluation and paper (2026-12-14) |

M8 Hardening and release is due on 2026-12-21, the day after the last iteration ends. Milestone titles and due dates are those of `docs/PLAN.md` section 5.

## 2. Board fields

| Field | Values | Needed before a card leaves Backlog |
|-------|--------|-------------------------------------|
| Priority | `P0-critical`, `P1-high`, `P2-medium`, `P3-low` | Yes |
| Size | `XS`, `S`, `M`, `L`, `XL` | Yes |
| Epic | One option per epic, for example `E01 Scaffolding and DX` | Yes |
| Milestone | The issue's GitHub milestone, for example `M0 Foundations` | Yes |
| Sprint | `Sprint 1` to `Sprint 13` | No; set at sprint planning, before the card moves to In progress |

Priority, Size and Epic mirror the issue's labels (`P1-high`, `size:S`, `area:...`) and the `Epic:` line at the foot of the issue body. If a label and a field disagree, fix the field to match the issue.

## 3. Columns

The `Status` field has five options. A card moves one column at a time.

| Column | A card enters when | A card may leave when |
|--------|--------------------|-----------------------|
| Backlog | The issue exists with the standard sections (context, goal, tasks, acceptance criteria, tests, dependencies) and is on the board. | Backlog -> Ready: Priority, Size, Epic and Milestone are set, and the issue meets the Definition of Ready ([`definition-of-ready.md`](definition-of-ready.md), written by E42-02). An issue that needs a decision, a key or an account is labelled `needs-human` and stays here until the question is answered. |
| Ready | The Backlog exit conditions hold. | Ready -> In progress: assignee set, Size and Priority set, Sprint set to the current sprint, all Blocked by issues closed. One card per person in In progress. |
| In progress | Someone has assigned themselves and started. | In progress -> In review: the work is pushed to `main` in small commits that reference the issue, with its tests, and the local checks of `AGENTS.md` section 9 have passed. |
| In review | The work is on `main` and waits for CI and the closing checks. | In review -> Done: CI is green, the acceptance-criteria boxes are ticked and the closing comment of `AGENTS.md` section 6 is posted. If CI is red or a criterion is not met, the card goes back to In progress. |
| Done | The issue is closed and the Definition of Done holds (`AGENTS.md` section 7, `docs/PLAN.md` section 7). | It does not leave. A reopened issue goes back to In progress with a comment that says why. |

An issue that turns out to be larger than its Size is split: the follow-up issues get the same structure, are linked, and start in Backlog.

## 4. Weekly rhythm

| When | What | Output |
|------|------|--------|
| Monday | **Sprint planning.** Work in the earliest open milestone. Take cards from Ready in the order of work of `docs/PLAN.md` section 7: the lowest-numbered open issue whose blockers are all closed, `P0-critical` before `P1-high` (`AGENTS.md` section 2). Set Sprint on each card taken and check that the total Size fits the week. | Cards for the week have Sprint set and an assignee. |
| Wednesday | **Mid-sprint check.** Look at In progress and In review: anything older than two days, anything blocked, any card whose Size was wrong. Split or re-plan; move cards that will not finish back to Ready and clear their Sprint. | The board matches reality. |
| Sunday | **End of sprint.** Write the status note in `docs/status/` (format and first note: E42-03) and review the risk register of `docs/PLAN.md` section 8 (ritual: E42-07). Cards still open keep their column; their Sprint is set again at the next planning. | One status note per sprint for the supervisor. |

Outside these three points the board is updated as work happens: move the card when you start, when you push and when you close.

## 5. Roles

| Role | Does | Who |
|------|------|-----|
| Planning lead | Runs sprint planning and the mid-sprint check | To be named (E42-09) |
| Status-note author | Writes the end-of-sprint note in `docs/status/` | To be named (E42-09) |
| Board owner | Keeps fields, options and iterations in step with `tools/project/board.json`; regenerates that file when the board changes | To be named (E42-09) |
| Supervisor contact | Receives the status note and attends demos | To be named (E42-09) |

Until E42-09 names people, whoever closes the last issue of the week writes the note.

## 6. Related pages

- Definition of Done: `AGENTS.md` section 7 and `docs/PLAN.md` section 7.
- Choosing and closing an issue: `AGENTS.md` sections 2 and 6.
- Board coordinates: `tools/project/README.md`.
- Other process guides: [`testing.md`](testing.md), [`cli-snapshots.md`](cli-snapshots.md).
