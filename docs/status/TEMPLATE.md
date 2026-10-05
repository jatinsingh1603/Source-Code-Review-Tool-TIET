<!--
Status note template. Owning epic: E42 (issue E42-03).

How to use
1. Copy this file to docs/status/YYYY-MM-DD-sprint-NN.md. The date is the last day of the sprint
   (a Sunday) and NN is the two-digit sprint number, for example 2026-09-27-sprint-01.md. Sprint
   dates are in docs/process/sprint-cadence.md.
2. Keep the seven H2 headings, their order and the columns of the milestone table exactly as
   they are: tools/status_report.py (E42-04) finds sections by them.
3. The regions between "milestone:auto-start" and "milestone:auto-end" and between
   "metrics:auto-start" and "metrics:auto-end" are filled by the tool. Text outside them is
   written by hand and is left alone by the tool.
4. State and overall status use the vocabulary ON_TRACK, AT_RISK, OFF_TRACK, the same as the
   status updates of the project board.
5. Delete this comment in the copy.
-->
# Status note: Sprint NN

## Sprint

| Item | Value |
|------|-------|
| Sprint | Sprint NN |
| Dates | YYYY-MM-DD (Monday) to YYYY-MM-DD (Sunday) |
| Milestone in focus | Milestone title as in `docs/PLAN.md` section 5 |
| Written by | Name |
| Written on | YYYY-MM-DD |

## Milestone status

<!-- milestone:auto-start -->
| Milestone | Due | Open | Closed | Percent | State |
|-----------|-----|------|--------|---------|-------|
| M0 Foundations | 2026-09-27 | 0 | 0 | 0% | ON_TRACK |
<!-- milestone:auto-end -->

State is one of ON_TRACK, AT_RISK, OFF_TRACK. Open and Closed count the issues of the milestone at the end of the sprint; Percent is Closed divided by their sum.

## Highlights

- What was finished, in terms a reader outside the team can follow.

## Metrics

<!-- metrics:auto-start -->
| Metric | Value |
|--------|-------|
| Issues closed in the sprint | 0 |
| Points closed in the sprint | 0 |
| Velocity (mean points closed per sprint so far) | 0 |
<!-- metrics:auto-end -->

Points per Size: XS=1, S=2, M=5, L=8. An XL issue has no point value; it is split before it is planned (`AGENTS.md` section 2).

## Risks and blockers

- The top three open risks of [`risk-log.md`](risk-log.md) by likelihood times impact, one line each (`docs/process/risk-review.md`).
- Risks that changed this sprint, with the row of the risk register (`docs/PLAN.md` section 8) they belong to.
- Blockers: `needs-human` issues and anything waiting on a decision, a key or an account.

## Next sprint

- The issues planned for the next sprint, in the order of work of `docs/PLAN.md` section 7.

## Overall status

ON_TRACK, AT_RISK or OFF_TRACK, followed by one sentence that says why.
