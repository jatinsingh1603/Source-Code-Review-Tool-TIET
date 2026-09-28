# Architecture decision records

An architecture decision record (ADR) captures one significant decision: the problem, the options considered, the choice and its consequences. With many contributors and coding agents working without shared conversation history, ADRs are the durable memory of why the system is the way it is. `docs/ARCHITECTURE.md` is normative and changes only through an ADR.

## When an ADR is required

Write an ADR when a change:

- alters `docs/ARCHITECTURE.md`;
- adds, removes or renames a package;
- touches a privacy invariant (I1 to I6) or an import contract;
- adds an outbound network destination;
- adds a runtime dependency with a licence other than MIT, BSD, Apache-2.0, ISC or PSF;
- reverses an earlier ADR.

An ADR is not required for ordinary implementation choices inside a package.

## Lifecycle and status values

| Status | Meaning |
|--------|---------|
| Reserved | Number held for an issue that will write the record; no file yet |
| Proposed | File exists and is under discussion |
| Accepted | Decision in force; the decision text is now immutable |
| Superseded by ADR-XXXX | Replaced by a later record |
| Rejected | Considered and not adopted; kept for the record |

Once a record is `Accepted`, only two things may change: its status line, and the optional final section `Implementation notes`, which implementing issues may extend with facts (tables, file names, test names) that do not alter the decision. To change a decision, write a new ADR that supersedes the old one, update the status line of both records, and update this index.

Every record has a "Privacy impact" section stating whether invariants I1 to I6 are strengthened, unchanged or weakened, and why. It may not be left empty.

## Numbering and creating a record

Files are named `NNNN-kebab-case-title.md`: four digits, zero padded, then a slug of the title (lower-case ASCII letters and digits joined by single hyphens, at most 60 characters). Numbers are never reused. Create a record with the helper, which picks the next free number (skipping reserved ones), copies `0000-template.md`, fills in number, title and date, and adds a row below:

```bash
uv run python tools/dev/new_adr.py "Title of decision"
```

If the title matches a `Reserved` row, the helper uses that number and changes the row to `Proposed`. `uv run python tools/dev/new_adr.py --check` verifies that this index and the record files agree.

## Index

| Number | Title | Status | Date | Supersedes | Issue |
|--------|-------|--------|------|------------|-------|
| 0001 | Technology stack | Reserved | | | #21 (E01-10) |
| 0002 | External engines as subprocesses | Reserved | | | #22 (E01-11) |
| [0003](0003-single-egress.md) | Single egress | Accepted | 2026-09-27 | | #23 (E01-12) |
| 0004 | Changelog and versioning | Reserved | | | #33 (E01-22) |
| [0005](0005-logging-and-no-telemetry.md) | Logging and no-telemetry | Accepted | 2026-09-27 | | #24 (E01-13) |
| [0006](0006-configuration-layering-secrets-and-trust.md) | Configuration layering, secrets and trust | Accepted | 2026-09-28 | | #81 (E03-01) |
