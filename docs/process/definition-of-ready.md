# Definition of Ready

Owning epic: E42 (issue E42-02).

**How to use.** Tick this list for a card before it moves from Backlog to Ready; that is the Backlog exit condition of [`sprint-cadence.md`](sprint-cadence.md) section 3. A card with an unticked line stays in Backlog, and the missing piece is added to the issue or asked for in a comment.

The counterpart for finishing work is the Definition of Done in `AGENTS.md` section 7.

## Checklist

- [ ] The issue has the sections of the work-item template (`.github/ISSUE_TEMPLATE/work_item.md`): Context, Goal, Tasks, Acceptance criteria, Tests required, Privacy and security considerations, Dependencies.
- [ ] The Goal states the observable outcome in one or two sentences.
- [ ] Acceptance criteria are present and each is verifiable: it names a command, a test, a file or an output that can be checked.
- [ ] Tests required are listed, or the issue says why none apply.
- [ ] Module paths and interface names in the issue are those of `docs/ARCHITECTURE.md`, or the issue names the ADR that changes them.
- [ ] Type: exactly one of `type:feature`, `type:task`, `type:test`, `type:docs`, `type:infra`, `type:security`, `type:research`. (`type:epic` marks a tracking issue, which is not worked as a card.)
- [ ] Priority: exactly one of `P0-critical`, `P1-high`, `P2-medium`, `P3-low`, and the board's Priority field has the same value.
- [ ] Size: exactly one of `size:XS`, `size:S`, `size:M`, `size:L`, `size:XL`, and the board's Size field has the same value. A `size:XL` issue is split before it becomes Ready.
- [ ] Area: at least one `area:` label, for example `area:cli` or `area:privacy`.
- [ ] Readiness: exactly one of `agent-ready` or `needs-human`.
- [ ] For `needs-human`: the body states the exact question, key or account that a person has to provide.
- [ ] Milestone is set to a milestone of `docs/PLAN.md` section 5, and Epic is set on the board and in the `Epic:` line of the body.
- [ ] Every issue listed under "Blocked by" exists and is resolvable: it is closed, or it is open with nothing that keeps it from being done first.
- [ ] "Privacy and security considerations" is filled in; "None" is a valid answer when the issue says why.
- [ ] Privacy sub-gate: an issue that touches `codekavach.privacy`, `codekavach.llm` or an outbound network call carries the label `privacy-critical` and names each affected invariant (I1 to I6).

Moving on from Ready to In progress needs an assignee, the current Sprint and all "Blocked by" issues closed; see the column table of the sprint guide.
