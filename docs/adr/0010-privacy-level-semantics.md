# ADR-0010: Privacy level semantics

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-13 |
| Deciders | maintainers |
| Issue | #250 (E25-02) |
| Affects | `docs/ARCHITECTURE.md` sections 1 and 6.1; `codekavach.privacy.levels`, `codekavach.privacy.slicing`, `codekavach.privacy.stages`; invariants I1, I4, I5 |

## Context and problem statement

`docs/ARCHITECTURE.md` section 6.1 names five privacy levels, L0 to L4, but M1 implemented only L3. Section 1 says a local model may sit inside the trusted boundary and that "policy may then permit lower privacy levels", which leaves open what each level sends, on which unit of code, and what L0 means when a local model is configured. These are architectural choices, so they are recorded here rather than in code comments.

## Decision drivers

- A level must state what leaves the machine in terms an auditor can check against the ledger.
- Weaker levels exist for providers inside the trust boundary; they must not become a silent default.
- Every refusal fails closed (invariant I4); nothing is truncated into a misleading unit.
- The same input gives the same payload at every level (invariant I5).

## Considered options

1. L1 and L2 on the M1 minimal slice, differing from L3 only in transformations.
2. L1 and L2 on the enclosing function.
3. L1 and L2 on every file the candidate touches, whole, with a budget fallback.

## Decision outcome

Option 3, as stated by `LEVEL_PLANS` in `src/codekavach/privacy/levels.py` and rendered in `docs/reference/privacy-levels.md`:

| Level | Unit | What is applied |
|---|---|---|
| L0 | none | Nothing crosses the client trust boundary. No payload is built. The LLM review stage is dropped unless the provider's resolved trust tier is `local`. |
| L1 | file | Typed placeholders for secrets, personal data and domain terms; names, comments and structure are kept. |
| L2 | file | L1 plus consistent pseudonymisation of identifiers; comments are removed. |
| L3 | slice | L2 on the minimal slice (the default). |
| L4 | none | Abstract facts only. Not delivered yet, so a candidate resolved to L4 fails closed with `level_unavailable` and is still reported from deterministic evidence. |

A whole-file unit may use `UNIT_BUDGET_FACTOR` (4) times `privacy.slice.max_tokens`. A file over that budget is never truncated: the selector falls back to the enclosing function, then to the sink window, and the slice records `fallback_reason = "over_budget"`, so the report can count how many L1 and L2 units were whole files.

A weaker level is opt-in. `privacy.level` and `privacy.min_level` default to L3, the provider tier floors (`privacy.provider_tier_levels`) still apply, and a project policy can only tighten (ADR-0006, E25-01).

### Consequences (positive, negative, neutral)

- Positive: L1 and L2 give a model inside the trust boundary the whole context a reviewer would read, which is what the weaker levels are for.
- Negative: a whole file pseudonymised at L2 holds more identifiers than a slice, so the egress guard's vault scanner (invariant I6) blocks an L2 request more often when a renamer leaves a name unrenamed. That refusal is fail-closed and ledgered; it is a cost in recall, not in privacy.
- Neutral: L1 discloses comments and string literals, which are also a prompt-injection surface; the attestation records `comments_retained`.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

- `tests/unit/privacy/test_levels.py`: every level has a plan, L0 and L4 send no code, transformations grow with the level, L4 fails closed, L0 drops review for non-local tiers.
- `tests/unit/privacy/slicing/test_wholefile.py`: the whole file is one segment, files are taken once, the budget refusal is curable, a never-send file is refused at once, and the selector records the fallback reason.
- `tests/integration/test_privacy_pipeline.py::test_l1_and_l2_send_whole_files_and_l3_a_subset`: on the sample application, L1 payloads keep the file's own names, L2 payloads contain none of them, and L3 payloads are smaller.
- `tests/unit/privacy/test_levels.py::test_the_reference_table_is_generated_from_the_plans`: the reference table cannot drift from `LEVEL_PLANS`.

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

- I1 unchanged: the unit changes what is prepared, not how it leaves; every request still goes through the single egress transport and its guard.
- I2 unchanged: the LLM layer still receives `SanitisedPayload` only.
- I3 unchanged: the vault holds the mappings of every level that pseudonymises.
- I4 strengthened: L4 fails closed instead of downgrading, and an over-budget unit falls back to a smaller unit rather than a truncated one.
- I5 unchanged: the whole-file strategy is a pure function of the inventory; a test asserts equal slices for equal inputs.
- I6 unchanged at L2 and L3, where the guard's vault scanner still blocks any original of four characters or more. At L1 originals are sent by definition; L1 is permitted only where the operator lowered `privacy.level` and `privacy.min_level` and the provider tier floor allows it.

## Implementation notes (optional; the only section that may grow after acceptance)

- The consent downgrade gate (`needs_reconsent`) and the plan-time refusal of L0 with a public-tier provider are tracked in issue #250; their state is recorded there.
- What the vault scanner compares against, per level. The vault is per project and holds every name that an L2 or L3 scan of the project renamed. At L2 and L3 every request body is compared with all of it, unchanged. An L1 payload is not compared with the vault (`LevelPlan.names_retained`): L1 renames nothing by definition, and before this rule the first L1 scan of a project passed while every L1 scan after an L2 or L3 scan was blocked, so the outcome depended on history rather than on the payload. The secret, personal-data, domain-term, budget and aggregation scanners run at every level. Test: `tests/unit/privacy/test_egress_scanners.py::test_an_l1_payload_keeps_names_by_definition_and_is_not_compared_with_the_vault`.
- The "negative" consequence above was observed on the KavachBank sample: most whole-file L2 requests were blocked. The causes were a renamer gap and a matcher false positive, both fixed rather than tolerated. The JavaScript renamer kept an internal shorthand key in clear (`{ exportStatement }` became `{ exportStatement: fn_1 }`), which put an original in the payload contrary to I6; the key now takes the binding's token, and is expanded with a key in clear only when that name is public in the file. And the stub label `unresolved` contained the client variable `resolved`; inside a word the tool writes, only an original equal to the whole word is a hit. Tests: `tests/privacy/test_pseudonymise_survival.py::test_the_egress_vault_scanner_passes_every_payload_the_pseudonymiser_makes` and `tests/unit/privacy/test_egress_scanners.py::test_an_original_inside_a_word_the_tool_writes_is_not_a_hit_but_the_word_itself_is`. After the fix, KavachBank scans at L1, L2 and L3 in one project, in any order, recorded no blocked payload (CLI with the mock provider, and `scripts/seed_demo.py` against `codekavach serve`).

## Links

- `docs/ARCHITECTURE.md` sections 1 and 6.1
- `docs/reference/privacy-levels.md`
- Issue #250 (E25-02)
