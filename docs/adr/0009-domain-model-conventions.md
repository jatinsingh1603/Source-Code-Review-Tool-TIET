# ADR-0009: Domain-model conventions

| | |
|---|---|
| Status | Proposed |
| Date | 2026-10-06 |
| Deciders | Project maintainers |
| Issue | #49 (E02-01) |
| Affects | `docs/ARCHITECTURE.md` section 5; `codekavach.core.models`; invariants I2 and I6; every epic that builds on the core models |

## Context and problem statement

`docs/ARCHITECTURE.md` section 5 summarises the core data model in one table of key fields. Epic E02 made several decisions that refine or extend that table:

- extra fields;
- where the fingerprint function lives;
- how raw code and sanitised text are kept apart;
- how lines are counted.

Every later epic builds on these models. The decisions are spread over the E02 issues, so this record consolidates them in one place for reviewers and the supervisor, before anyone depends on them by accident. It changes no code: each decision is already implemented by the E02 issue named with it.

## Decision drivers

- The privacy invariants: raw code never reaches `codekavach.llm` (I2), and no original identifier appears in a ledger payload (I6).
- Results that are stable across scans, so that baselines, suppressions and issue sync work.
- Interoperability with SARIF 2.1.0, git and the line numbers that engines report.
- No unnecessary runtime dependencies.
- Testability: injectable clocks and entropy, and deterministic serialisation.

## Considered options

For each decision below, the option taken and the alternatives rejected are given with the decision.

## Decision outcome

### D1 Base conventions

All models derive from `KavachModel` (`frozen=True`, `extra="forbid"`). Sequence fields are `tuple[T, ...]`, never `list`, so that frozen models really are immutable and hashable. Timestamps are timezone-aware UTC and serialise as RFC 3339 with a `Z` suffix and exactly six fractional digits. `hide_input_in_errors=True` keeps the text of a validation error from echoing input values (client code or secrets) into logs and tracebacks. *Rejected:*

- mutable models (an object shared between stages could change underneath a hash);
- `list` fields (a list inside a frozen model can still be mutated and makes the instance unhashable);
- naive datetimes, or a variable number of fractional digits (byte-unstable serialisation breaks hashes and golden files).

### D2 Identifiers

Entity ids are prefixed ULIDs: `scan_`, `proj_`, `cand_`, `slice_`, `pay_` or `find_`, followed by 26 Crockford base32 characters. The ULID encoder is implemented in-house (`codekavach.core.models.ids`, about 60 lines), so that tests can inject the clock and the entropy source and no runtime dependency is added. ULIDs sort by creation time, which keeps store listings and logs readable. *Rejected:* UUID4 (no ordering), a third-party ULID package (a dependency for 60 lines, and harder to make deterministic in tests), and unprefixed ids (an id pasted into the wrong place is not recognisable).

### D3 Identity versus id

An id names one object in one scan. The `fingerprint` names the same weakness across scans, and it is what baselines, suppressions and GitHub issue sync key on. Keeping the two apart lets a re-scan produce new objects without losing their history. *Rejected:* reusing ids across scans (they would have to be derived from content, which is exactly the fingerprint's job), and keying issue sync on a location (it changes with every edit above it).

### D4 Fingerprint placement

The pure fingerprint function lives in `codekavach.core.models.fingerprint`. Every analysis module must call it when it builds a `Candidate`, and `codekavach.core` must not import from `codekavach.analysis`. `codekavach.analysis.aggregate` (E21), which ARCHITECTURE section 3 names as the home of "fingerprints", uses the function for deduplication, correlation and baselines. This clarifies section 3; it does not contradict it. *Rejected:* placing the function in `analysis.aggregate`, which would make every engine adapter import aggregation code and invert the dependency direction.

### D5 Raw versus sanitised text

`RawCode` and `SanitisedText` are nominal wrapper classes, not `typing.NewType`. A `NewType` is erased at run time: it cannot stop raw text being logged through `repr`, cannot make Pydantic reject a plain `str` where sanitised text is required, and lets either type flow silently into any `str` parameter. The wrappers give:

- static separation under `mypy --strict`;
- run-time rejection in Python-mode validation;
- a redacted `repr`.

Leaving a wrapper takes an explicit `.expose()`. This is the design basis of I2, enforced statically by the guard of E02-28. *Rejected:* `NewType`, for the reasons above, and plain `str` with naming conventions (nothing enforces them).

### D6 Coordinates

Lines are 1-based and inclusive. Columns are 1-based Unicode code points with an exclusive end, which matches SARIF 2.1.0 regions with `columnKind = unicodeCodePoints`. *Rejected:* 0-based coordinates (every engine and editor shows 1-based lines, so off-by-one errors in reports would be likely), and byte or UTF-16 columns (they depend on the encoding and on the language of the tool reading them).

### D7 Versioning

Each persisted top-level model carries an integer `schema_version`. Old documents are upgraded through a migration registry (`codekavach.core.models.migrate`, E02-21) before validation, and a completeness check in CI (E02-23) fails when a version is raised without a migration step. *Rejected:* unversioned documents (experiment data for the paper must stay readable after a model changes), and semantic version strings (a single integer per model is enough, and comparing integers cannot go wrong).

### D8 Schema export entry point

JSON Schema export is `python -m codekavach.core.models.export`, not a new top-level CLI command, because the normative command list in ARCHITECTURE section 3 has no `schema` command. E05 may wrap the function later. *Rejected:* adding a `schema` command, which would change the command list without an ADR of its own.

### D9 `SanitisedPayload.line_map` holds no paths

Line-map entries point at a slice segment index; the path stays in the `CodeSlice`, inside the privacy layer. A payload object therefore never contains an original path, identifier or value. This supports I6: a payload, and the ledger entry derived from it, carries nothing that names the client's code. *Rejected:* storing file paths in the payload, which would carry original names to the LLM side and into the ledger.

### D10 `Finding.impact` and `Finding.likelihood`

Both are small structured values: a `level` from 1 to 5 plus narrative text. ARCHITECTURE section 8 needs a position on the five-by-five matrix, and Demo 1 needs an impact narrative. *Rejected:* free text only (no matrix position), and a level only (the auditor's report needs the narrative).

### D11 `EgressRecord` extensions

`scan_id`, `task`, `outcome` (`sent`, `blocked`, `completed` or `failed`), `block_code`, `ref_seq` and `request_hash` are added. With them:

- blocked attempts are auditable;
- completion token counts can be appended as a new entry instead of mutating a hash-chained one;
- the exact request bytes can be verified once E12 records them.

`candidate_id` is nullable for scan-level tasks such as `summarise`. Ledger entries are never migrated (`MIGRATABLE = False`): a future format change keeps the old class for reading old entries. *Rejected:* updating an entry in place when a response arrives (it breaks the hash chain), and logging blocked attempts elsewhere (the ledger is the single audit trail of egress).

### D12 Shared test support

Factories (`tests/support/factories.py`, E02-25) and hypothesis strategies (`tests/support/strategies.py`, E02-26) for the models live in `tests/support/` and are reused by other epics. Secret-looking test values are vendor-documented examples or checksum-invalid values, defined in one module (`tests/support/synthetic.py`). *Rejected:* per-test builders (they drift from the models and from each other), and inline secret-looking literals (they trip secret scanning and are hard to audit).

### D13 Line model

- A line ends at `\n`, and a `\r` directly before it belongs to the terminator.
- A last line without a terminator counts as a line, and the empty string has zero lines.
- A lone `\r`, a form feed, U+2028, U+2029 and the other characters that `str.splitlines()` treats as boundaries are ordinary characters.

This matches tree-sitter rows, git and the line numbers most engines report. `str.splitlines()` is not used for line arithmetic anywhere. One helper, `split_lines()` in `codekavach.core.models.text`, implements the rule. Files with classic Mac line ends (a lone `\r`) are a concern of ingestion (E06). *Rejected:* `str.splitlines()`, whose extra boundaries would shift every line number after a form feed or U+2028 relative to the engines.

### D14 Data classification

Every model declares `DATA_CLASSIFICATION`: `raw`, `sanitised`, `untrusted` or `metadata`. The default on the base class is `raw`, so an unclassified model is treated as client data (fail closed). The I2 static guard (E02-28) derives the allow-list of `codekavach.llm` from it, and the reference page (E02-30) prints it. *Rejected:* an explicit allow-list maintained by hand (it does not notice new models), and a default of `metadata` (a forgotten classification would open the LLM layer to client data).

### D15 Fields beyond the section 5 table

The table in ARCHITECTURE section 5 lists key fields only. The additional fields, and the reasons for them:

| Model | Field | Reason |
|-------|-------|--------|
| `Candidate` | `kind` | Vulnerability, secret, dependency, misconfiguration or hotspot; drives routing and reporting |
| `Candidate` | `language` | Selects slicing, pseudonymisation and prompts per language |
| `Candidate` | `message` | The engine's message, kept locally for the auditor |
| `Candidate` | `engine_version`, `engine_confidence` | Reproducibility and confidence calibration across engines |
| `Candidate` | `properties` | Engine-specific key and value pairs that do not deserve a field |
| `CodeSlice` | `id`, `candidate_id` | Links slice, payload and candidate without object references |
| `CodeSlice` | `language`, `truncated` | The language for pseudonymisation; whether the slice hit the size budget |
| `SanitisedPayload` | `id`, `candidate_id`, `slice_id` | Ledger and restore can name the payload without holding it |
| `LLMVerdict` | `cited_lines` | Structured line references, so that restore (section 6.2 step 9) maps payload lines to file lines without parsing free text |
| `Evidence` | `clipped`, `masked` | Whether the snippet was cut at the line budget; whether a secret was masked before the snippet was built |
| `Finding` | `fingerprint`, `correlation_key` | Identity across scans (D3), and grouping of the same weakness reported by several engines |
| `Finding` | `confidence`, `description` | Shown to the auditor next to the severity |
| `Finding` | `cvss4_score` | The score of `cvss4_vector`, stored so that reports do not recompute it |
| `Finding` | `taxonomy`, `taint_path` | Mappings beyond CWE and OWASP; the data flow behind the finding |
| `Finding` | `kind`, `language` | Carried over from the candidate for reports and filtering |
| `Finding` | `status_history` | The append-only lifecycle (E02-11), an integrity control against prompt-injected suppression |
| `Finding` | `created_at`, `first_seen_scan_id` | Age of a finding across scans, for baselines and trends |
| `LLMReviewRef` | `reasoning` | Section 7: the model's verdict "is shown to the auditor" |

### Consequences (positive, negative, neutral)

- Positive: one place to look up why a model looks as it does. Changes to D5, D9 or D14 are recognisable as privacy-relevant.
- Negative: wrapper types and tuple fields make some code more verbose (`.expose()`, `tuple(...)`).
- Neutral: the ARCHITECTURE section 5 table stays a summary; field-level detail lives here and in the generated reference (E02-30).

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Decision | Enforced by |
|----------|-------------|
| D1, D7 | `tests/unit/core/models/test_roundtrip_properties.py` (immutability, hashability, versioned load) and the golden wire files |
| D2 | `tests/unit/core/models/test_ids.py` |
| D3, D4 | `tests/unit/core/models/test_fingerprint.py`; the `core-models-independent` import contract |
| D5, D14 | `tests/unit/core/models/test_text.py`; the I2 guard in `tests/privacy/test_i2_static_guard.py` |
| D6, D13 | `tests/unit/core/models/test_location.py`, `tests/unit/core/models/test_text.py` |
| D7, D8 | The schema drift and migration completeness checks (`make schemas-check`, CI) |
| D9, D11 | `tests/unit/core/models/test_payload.py`, `tests/unit/core/models/test_egress.py` |
| D12 | `tests/unit/support/` |

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Strengthened.

- **I2.** D5 and D14 are its design basis. The wrapper types separate raw from sanitised text in the type system and at run time, and the data classification derives the allow-list of the LLM layer.
- **I6.** D9 supports it: a payload's line map holds no path, so neither the payload nor its ledger entry names the client's code.
- **Ledger tamper evidence.** D11 keeps it: entries are appended, never updated or migrated.

A later change to the wrappers, to `line_map` or to the classification default is a privacy-relevant change and needs its own ADR. I1, I3, I4 and I5 are unchanged.

## Implementation notes (optional; the only section that may grow after acceptance)

## Links

- `docs/ARCHITECTURE.md` sections 3, 5, 6.3 and 8; `AGENTS.md` section 3
- SARIF 2.1.0 specification (OASIS), region object
- ULID specification; RFC 3339
- `docs/reference/model-versioning.md`, `docs/reference/domain-model.md`
