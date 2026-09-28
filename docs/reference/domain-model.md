# Domain model reference

The full reference for `codekavach.core.models` is written by E02-30. This page currently holds only the section on test factories.

## Testing with model factories

`tests/support/factories.py` provides one deterministic builder per core model, so that a valid object is one call away in any test and golden files never contain random ids or timestamps:

```python
from tests.support.factories import make_finding, make_egress_chain, fixed_ids

finding = make_finding()                       # valid, identical on every call
low = make_finding(severity=Severity.LOW)      # overrides exactly that field, validated
chain = make_egress_chain(5)                   # five sealed entries; the first is the E02-18 vector
ids = fixed_ids()                              # ULID factory: frozen clock, counter entropy
```

Available builders: `make_location`, `make_region`, `make_taint_path`, `make_candidate`, `make_slice`, `make_payload`, `make_verdict`, `make_evidence`, `make_finding`, `make_egress_chain`, `make_egress_totals`, `make_summary`, `make_project` and `make_scan`.

Rules the factories follow, and that tests relying on them can count on:

- **Real constructors only.** Every object is built through the model constructors and class methods (`Candidate.create`, `SanitisedPayload.build`, `EgressRecord.seal`, `Evidence.from_source`, `ScanSummary.from_findings`, `EgressTotals.from_records`), never through `model_construct`. An invalid override raises `ValidationError`.
- **Validated overrides.** Overrides are applied with `KavachModel.evolve`. Overrides of hashed fields of a payload (`text`, `line_map`, ...) go through `SanitisedPayload.build`, so the hash is recomputed.
- **One coherent story.** The defaults describe one synthetic weakness: the SQL injection in `src/bank/accounts.py` at line 88 (`AccountRepo.find_by_owner`), rule `python.sqli.string-concat` of `codekavach-rules`, CWE-89. The candidate's fingerprint is vector A of E02-10, the slice, payload, evidence and finding refer to the same candidate, and the scan id matches the finding's provenance and the ledger.
- **Sample text.** `SAMPLE_SOURCE` (twelve synthetic lines of `AccountRepo`, file lines 80 to 91) and its hand-written pseudonymised counterpart `SAMPLE_SANITISED` are illustrative only; the real pseudonymiser is E09. The sample deliberately contains business-sounding identifiers of four or more characters, so that privacy tests have something the I6 completeness check must catch.
- **Synthetic values.** Secret-looking and personal-looking values live only in `tests/support/synthetic.py`: vendor-documented example keys, addresses under the reserved domain `example.test`, and telephone numbers from documentation ranges. A test fails if a secret-looking literal appears in another file under `tests/support/`.

### Hypothesis strategies and profiles

`tests/support/strategies.py` has one hypothesis strategy per core model: `regions()`, `locations()`, `taint_paths()`, `candidates()`, `code_slices()`, `sanitised_payloads()`, `verdicts()`, `evidences()`, `status_histories()`, `findings()`, `egress_chains(max_size=20)`, `egress_totals()`, `summaries()`, `projects()` and `scans()`. It also provides `repo_paths()`, `raw_code_texts()` and `safe_payload_texts()`.

Like the factories, the strategies build through the real constructors and class methods, so every example is valid by construction. For instance, findings take their evidence from `Evidence.from_source` and their history from `apply_transition`, and ledger chains are sealed entry by entry.

The text strategies deliberately include awkward cases:

- `raw_code_texts()` produces tabs, blank lines, CRLF, missing final newlines, a form feed or U+2028 inside a line, and occasionally a 5,000-character line.
- `safe_payload_texts()` contains only whole placeholders, so `SanitisedPayload.build` always accepts it.

The strategies are cached and assemble bulky text from a seeded `random.Random`, which keeps an example to a few milliseconds.

Example budgets come from the profiles registered in `tests/conftest.py` and selected with `HYPOTHESIS_PROFILE`:

| Profile | Examples | Notes |
|---------|----------|-------|
| `dev` (default) | 50 | |
| `ci` | 200 | Derandomized, so two runs draw the same examples |
| `nightly` | 2000 | |

An unknown profile name stops the run with a usage error. `tests/unit/support/test_model_strategies.py` checks every strategy with 200 examples and all health checks active.
