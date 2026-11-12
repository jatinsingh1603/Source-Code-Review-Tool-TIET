# Privacy levels

The level decides what the prepare stage sends for one candidate and on which unit of code. The decision and its reasons are recorded in [ADR-0010](../adr/0010-privacy-level-semantics.md). The table below is generated from `LEVEL_PLANS` in `src/codekavach/privacy/levels.py`, and `tests/unit/privacy/test_levels.py` fails when the two differ.

Strictness order: L1 < L2 < L3 < L4 < L0. The default is L3. `privacy.level`, `privacy.min_level`, the provider tier floors and a project policy decide the level of each candidate; the strictest wins.

<!-- generated from LEVEL_PLANS: do not edit by hand -->
| Level | Unit | Redact | Pseudonymise | Comments retained | Minimise | Sends code | Description |
|---|---|---|---|---|---|---|---|
| L0 | none | no | no | no | no | no | Nothing leaves the machine; no payload is built. |
| L1 | file | yes | no | yes | no | yes | Typed placeholders for secrets, personal data and domain terms; whole files, code otherwise intact. |
| L2 | file | yes | yes | no | no | yes | Placeholders plus pseudonymised identifiers, on every file of the candidate, whole. |
| L3 | slice | yes | yes | no | yes | yes | Placeholders plus pseudonyms on the minimal slice around the candidate. |
| L4 | none | no | no | no | no | no | Abstract facts only, no code (not yet delivered: fails closed). |
<!-- end of generated table -->

## Units

- **file** (L1, L2): every file the candidate touches, whole. A unit may use 4 times `privacy.slice.max_tokens`. A file over that budget is not truncated: it falls back to the enclosing function, then the sink window, and the slice records `fallback_reason = "over_budget"`.
- **slice** (L3): the minimal slice of the M1 strategies (taint path, backward slice, enclosing function, sink window).
- **none** (L0, L4): no code is sent. At L0 the LLM review stage is dropped unless the provider's trust tier is `local`. L4 is not delivered yet: a candidate resolved to L4 is withheld and still reported from deterministic evidence.

At L2 and L3 the egress guard blocks any request that still contains an original identifier, literal or secret of four characters or more that the vault holds (invariant I6, enforced by `tests/privacy/test_i6_ledger.py`). At L1 original names and comments are sent by definition, which is why L1 is opt-in and limited by the provider tier floors.
