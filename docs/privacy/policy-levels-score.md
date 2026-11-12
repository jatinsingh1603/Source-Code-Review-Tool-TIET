# Privacy policy, levels, budgets and the privacy score

This page is for the person who has to approve CodeKavach and for the auditor who reads its report. It describes what is enforced, where, and what is only an indicator.

## Levels

The strictness order is `L1 < L2 < L3 < L4 < L0`. A level is a pipeline mode, defined once in `codekavach.privacy.levels.LEVEL_PLANS`.

| Level | What leaves the machine | Unit | Notes |
|-------|--------------------------|------|-------|
| L0 | Nothing | none | No payload is built. With a non-local provider the `llm-review` stage is removed from the plan; a provider of trust tier `local` may still run. |
| L1 | Code with secrets, personal data and domain terms replaced by typed placeholders | enclosing function | Names and structure are unchanged. |
| L2 | L1 plus consistent pseudonyms for identifiers | enclosing function | |
| L3 | L2 on the minimal slice around the candidate | slice | The default. |
| L4 | Abstract facts only | none | Not delivered yet: candidates at L4 are withheld (fail closed), never downgraded. |

Deviation from the original issue: whole-file units for L1 and L2 are not implemented; the unit is the enclosing function, the largest unit the slicer produces.

A run at a level less strict than the one last consented to asks again (`codekavach privacy consent`); a non-interactive run is refused. `levels.needs_reconsent` states the rule; the consent store already applies it.

## Policy as code

Place `codekavach.policy.toml` in the project root (example: `docs/examples/codekavach.policy.example.toml`). Axes:

- `[[path]]`: glob with `level` or `never_send = true`;
- `[[language]]`: minimum level per language;
- `[[rule]]`: minimum level for a rule id or CWE glob (for example `CWE-89`);
- `[[classification]]`: a tag (such as `pci`) attached to globs, with the level it demands;
- `[provider_tiers]`: minimum level per trust tier.

Resolution is strictest-wins over the settings (already floored by the organisation policy) and every axis of the file; a file can only tighten. `never_send` overrides every level. Errors carry `CK-POL-001` (too large), `CK-POL-002` (not TOML), `CK-POL-003` (invalid content).

`codekavach privacy explain <file|candidate-id>` prints each contribution, its source and which one won. Decisions are stored per candidate in the `privacy.policy` artefact as `(level, withheld, rule_key, policy_hash)`: no path, pattern or language, so the record is safe outside the client environment. The `rule_key` has the shape `<axis>:<index-or-tag>` and matches `^[a-z_]+:[A-Za-z0-9_-]{0,64}$`.

Not done: adding `policy_hash` and `policy_rule_key` to the ledger entry schema (it is hash-chained and owned by the egress epic); the hash is in the decision artefact and the attestation instead.

## Exposure budgets

`privacy.egress.aggregation_budget_pct` (default 100, meaning off) is enforced in two places: the egress guard (per scan, in memory) and `privacy-prepare`, which consults an `ExposureAccount` kept in `exposure.json` in the state directory. The account holds, per provider and per scan, the union of disclosed line intervals keyed by an HMAC of the file path, so it contains no path. The ceiling applies to a scan and to the engagement (all scans for that provider); a slice that would pass it is refused with item error `privacy_aggregation_budget`. Cross-slice unlinkability is the existing `privacy.pseudonym.link_mode = "per_request"`; the score reports linkability measured on shared placeholder tokens. Slice-shape uniqueness and cover traffic remain research notes.

## The privacy score

`codekavach.privacy.attestation.build_attestation(state_dir, scan_id, settings)` returns an `Attestation` (Pydantic model). `attestation.to_api()` is the body of `GET /api/v1/scans/{id}/privacy`; `attestation.digest()` is a SHA-256 of its canonical JSON and `attestation.sign(key)` an HMAC over it. `codekavach privacy score` prints it.

The score has no hidden inputs. Components are points from 0 to 100 and each is labelled **measured**, **indicative** or **not computed**:

| Component | Kind | Definition |
|-----------|------|------------|
| `level_strength` | indicative | weakest payload level: L1 25, L2 50, L3 75, L4 90, L0 100 |
| `disclosure_volume` | measured | 100 - 4 x (union percentage of repository lines disclosed), floor 0 |
| `residual_terms` | measured | 100 when configured domain terms are absent from every ledger payload, 0 when found, 50 when no terms were configured |
| `linkability` | measured | 100 x (1 - share of placeholder tokens that occur in two or more payloads) |
| `budget_usage` | measured or not computed | 100 - usage of the aggregation ceiling, when one is set |
| `ledger_integrity` | measured | the hash chain verifies |
| `naming_channel` | not computed | structural and naming leakage; owned by the leakage harness |

Summary: `score = round(0.35 level_strength + 0.30 disclosure_volume + 0.25 residual_terms + 0.10 linkability)`, capped at 40 when a residual term is found, at 50 when the chain is broken and at 60 when the budget is exceeded. A scan that sent nothing scores close to 100. The summary is a convenience: read the components. A high score does not claim that structure, control flow or the technology stack stayed hidden; the verbatim check does not detect paraphrased or encoded terms.

## Does the suite bite

`tests/privacy/test_guard_bites.py` breaks five named controls on purpose (never-send, strictest-wins, exposure budget, reconsent, L0 review removal) and asserts that each control's check notices. Not done: the L1-versus-L3 differential utility band, and a broader mutation harness over redaction and the vault.
