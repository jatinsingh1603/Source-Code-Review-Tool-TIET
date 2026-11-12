# Evaluation results

Small, code-free summaries produced by `codekavach eval detection` and `codekavach eval leakage`.
They contain counts, rates and hashes only; no source text, no payload and no secret value.

## `kavachbank-mock/`

Both runs use the KavachBank synthetic fixture and the **mock** provider, offline.

```text
codekavach eval detection --dataset kavachbank --level L1 --level L2 --level L3 --level L4 --out DIR
codekavach eval leakage   --dataset kavachbank --level L1 --level L2 --level L3 --level L4 --out DIR
```

How to read them honestly:

* The mock provider gives canned verdicts, and the harness ignores them when deciding what is
  reported. The L1 to L4 detection arms therefore equal the engines-only arm: they show that the
  privacy layer does not break the pipeline, not how well a model reviews code. Run the same
  command with `--provider agentrouter` (or any real provider) to measure a model.
* The labelled set is 10 planted vulnerabilities and 10 safe controls. The confidence intervals are
  wide for that reason and are printed as such.
* Leakage is measured against an honest-but-curious provider that sees every sent payload. The
  zero-leak gate covers planted secrets, planted personal data, business terms and injected canary
  identifiers; at L1 identifier names remain visible by design and are excluded from the gate
  (they are still counted in identifier recovery).
* The attackers are heuristic (verbatim and sub-word identifier recovery, a keyword sector
  classifier, line coverage and pseudonym linkability). A low score means these attackers
  recovered little, not that no attacker could.
* The `llm` attacker is not run in these results. The `llm-raw` detection arm is not run either.

## `kavachbank-agentrouter-L3/`

Detection only, one level, with a real model: provider `agentrouter` (model `gpt-5.6-sol`) at L3 on KavachBank, one run.

| Arm | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| engines-only | 10 | 3 | 0 | 76.9 | 100.0 | 87.0 |
| agentrouter@L3 | 10 | 1 | 0 | 90.9 | 100.0 | 95.2 |

The model, seeing only L3 payloads, removed two of the three engine false positives and lost no true positive. This is one run on ten labels: the 95 percent intervals overlap (F1 70.0-100.0 against 84.2-100.0), so it shows the direction, not a proven gain. The leakage results for this provider were not re-run; the payloads at L3 are the same as in the mock run.
