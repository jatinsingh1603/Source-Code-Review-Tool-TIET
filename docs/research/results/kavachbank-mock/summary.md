# Detection evaluation: KavachBank

Dataset layout `kavachbank`, 10 labelled vulnerabilities, 10 safe controls, synthetic: True.

| Arm | Findings | TP | FP | FN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| engines-only | 58 | 10 | 2 | 0 | 83.3 (58.3-100.0) | 100.0 (100.0-100.0) | 90.9 (73.7-100.0) |
| mock@L1 | 58 | 10 | 2 | 0 | 83.3 (58.3-100.0) | 100.0 (100.0-100.0) | 90.9 (73.7-100.0) |
| mock@L2 | 58 | 10 | 2 | 0 | 83.3 (58.3-100.0) | 100.0 (100.0-100.0) | 90.9 (73.7-100.0) |
| mock@L3 | 58 | 10 | 2 | 0 | 83.3 (58.3-100.0) | 100.0 (100.0-100.0) | 90.9 (73.7-100.0) |
| mock@L4 | 58 | 10 | 2 | 0 | 83.3 (58.3-100.0) | 100.0 (100.0-100.0) | 90.9 (73.7-100.0) |
| llm-raw | skipped | | | | raw code is never sent by this harness; run it by hand on synthetic fixtures only | | |

Method: matcher: same file, line window 3, same CWE family; llm_filter: findings the LLM judged not vulnerable are dropped, except for the mock provider, whose canned verdicts are ignored; precision: in-scope findings only; out-of-scope findings are counted separately; bootstrap: 1000 resamples of tp/fp/fn units, seed 20260101, 95 percent
