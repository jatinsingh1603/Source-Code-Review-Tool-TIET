# Detection evaluation: KavachBank

Dataset layout `kavachbank`, 10 labelled vulnerabilities, 10 safe controls, synthetic: True.

| Arm | Findings | TP | FP | FN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| engines-only | 59 | 10 | 3 | 0 | 76.9 (53.8-100.0) | 100.0 (100.0-100.0) | 87.0 (70.0-100.0) |
| agentrouter@L3 | 57 | 10 | 1 | 0 | 90.9 (72.7-100.0) | 100.0 (100.0-100.0) | 95.2 (84.2-100.0) |
| llm-raw | skipped | | | | raw code is never sent by this harness; run it by hand on synthetic fixtures only | | |

Method: matcher: same file, line window 3, same CWE family; llm_filter: findings the LLM judged not vulnerable are dropped, except for the mock provider, whose canned verdicts are ignored; precision: in-scope findings only; out-of-scope findings are counted separately; bootstrap: 1000 resamples of tp/fp/fn units, seed 20260101, 95 percent
