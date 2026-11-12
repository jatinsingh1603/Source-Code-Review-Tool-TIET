# Leakage evaluation: KavachBank

Provider `mock`. Adversary: honest-but-curious provider: sees every sent payload and its metadata; no vault, salt, project tree or ground truth.
Zero-leak gate (secrets, personal data, canary identifiers) across all levels: **PASSED**.

| Level | Sent | Canary hits | Business terms | Identifier recovery | Sector evidence | Coverage | Linkability | Privacy score | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| L1 | 16 | 0 | 0 | 0.73 | 0.12 | 0.14 | 1.00 | 58.9 | 0.91 |
| L2 | 14 | 0 | 0 | 0.19 | 0.00 | 0.12 | 0.16 | 88.8 | 0.91 |
| L3 | 14 | 0 | 0 | 0.19 | 0.00 | 0.12 | 0.16 | 88.8 | 0.91 |
| L4 | 0 | 0 | 0 | 0.00 | 0.00 | 0.00 | 0.00 | 100.0 | 0.91 |

## Ablations

| Variant | Level | Leakage | Canary gate | Coverage | Linkability | F1 |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| default | L3 | 11.2 | pass | 0.12 | 0.16 | 0.91 |
| sink-window-slices | L3 | 11.1 | pass | 0.11 | 0.16 | 0.91 |
| per-request-pseudonyms | L3 | 11.2 | pass | 0.12 | 0.16 | 0.91 |
| role-hints | L3 | 11.2 | pass | 0.12 | 0.16 | 0.91 |

No code payloads are stored in this file; leaked values appear only as hashes.
