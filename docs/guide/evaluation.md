# Evaluation guide

CodeKavach measures two things instead of claiming them: how well it **detects** vulnerabilities, and how much an adversarial provider could **learn** from what is sent. Both are commands that write a results directory.

```console
$ codekavach eval detection --dataset kavachbank --level L1 --level L2 --level L3 --level L4 --out results/detection
$ codekavach eval leakage   --dataset kavachbank --level L1 --level L2 --level L3 --level L4 --out results/leakage
```

Add `--provider agentrouter` (or any provider id) to `eval detection` to measure a real model. Without it the mock provider is used, which measures that the pipeline works at each level, not how good a model is. Each run is a real scan in a throw-away state directory, so a run with a hosted provider sends data like any scan does; leakage runs on synthetic datasets only.

Committed example results: [`docs/research/results/`](../research/results/README.md).

## Datasets

A dataset is a directory with source code and a ground truth. `--dataset` takes a name from `fixtures/` or a path. Layouts recognised:

| Layout | Detected by | Labels |
|--------|-------------|--------|
| KavachBank and the demo projects | `ground-truth/manifest.yaml` | Planted vulnerabilities with file, line, CWE; safe controls; planted secrets, personal data and business terms (used as canaries). |
| Generic JSON | `ground-truth.json` at the root | `{"name", "synthetic", "vulnerabilities":[{id,cwe,file,line}], "negatives":[...], "terms":[...]}` |
| OWASP Benchmark | `expectedresults-*.csv` | One label per test case file (`real vulnerability` true or false, CWE); file-level. |
| Juliet | files named `CWE<n>_...` | Every file is a vulnerable case at file level; names with `good` and not `bad` are safe controls. |

Datasets are read from local directories; nothing is downloaded.

## Detection

**Matching.** A finding matches a label when it is in the same file, within three lines (any line for file-level labels) and in the same CWE family (for example CWE-327 and CWE-329 are both cryptography). Each label is matched by at most one finding; further findings on the same label are counted as duplicates, not false positives. A finding in a manifest or lock file (a dependency advisory) or in a CWE family the dataset does not label is out of scope and reported separately. A finding on a safe control is a false positive.

**Arms.**

| Arm | Meaning |
|-----|---------|
| `engines-only` | Deterministic analysis, LLM off. The baseline. |
| `<provider>@L1` ... `@L4` | The full pipeline with LLM review at that privacy level. A finding the model judged not vulnerable is dropped, except for the mock provider whose canned verdicts are ignored. |
| `llm-raw` | Raw code to a model without the privacy layer. **Not run** by this harness; it is listed as skipped so the results say so. |

**Metrics.** Precision, recall and F1 overall and per CWE, per CWE family and per language, each with a 95 percent bootstrap interval (1000 resamples, fixed seed). With ten labels the intervals are wide; they are printed because they are the honest answer.

**Outputs** in `--out`: `results.json` (all numbers), `summary.md`, `table.tex` (LaTeX table for a paper), `f1.svg` (and `f1.png` when matplotlib is installed).

## Leakage

**Adversary.** An honest-but-curious provider: it sees every payload that was sent, with its metadata, and may correlate them across a scan. It does not see the vault, the salt, the project tree or the ground truth.

**Attackers.**

| Attacker | What it does |
|----------|--------------|
| `canary` | Searches payloads for planted secrets, personal data, business terms and a canary module injected into the scanned copy (unique identifiers, an email, a token). Secrets, personal data and canary identifiers are a **hard gate**: any hit fails. At L1 identifier names are visible by design, so they do not fail the gate there. Results contain hashes of leaked values, never the values. |
| `identifier` | How many project-defined identifiers can be read off the payloads, verbatim or by sub-word. |
| `inference` | A keyword classifier guesses the business sector; reported as the share of sector evidence visible. |
| `stitching` | How much of the code base the payloads cover, and how many payload pairs share a pseudonym and could be linked. |
| `llm` | Optional model attacker; only on synthetic datasets and only through the egress path. Not run in the committed results. |

**Score.** `leakage_score` is 0 to 100, higher is worse: 0.35 identifier recovery, 0.15 sector evidence, 0.25 code coverage, 0.10 linkability, 0.15 business-term occurrences (saturating at five); a hard canary hit scores 100. `privacy_score` is 100 minus that. It is a summary of *these* attackers. A good score means they recovered little.

**Frontier and ablations.** Each level is reported with the detection F1 of the same scan, so the cost of privacy in utility is visible. Ablations run at L3 with sink-window slices, per-request pseudonyms and role hints.

## Adding an attacker or a dataset

Attackers are plain functions over `PayloadView` objects in `codekavach/eval/leakage.py`; add one and register its name in `ATTACKERS`. A dataset needs a loader in `codekavach/eval/datasets.py` that returns a `Dataset`. Both have unit tests under `tests/unit/eval/` to copy from. A smoke evaluation on KavachBank with the mock provider runs in the test suite and fails if recall drops below 0.8 or a canary leaks at L2 or above.
