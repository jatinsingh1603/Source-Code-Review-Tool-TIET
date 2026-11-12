# Auditor guide

This guide is for the person who reads a CodeKavach report, decides what to believe in it, and signs off. It explains the structure of the report, how to judge a single finding, and how to use the privacy attestation and the egress ledger as evidence of what was disclosed to the model provider.

## 1. What the report contains

The PDF and HTML reports are generated from one document model, so every format says the same thing.

| Section | What to look for |
|---------|------------------|
| **Executive summary** | Counts by severity, the three to five findings that matter most, and one paragraph in plain language. Written for a reader who will not open the findings. |
| **Scope and methodology** | What was scanned (files, languages), when, with which engines, privacy level, provider and model. Anything not scanned (skipped files, unsupported languages) is listed here. |
| **Risk matrix** | Findings placed by likelihood and impact. |
| **Findings** | One entry per finding, see section 2. |
| **Compliance mapping** | Findings mapped to OWASP Top 10, ASVS, CWE and the compliance clauses configured for the engagement. |
| **Privacy attestation** | What was prepared, what left the machine, and the checks that were run on it, see section 4. |
| **Appendix** | Tool and rule versions, ledger head hash, integrity manifest (SHA-256 of every report file). |

The retest (delta) report compares two scans and lists findings as new, fixed or unchanged.

## 2. Reading a finding

Each finding carries the same fields:

- **Title, severity and confidence.** Severity is derived from impact and likelihood (and CVSS where a vector applies); confidence says how sure the analysis is that the issue is real.
- **Identifiers.** CWE, OWASP category, ASVS requirement, CAPEC pattern where known; CVSS 4.0 and 3.1 vectors with their scores.
- **Location.** File and lines. The code is shown with line numbers, with secrets masked.
- **Evidence.** For taint findings, the path from the untrusted **source** through each step to the dangerous **sink**. Follow it step by step: a break in the path means a possible sanitiser or a false positive.
- **Model verdict.** Whether the model judged it vulnerable, its confidence, its reasoning, the impact and the suggested remediation, with the **provider and model** that produced it.
- **Engine and rule.** Which deterministic engine or rule found the candidate. A finding no engine flagged and only the model raised is marked as model-discovered and deserves more scrutiny.
- **Status and history.** open, confirmed, false positive, accepted risk or fixed, with who changed it and when.

### How much to trust a finding

1. A deterministic detection (rule or taint path) **and** a model verdict of vulnerable is the strongest case.
2. A deterministic detection with a model verdict of *not vulnerable* is a disagreement. Read the reasoning, then read the code. The tool does not hide it.
3. A model-only finding is a lead, not a conclusion. Reproduce it.
4. Secrets findings show the kind and location, never the value.

The model's text is advice. The code, the path and the engine are the evidence.

## 3. Verifying what the report says about itself

- **Integrity manifest.** The report bundle includes `SHA256SUMS`. Verify with `sha256sum -c SHA256SUMS` in the report directory. This detects a file altered after generation.
- **Reproducibility.** The scan records the version, the settings fingerprint and the rule set. A retest with the same inputs on the same version produces the same candidates.
- **Triage trail.** Status changes are stored with user and time and are visible in a finding's history.

## 4. The privacy attestation

The attestation is the answer to "what did you tell the model about our code". It is built from the ledger of the scan, not from the configuration, so it states what happened rather than what was intended.

It reports:

- **Level, provider, model and trust tier.** Hosted providers need a stricter minimum level than local ones.
- **Payloads sent, blocked and withheld.** *Blocked* means the egress guard stopped a payload because it still contained a recorded secret, a listed business term, a known original identifier or other residual personal data. *Withheld* means policy said the code must not be prepared at all.
- **Placeholders by type.** How many secrets, email addresses, identity numbers and so on were replaced, by kind. Values are never recorded.
- **Pseudonyms and tokens sent.** How many identifiers were renamed, and the approximate size of what was sent.
- **Ledger chain.** Whether the hash chain verifies, the number of entries and the head hash. A broken chain is a failure of the evidence, not just a warning.
- **Zero-leak check.** The number of terms checked and the occurrences found verbatim in anything sent. The expected value is zero. The check covers recorded secrets, listed domain terms and original identifiers.
- **Policy.** The hash of the policy applied, and which rules decided the level of each candidate.
- **Privacy score.** A 0 to 100 summary with each component shown and labelled as *measured*, *indicative* or *not computed*. The score is capped at 40 if a residual term was found, at 50 if the chain is broken, and at 60 if an exposure budget was exceeded. Read the components, not the headline.

### What the attestation does not say

- It does **not** prove that no meaning can be inferred from what was sent. At L2 and L3 the shape of the code (control flow, literal skeletons, public library names) is visible. The whitepaper's [Known limits](whitepaper.md#known-limits) lists the rest.
- The zero-leak check is a verbatim search. A paraphrased or encoded term is not found by it.
- The ledger shows requests made through CodeKavach. It cannot show what a user copied by hand.

## 5. Inspecting the evidence yourself

In the dashboard, open **Privacy Centre, Egress ledger**. Each entry has a sequence number, time, provider, model, level, payload hash, entry hash and previous hash. Open an entry to see the original code and the exact text sent side by side, with changes marked as secret, personal data, identifier or literal. Opening that pair is restricted to admins and auditors and every access is written to the audit log.

On the command line:

```console
$ codekavach privacy inspect --scan latest          # original and sent, side by side
$ codekavach privacy ledger verify                # chain and payload hashes
$ codekavach privacy score --scan latest            # score with every component
```

The ledger is append-only and hash-chained: each entry includes the hash of the previous one, and the hash of the payload it records. Changing or removing an entry breaks every hash after it. **Verify** recomputes them.

## 6. Sign-off checklist

1. Scope and methodology match the engagement; unsupported languages and skipped paths are acknowledged.
2. The scan ran at the agreed privacy level, with the agreed provider and model.
3. The ledger chain verifies and the zero-leak check reports zero occurrences.
4. Blocked payloads were reviewed: each is a candidate the model did not see.
5. Every critical and high finding is confirmed, rejected or accepted with a written reason.
6. Model-only findings were reproduced before being reported as confirmed.
7. The report files match the manifest.
8. The whitepaper's known limits were read and the residual disclosure is acceptable to the client.
