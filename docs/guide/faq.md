# Security questions and answers

The questions a security team asks before it lets a review tool near its source code, answered with what the product does and with what it does not do. Where something has not been measured, the answer says so. The limits behind these answers are in the README's [Known limits](../../README.md#known-limits), the [whitepaper](whitepaper.md) and [`KNOWN-LIMITATIONS.md`](../KNOWN-LIMITATIONS.md).

## What leaves the machine

**What exactly is sent to the model provider?** Only what the egress ledger records, and you can read it: `codekavach privacy ledger show` on the command line, **Egress Ledger** in the dashboard. Each entry has the payload hash, the privacy level and the provider. A payload the egress guard blocks is recorded as blocked. With the `mock` and `replay` providers nothing is transmitted at all: the ledger then shows what would have been sent.

| Level | What the provider receives | Default |
|-------|----------------------------|---------|
| L0 | Nothing. Deterministic engines and a local model only | |
| L1 | Code with secrets and personal data replaced by typed placeholders | |
| L2 | L1 plus consistent pseudonyms for identifiers | |
| L3 | L2, cut down to the minimal slice around the finding | yes |
| L4 | Abstract data-flow facts only, no code. This release does not deliver L4: a scan at L4 fails closed, sends nothing and withholds every candidate | |

At L2 and L3 the provider still sees the control flow of the slice, the shape of string literals and the names of public library APIs.

**Can the provider reconstruct our business logic from what it receives?** Partly, and the product measures it instead of denying it. At L3 the provider sees a slice with pseudonymised names and no comments or string contents, but the control flow and the shape of literals remain, and so do public API names, which can hint at the stack and the domain. The leak check is verbatim only. How much an adversary can reconstruct (identifier recovery, summarising the logic, re-assembling slices, identifying the project) is what `codekavach eval leakage` measures; treat the protection as a hypothesis under test and read the figures in the [evaluation results](../research/results/README.md). For paths that must not be disclosed in any form, use L0 or a `never-send` rule in the policy.

**Is the zero-leak check a proof?** It shows one narrow thing: no recorded original identifier, literal, secret or listed term of four or more characters occurs verbatim in any stored payload. It does not show that no meaning can be inferred, and it cannot find a term nobody listed.

**Why are there more prompt tokens than payload bytes in the attestation?** Payload bytes count the code slices. Prompt tokens also include the fixed review instructions that go with every slice. The privacy annex of the report splits tokens into prompt and completion.

**Does a second scan of the same code send the same payloads?** No. Every scan started from the dashboard gets a fresh pseudonym salt, so two scans of the same code cannot be linked by their pseudonyms, and the model is asked again. Only a repeated **Review with model** on the same finding is answered from that scan's cache, with no egress and no ledger entry.

**Can we run it without any cloud service?** Yes. L0 with a local model (Ollama) or the deterministic engines only, in the air-gapped compose profile or from the air-gapped bundle. See [Operations](operations.md#air-gapped-operation).

## The model

**What if the model is malicious or compromised?** It does not receive secrets (typed placeholders), real identifiers (pseudonyms) or whole files at L3. A model can still return a wrong or manipulated answer. Findings are candidates that carry evidence, model answers pass schema validation and prompt-injection defences, and the deterministic engines do not depend on the model. Treat model output as untrusted input; the limits of the injection defences are in [`KNOWN-LIMITATIONS.md`](../KNOWN-LIMITATIONS.md#prompt-injection-and-the-model-boundary-2026-11-15).

**Does the model decide the severity?** No. Severity comes from the rule, the weakness class and, for secrets, the detector's type and confidence. A hard-coded private key or cloud secret key is Critical, an access key id High, a low-entropy generic password Medium and a public identifier such as a payment gateway key id Low. A model verdict adds a confidence and an explanation. A "vulnerable" verdict with low or medium confidence is shown as **Needs review**, not **Confirmed**: the model flags, a reviewer confirms.

**How long does a model review take?** It depends on the provider. With a gateway that answers one request at a time, measured timings are in the [walkthrough](walkthrough.md#how-long-a-model-review-takes). The deterministic stages take seconds.

## Evidence and storage

**Where is the mapping from pseudonyms to real names kept?** In the local vault, encrypted, in the scan's state directory. It is never sent, logged or exported. Losing the vault passphrase makes old vaults unreadable: findings of those scans can no longer be mapped back to real names.

**Can someone with access to the server rewrite the ledger?** Yes. The hash chain is tamper-evident, not tamper-proof: an edited, inserted, removed or reordered entry is detected, but the hashes are not keyed and nothing outside the scan's directory anchors the chain, so someone who can write to that directory can cut entries off the end or recompute every hash, and verification still passes. The check against that is the head hash printed in the report and in the verification file: keep a copy somewhere the server's operator cannot change. External anchoring is not part of this release.

**What data does the dashboard store, and where?** Scan results, findings, triage decisions, ledger entries, vaults and reports, in its own database and data directory (the `codekavach-data` volume under Docker) on your machine. The product has no telemetry: nothing is sent to the authors.

**Do reports contain our code?** Yes. The evidence in a report is snippets of the scanned code, with the real file names and identifiers restored. Keep reports, the inspection page and backups of the data directory with the classification of the code.

## Detection and triage

**Does the tool find real vulnerabilities, or only planted ones?** The evaluation harness (`codekavach eval`) compares findings with labelled ground truth at each privacy level. The bundled sample applications have planted flaws so that a scan of them has a known answer; on them the scanner finds most planted flaws, not all, and it also flags some code that is safe. No detection rate on other code is claimed beyond what `eval` has measured. See the [evaluation guide](evaluation.md).

**How are false positives handled?** A reviewer sets the status of a finding (confirmed, false positive, accepted risk, fixed) with a comment; the evidence and the data-flow path are on the finding page so that the decision is quick. Every change is kept in the finding's history.

**What happens to triage decisions on the next scan?** They are kept. An unchanged finding keeps the reviewer's decision, and its history says which scan it was carried from. A finding marked **fixed** that is reported again opens again, as a regression.

**Why does the report count more findings than the Overview?** The executive summary counts every finding of the scan and then says how many remain open; the Overview's card counts open findings. The trend chart counts every finding each scan reported.

## Access

**Who can see original code in the dashboard?** Administrators and auditors. A developer sees findings and the ledger without the original-next-to-payload view; a viewer sees no privacy pages, cannot start a scan and cannot triage. Every read of an original-next-to-payload pair is written to the audit log. Roles are in the [admin guide](admin-guide.md#2-users-and-roles).

**What does it cost to run?** The software is free to run (MIT licence). Model cost depends on the provider and the level; L3 sends slices, not files, so it sends the least of the code-sending levels. The attestation of every scan gives the tokens that scan used.

**What is not finished?** [`KNOWN-LIMITATIONS.md`](../KNOWN-LIMITATIONS.md) and the [hand-over document](../handover.md#known-limitations) list it.
