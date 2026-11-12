# Privacy-preserving LLM code review: the approach

A short whitepaper on how CodeKavach lets an organisation use a large language model (LLM) to review its source code without handing the code over. It states the threat model, the design, what is measured and, plainly, what is not solved.

## 1. The problem

An LLM can reason about a vulnerability in ways a pattern-matching scanner cannot: it can see that a value is validated in one function and not in another, explain impact in the language of the business, and suggest a fix. But source code is the business. It holds pricing, risk and fraud logic, partner integrations, and too often credentials and customer data in fixtures. A bank, a hospital or a product company cannot paste that into a third party's service, and a promise of good behaviour from a provider does not change that.

Two obvious answers fail. Keeping everything local with conventional static analysis is safe but noisy and shallow. Sending everything to the model with a contract is deep but leaks by design.

## 2. Threat model

The adversary is an **honest-but-curious model provider**: it follows the protocol, but it keeps what it receives, may correlate requests across a project, and may be breached later. It sees every request. It does not see the client's machine, the vault, the project tree or the ground truth.

What we want to protect, in decreasing order of how firmly we can promise it:

1. **Secrets and personal data** (keys, passwords, tokens, identity numbers, contact details). Promise: they do not leave.
2. **Business terms and names** (identifiers, string literals, comments, domain words). Promise: they are replaced, and a listed term is checked for verbatim.
3. **Business logic** (what the code does). Aim: disclose as little as the question needs, and measure what remains.

Out of scope: an attacker on the client machine, a malicious user with legitimate access, and the content of the report once it is delivered.

## 3. Design

The heavy lifting is local. Deterministic engines, secret detection, dependency analysis and a taint engine find **candidates**. Only then does the privacy layer prepare, for each candidate, a payload for the model.

1. **Redact.** Secrets and personal data are replaced by typed placeholders (`<SECRET_1>`, `<EMAIL_2>`). The original values go into a local, encrypted **vault** and are never written anywhere else.
2. **Slice.** Only the smallest code needed to judge the candidate is cut out: the enclosing function, or the path from source to sink, with stubs for callees. No whole files.
3. **Pseudonymise.** Identifiers are renamed consistently (`fn_3`, `param_1`), strings and comments are neutralised, and listed business terms are removed. The mapping stays in the vault.
4. **Guard.** Immediately before sending, an **egress guard** scans the final bytes for any recorded secret, listed term or original identifier, and for residual personal data. A hit blocks the request. The guard sits in the only code path that can send, so nothing bypasses it.
5. **Ledger.** Every request, sent or blocked, is appended to a hash-chained **egress ledger** with the payload hash. The ledger is the evidence of what left.
6. **Restore.** The model's verdict, written about `fn_3` and `param_1`, is mapped back to real files, lines and names locally, and only then rated and reported.

The **privacy level** chooses how far to go:

| Level | Disclosed |
|-------|-----------|
| L0 | nothing |
| L1 | code with secrets and personal data replaced |
| L2 | L1 plus pseudonymised identifiers |
| L3 | L2, minimal slice only (default) |
| L4 | abstract data-flow facts, no code |

A **policy** (organisation and project) sets floors and per-path, per-rule and per-provider levels; `never-send` overrides everything. The strictest applicable rule wins.

## 4. What is measured

The project measures rather than asserts. The evaluation harness (see the [Evaluation guide](evaluation.md)) reports:

- **Detection quality** at each level and for each provider: precision, recall and F1 with bootstrap confidence intervals, against labelled datasets.
- **Canary exposure**: planted secrets, personal data, business terms and injected unique identifiers searched for in every payload. Secrets, personal data and canary identifiers must be zero.
- **Identifier recovery**, **sector inference** and **slice stitching**: how much of the real code base an observer could rebuild from the payloads.
- **A privacy score per scan**, with each component labelled as measured, indicative or not computed.

Result of the first run on the synthetic KavachBank fixture with the offline mock provider ([`docs/research/results/`](../research/results/README.md)):

| Level | Canary gate | Identifier recovery | Code coverage | Pairs linkable |
|-------|-------------|--------------------:|--------------:|---------------:|
| L1 | pass (names visible by design) | 0.73 | 0.14 | 1.00 |
| L2 | pass | 0.19 | 0.12 | 0.16 |
| L3 | pass | 0.19 | 0.12 | 0.16 |
| L4 | pass (nothing sent) | 0.00 | 0.00 | 0.00 |

Reading it: moving from L1 to L2 removes most of the readable names; L4 sends no code. The engines found all ten planted vulnerabilities. These numbers come from one small synthetic project and a heuristic adversary; they show that the method works and the harness runs, not that the figures generalise.

## 5. Known limits

Stated plainly, because the value of this document depends on it.

- **Structure is still disclosed.** A slice is real program structure. At L2 and L3 the control flow, the shape of literals (the skeleton of an SQL string, the number of arguments to a call) and the names of public library APIs are visible. Library names reveal the technology stack and hint at the domain. Our own measurement shows a keyword classifier finds no sector evidence at L2 and L3 on the sample, but a model-based attacker was not run.
- **The zero-leak check is verbatim.** It proves that no recorded secret, listed term or original identifier appears literally in anything sent. It does not detect a paraphrase, an encoding, a translation or an acronym of a term, and it cannot check a term nobody listed. The quality of the term list is part of the control; `codekavach privacy terms` helps build it.
- **Meaning is not measured exhaustively.** What an adversarial provider could reconstruct (business-logic summarisation, re-assembly of slices across many requests, re-identification of the project from its API usage) is an open research question. The harness measures a defined set of heuristic attackers. A low score means these attackers recovered little, not that no attacker could.
- **Cross-request linkage.** With consistent pseudonyms, payloads in one scan can be linked to each other (the L2 and L3 linkability above). Per-request pseudonyms remove the link at the cost of cache hits and cross-slice reasoning. Over many scans, the union of what a provider has seen grows; an exposure budget can cap it, and is off by default.
- **Utility has a cost.** Higher levels give the model less to work with. The privacy-utility frontier is reported per dataset; on real models it must be measured, not assumed. The committed results use the mock provider, whose verdicts carry no judgement.
- **Model quality.** A model can miss a vulnerability or invent one. The report keeps the deterministic evidence next to the model's verdict, and a human triages.
- **Not covered.** Side channels (timing, request size), compromise of the client machine or the vault passphrase, a user who pastes code by hand, and provider-side logging of metadata that is not payload.
- **Paths that must never be disclosed in any form** should be assigned L4 or L0, or `never-send`, by policy, and reviewed with a local model.

## 6. Using it responsibly

Start with **Send off**, read the egress preview, and run the zero-leak and ledger verification before the first real scan. Set an organisation minimum level. Put your own domain terms in the term list. Treat the privacy score as a summary of measured components, not a certificate. When the stakes are high, use a local model.

## 7. Related work and references

The design builds on the OWASP Code Review Guide and ASVS, MITRE CWE and CAPEC, CVSS 4.0, SARIF, and the research collected in [`RESOURCE.md`](../../RESOURCE.md) and [`REFERENCE.md`](../../REFERENCE.md). The privacy layer's levels, policy and score are specified in [Privacy levels, policy and score](../privacy/policy-levels-score.md); the architecture and invariants in [`ARCHITECTURE.md`](../ARCHITECTURE.md).
