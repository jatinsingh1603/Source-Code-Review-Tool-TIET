# CodeKavach

**Privacy-preserving, LLM-assisted secure source code review.**
*Kavach* (कवच) means armour: CodeKavach lets an organisation get an audit-grade security review of its source code from any large language model, **without its business logic, secrets or personal data ever reaching the LLM provider.**

> Status: planning and foundations. Follow progress on the [project board](../../projects) and in the [issue tracker](../../issues).

## The problem

LLMs are good at reasoning about vulnerable code, but a bank, a hospital or a product company cannot paste its source code into a third-party model. The code *is* the business: pricing rules, risk engines, fraud logic, partner integrations, and, too often, hardcoded credentials and customer data in fixtures. Conventional SAST tools keep code local but produce noisy results with little reasoning, and they cannot explain impact the way an auditor does.

## The approach

CodeKavach does the heavy lifting locally and sends the LLM only what it needs, in a form that is useless to anyone but the reviewer.

```
 repository
     |
     v
 [1] Ingest & parse ............ tree-sitter ASTs, symbol tables, call graph        (local)
 [2] Deterministic analysis .... SAST engines, secrets, SCA, IaC, taint engine      (local)
 [3] Candidate findings ........ source -> sink paths, rule hits, hotspots          (local)
 [4] PRIVACY LAYER ............. redact secrets/PII -> slice -> pseudonymise        (local)
     |                           + egress ledger: every byte that leaves is logged
     v
 [5] LLM reasoning ............. any provider or a self-hosted model               (remote or local)
     |
     v
 [6] De-pseudonymise ........... map verdicts back to real files, lines, names      (local)
 [7] Risk rating ............... CWE, OWASP, CVSS v4.0, compliance mapping          (local)
 [8] Audit report .............. PDF, DOCX, HTML, SARIF, JSON, CSV                  (local)
 [9] Issue sync ................ GitHub issues + Kanban cards in the client's repo  (optional)
```

### Privacy levels

| Level | What leaves the machine | Protects secrets/PII | Protects business logic |
|-------|-------------------------|----------------------|-------------------------|
| L0 | Nothing. Local model or deterministic engines only | yes | yes |
| L1 | Code with secrets and PII redacted | yes | no |
| L2 | L1 + all identifiers, strings and comments pseudonymised | yes | partially (structure still visible) |
| **L3 (default)** | L2, but only the minimal vulnerability-relevant slice of code | yes | yes (no whole files, no real names, no domain vocabulary) |
| L4 | No code at all, only abstract data-flow facts and questions | yes | yes (maximum) |

Pseudonymisation is reversible only with a mapping vault that never leaves the client's environment.

## Design goals

- **Any LLM**: Anthropic Claude, OpenAI, Google Gemini, xAI Grok, AWS Bedrock, Azure OpenAI, or self-hosted open models (Qwen, DeepSeek, GLM, Kimi, Llama) via Ollama or vLLM. Bring your own key.
- **Runs anywhere**: CLI, CI (GitHub Action), GitHub App, REST API server, web dashboard, VS Code extension. Self-hosted, air-gapped, or hosted.
- **Audit-grade output**: reports structured the way professional audit firms deliver them, with executive summary, scope, methodology, risk matrix, evidence-backed findings, impact analysis, remediation guidance and compliance mapping.
- **Standards-based**: OWASP Code Review Guide, ASVS, Top 10, MITRE CWE and CAPEC, NIST SSDF, CVSS v4.0, SARIF. See [REFERENCE.md](REFERENCE.md).
- **Evidence-based**: built on published research and open-source engines. See [RESOURCE.md](RESOURCE.md).
- **Measurable privacy**: a leakage evaluation harness quantifies what an adversarial provider could reconstruct at each privacy level.

## Repository map

| Path | Contents |
|------|----------|
| `REFERENCE.md` | Frameworks, standards and methodologies the tool is built on |
| `RESOURCE.md` | Research papers, datasets, open-source tools and documentation links |
| `docs/` | Plan, architecture, decision records, threat model, research notes |
| `src/codekavach/` | Python core (coming with milestone M0) |

## Academic context

CodeKavach is developed at the Thapar Institute of Engineering and Technology as an open-source project and the basis of a research paper on the privacy-utility trade-off in LLM-assisted vulnerability detection.

## Licence

[MIT](LICENSE)
