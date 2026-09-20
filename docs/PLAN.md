# CodeKavach Project Plan

| | |
|---|---|
| Project | CodeKavach: privacy-preserving, LLM-assisted secure source code review |
| Institution | Thapar Institute of Engineering and Technology |
| Repository | https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIT |
| Licence | MIT |
| Plan version | 1.0 (2026-09-21) |
| First demo | 2026-10-05 (privacy-layer proof) |
| Final submission | 2026-12-21 (v1.0 + evaluation + paper draft) |

## 1. Vision

Give any organisation a standards-based security review of its source code, reasoned by whichever LLM it chooses, while removing secrets and personal data before anything leaves its environment, and minimising and measuring what the provider can learn about its business logic.

## 2. Requirements baseline

These were elicited from the project owner on 2026-09-21 and are the primary source for every design decision.

| # | Requirement | Decision |
|---|-------------|----------|
| R1 | Primary goal | Protect business logic and hardcoded secrets, API keys and PII from every LLM provider while still delivering a real code audit |
| R2 | Default privacy level | L3: redact, then slice, then pseudonymise. L0, L1, L2 and L4 selectable by policy |
| R3 | LLM providers | Any: Anthropic, OpenAI, Google Gemini, xAI Grok, AWS Bedrock, Azure OpenAI, self-hosted open models (Qwen, DeepSeek, GLM, Kimi, Llama) via Ollama or vLLM. User supplies the key |
| R4 | Interfaces | CLI, CI, GitHub Action, GitHub App, REST API server, web dashboard, VS Code extension |
| R5 | Deployment | Self-hosted, air-gapped and hosted modes |
| R6 | Languages | Python, JavaScript, TypeScript, Java, Kotlin, C, C++, PHP, Go, C#, Ruby, with a plugin path for more |
| R7 | Methodology | Built on recognised frameworks: OWASP, MITRE, NIST, CERT, PCI DSS, ISO 27001. Catalogue in `REFERENCE.md` |
| R8 | Reports | Professional audit-firm structure. PDF, DOCX, interactive HTML, SARIF, JSON, CSV, XLSX and a compliance mapping annex |
| R9 | Evidence | Text code snippets with line numbers and highlighting. No screenshots or videos |
| R10 | Issue sync | Raise findings as GitHub issues in the client's repository and add them to the client's Kanban board each agile cycle. No automatic fixing |
| R11 | Research | Tool first, then a research paper on the privacy-utility trade-off. Sources in `RESOURCE.md` |
| R12 | Transparency | Supervisor tracks progress through the GitHub project board; team of students contributes |
| R13 | Development keys | No paid API keys at the start: develop against a mock provider, a replay provider and local models; real providers verified when keys arrive |

## 3. Scope

In scope: static review of source code, configuration, dependencies and infrastructure-as-code; LLM reasoning over privacy-processed evidence; risk rating; reporting; issue tracking integration; evaluation harnesses.

Out of scope for v1.0: dynamic testing (DAST), automatic code fixing or pull requests, binary analysis, mobile app packages, runtime agents.

## 4. Guiding principles

1. **Local first.** Everything that can be done without an LLM is done locally and deterministically. The LLM is a reasoning aid for candidates the local engines produce, not a scanner that reads the repository.
2. **One way out.** Exactly one component, the egress guard, may send data to an LLM. Every payload passes leak checks and is recorded in a tamper-evident ledger the client can inspect.
3. **Reversible only at home.** Pseudonym mappings live in an encrypted vault that never leaves the client's environment.
4. **Measured, not claimed.** Privacy is quantified by attacking our own output with adversary models; detection quality is quantified on public benchmarks.
5. **Standards, not opinions.** Each finding carries CWE, OWASP, CVSS v4.0 and compliance identifiers.
6. **Provider-neutral.** No feature may depend on a single vendor's API.
7. **Fail closed.** If a privacy check cannot run, nothing is sent.

## 5. Milestones

| Milestone | Due | Outcome |
|-----------|-----|---------|
| M0 Foundations | 2026-09-27 | Scaffolding, CI, domain model, configuration, plugin pipeline, CLI skeleton |
| M1 Privacy layer MVP + Demo 1 | 2026-10-05 | Thin end-to-end slice and the side-by-side proof of what leaves the machine |
| M2 Detection engine | 2026-10-26 | Engine adapters, native rules, taint analysis, secrets, SCA, IaC, aggregation |
| M3 LLM reasoning | 2026-11-02 | Provider matrix, review tasks, consensus, context-request loop, prompt-injection defences |
| M4 Privacy hardening | 2026-11-09 | Policy engine, L0 to L4, advanced pseudonymisation, abstract-IR mode, leakage gates |
| M5 Audit reporting | 2026-11-23 | Risk rating, compliance mapping, all report renderers |
| M6 Platforms | 2026-12-07 | API server, dashboard, GitHub Action and App, issue and board sync, VS Code extension |
| M7 Evaluation and paper | 2026-12-14 | Detection and leakage experiments, paper draft, project report |
| M8 Hardening and release | 2026-12-21 | Packaging, air-gapped bundle, security review of the tool, documentation, v1.0 |

Milestones M2 to M7 overlap in practice; the due date is when the milestone's exit criteria must hold.

### Demo 1 exit criteria (2026-10-05)

1. `codekavach scan fixtures/kavachbank` completes on a laptop with no paid API key.
2. The sample application contains planted vulnerabilities, planted secrets and recognisable business logic (an interest and fee engine).
3. `codekavach privacy inspect` shows, side by side, the original code and the exact payload prepared for the LLM: secrets replaced by typed placeholders, identifiers, strings and comments pseudonymised, only slices present.
4. An automated check proves that no planted secret and no listed business-domain term occurs *verbatim* anywhere in the egress ledger. With a mock or replay provider the ledger shows what *would* have left; this is stated as such in the demo.
5. Findings come back mapped to the real files, lines and names.
6. An HTML and a PDF report are produced with executive summary, risk matrix, findings with snippet evidence, impact and remediation.

## 6. Epics

Each epic has a tracking issue; its work items are sub-issues. Keys (E01 to E42) appear in issue titles.

| Key | Epic | Milestone |
|-----|------|-----------|
| E01 | Repository scaffolding and developer experience | M0 |
| E02 | Core domain model and schemas | M0 |
| E03 | Configuration and settings | M0 |
| E04 | Plugin architecture and pipeline orchestrator | M0 |
| E05 | Command line interface | M0 |
| E06 | Repository ingestion | M1 |
| E07 | Parsing and code intelligence | M1 |
| E08 | Secret, PII and domain-term detection for redaction | M1 |
| E09 | Pseudonymisation engine | M1 |
| E10 | Mapping vault and de-pseudonymisation | M1 |
| E11 | Slice extraction | M1 |
| E12 | Egress guard and ledger | M1 |
| E13 | Demo 1: thin end-to-end slice and sample application | M1 |
| E14 | Engine adapter framework and SARIF normalisation | M2 |
| E15 | Engine adapters per language | M2 |
| E16 | Native rule engine and rule packs | M2 |
| E17 | Taint analysis engine | M2 |
| E18 | Hardcoded secret findings | M2 |
| E19 | Software composition analysis and SBOM | M2 |
| E20 | IaC, container and pipeline configuration review | M2 |
| E21 | Finding aggregation, baselines and suppressions | M2 |
| E22 | LLM provider abstraction | M3 |
| E23 | Prompt system and review tasks | M3 |
| E24 | LLM security hardening | M3 |
| E25 | Privacy policy engine and levels L0 to L4 | M4 |
| E26 | Advanced pseudonymisation and aggregation control | M4 |
| E27 | Abstract-IR mode (L4) | M4 |
| E28 | Privacy verification and leakage regression testing | M4 |
| E29 | Risk rating and taxonomy mapping | M5 |
| E30 | Report content model and narrative | M5 |
| E31 | Report renderers | M5 |
| E32 | Persistence, server and REST API | M6 |
| E33 | Web dashboard | M6 |
| E34 | GitHub integration: Action, App, issue and Kanban sync | M6 |
| E35 | VS Code extension, pre-commit hook and MCP server | M6 |
| E36 | Evaluation harness: detection quality | M7 |
| E37 | Evaluation harness: privacy leakage | M7 |
| E38 | Research paper and academic deliverables | M7 |
| E39 | Packaging and deployment | M8 |
| E40 | Security of CodeKavach itself | M8 |
| E41 | Documentation and teaching material | M8 |
| E42 | Project management and progress reporting | M0 |

## 7. Way of working

- **Board.** The GitHub project board is the single source of truth. Columns: Backlog, Ready, In progress, In review, Done. Fields: Priority, Size, Epic, Milestone, Sprint.
- **Sprints.** One week, Monday to Sunday. A short sprint note is added to `docs/status/` at the end of each sprint for the supervisor.
- **Issues.** Every issue is self-contained: context, goal, tasks, technical notes, acceptance criteria, tests, dependencies, privacy considerations. Issues labelled `agent-ready` can be completed by an AI coding agent without further clarification; `needs-human` issues need a person (keys, accounts, decisions).
- **Order of work.** Within a milestone, take the lowest-numbered open issue whose blockers are all closed.
- **Commits.** Small, focused commits to `main`, each referencing its issue (`Refs #n` or `Closes #n`). CI must stay green.
- **Definition of done.** Acceptance criteria met, tests written and passing, types and lint clean, documentation updated, no privacy invariant weakened, issue closed with a short note on what was done.

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Pseudonymisation reduces LLM accuracy too far | Medium | High | Preserve public API names and security-relevant roles; measure accuracy per level from M1 onward; offer policy per path |
| Residual leakage through structure or literals | Medium | High | Egress guard leak checks; attacker-model evaluation (E37); aggregation budgets; L4 for crown-jewel paths |
| Scope is very wide for three months | High | Medium | Thin end-to-end slice first; every platform sits on the same core; depth added by priority labels |
| No paid LLM keys during development | High | Medium | Mock and replay providers; local models; provider conformance suite run when keys arrive |
| Third-party engine licences conflict with MIT or with scanning proprietary code | Medium | High | Licence verdict per engine in `docs/research/INSIGHTS.md`; engines run as external processes; optional engines clearly marked |
| Prompt injection from reviewed code | Medium | High | Comments and strings removed or neutralised at L2+; structured outputs; output validation; regression suite (E24) |
| New GitHub account rate or abuse limits | Medium | Medium | Paced issue creation and small, regular commits |
| Benchmark contamination in LLM evaluation | Medium | Medium | Use post-cutoff CVE sets and pseudonymised variants; report contamination checks |

## 9. Deliverables

1. Open-source tool, v1.0, with Docker images and an air-gapped bundle.
2. Sample audit reports (PDF, DOCX, HTML, SARIF) for the bundled vulnerable applications.
3. `REFERENCE.md`, `RESOURCE.md`, architecture and threat model documentation.
4. Evaluation results: detection quality and privacy leakage per privacy level and per model.
5. Research paper draft and university project report.
