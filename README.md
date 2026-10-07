# CodeKavach

[![CI](https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET/actions/workflows/ci.yml)

**Privacy-preserving, LLM-assisted secure source code review.**
*Kavach* (कवच) means armour: CodeKavach lets an organisation get a standards-based security review of its source code from any large language model, **while keeping secrets and personal data local, and minimising and measuring how much business logic is disclosed to the LLM provider.**

> Status: foundations in place: packaging, quality gates, the test harness, CI and the contributor documents are set up, and the product is built milestone by milestone on top of them. Follow progress on the [project board](../../projects) and in the [issue tracker](../../issues).

## The problem

LLMs are good at reasoning about vulnerable code, but a bank, a hospital or a product company cannot paste its source code into a third-party model. The code *is* the business: pricing rules, risk engines, fraud logic, partner integrations, and, too often, hardcoded credentials and customer data in fixtures. Conventional SAST tools keep code local but produce noisy results with little reasoning, and they cannot explain impact the way an auditor does.

## The approach

CodeKavach does the heavy lifting locally and sends the LLM only what it needs to judge a specific candidate, in a form designed to reveal as little as possible about the rest of the system.

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
| L0 | Nothing. Local model or deterministic engines only | yes | yes (nothing leaves) |
| L1 | Code with secrets and PII redacted | yes | no |
| L2 | L1 + all identifiers, strings and comments pseudonymised | yes | partially (structure still visible) |
| **L3 (default)** | L2, but only the minimal vulnerability-relevant slice of code | yes | reduced: names, literals, comments and domain words removed, no whole files; the slice's control flow, literal shapes and public API names are still disclosed |
| L4 | No code at all, only abstract data-flow facts and questions | yes | strongest: only abstract facts are disclosed |

Pseudonymisation is reversible only with a mapping vault that never leaves the client's environment.

### Known limits

CodeKavach reduces and measures disclosure; it does not make disclosure impossible. Stated plainly:

- A vulnerability-relevant slice is still real program structure. At L2 and L3 the control flow of the slice, the shapes of literals (for example the skeleton of an SQL string) and the names of public library APIs are visible to the provider. Public API names can reveal the technology stack and hint at the domain.
- The automated leak check proves that no *recorded* original identifier, literal, secret or listed domain term of four or more characters appears verbatim in anything sent. It does not prove that no *meaning* can be inferred.
- How much an adversarial provider can reconstruct (identifier recovery, business-logic summarisation, slice re-assembly, re-identification of the project) is an open research question that this project measures in its leakage evaluation rather than assumes. Until those measurements exist, treat the business-logic protection as a hypothesis under test.
- Paths that must not be disclosed in any form should be assigned L4, L0 or `never-send` by policy.

## Design goals

- **Any LLM**: Anthropic Claude, OpenAI, Google Gemini, xAI Grok, AWS Bedrock, Azure OpenAI, or self-hosted open models (Qwen, DeepSeek, GLM, Kimi, Llama) via Ollama or vLLM. Bring your own key.
- **Runs anywhere**: CLI, CI (GitHub Action), GitHub App, REST API server, web dashboard, VS Code extension. Self-hosted, air-gapped, or hosted.
- **Audit-style output**: reports structured the way professional audit firms deliver them, with executive summary, scope, methodology, risk matrix, evidence-backed findings, impact analysis, remediation guidance and compliance mapping.
- **Standards-based**: OWASP Code Review Guide, ASVS, Top 10, MITRE CWE and CAPEC, NIST SSDF, CVSS v4.0, SARIF. See [REFERENCE.md](REFERENCE.md).
- **Evidence-based**: built on published research and open-source engines. See [RESOURCE.md](RESOURCE.md).
- **Measured, not claimed**: a leakage evaluation harness quantifies what an adversarial provider could reconstruct at each privacy level, and the results are published with the tool.

## Repository map

| Path | Contents |
|------|----------|
| `REFERENCE.md` | Frameworks, standards and methodologies the tool is built on |
| `RESOURCE.md` | Research papers, datasets, open-source tools and documentation links |
| `docs/` | Plan, architecture, [decision records](docs/adr/README.md), [domain model reference](docs/reference/domain-model.md), threat model, research notes, status notes, schemas, demo runbooks, sample reports |
| `src/codekavach/` | Python core; package tree as in `docs/ARCHITECTURE.md` section 3 |
| `tests/` | Unit, integration, end-to-end and privacy (property-based) tests; how they are organised: [`tests/README.md`](tests/README.md) |
| `ui/` | Web dashboard |
| `extensions/vscode/` | VS Code extension |
| `action/` | GitHub Action |
| `rules/` | Native rule packs (YAML) |
| `data/` | Taxonomy and compliance mapping tables |
| `fixtures/kavachbank/` | Deliberately vulnerable sample application with fake planted secrets |
| `deploy/` | Docker, Compose, Helm and the air-gapped bundle |
| `tools/` | Project tooling that is not part of the shipped package |
| `tools/dev/` | Developer scripts behind the Makefile targets and the pre-commit hooks; every script has a row in [`tools/dev/README.md`](tools/dev/README.md) |
| `docs/adr/` | Architecture decision records, numbered and indexed: [`docs/adr/README.md`](docs/adr/README.md) |
| `changelog.d/` | One changelog fragment per user-visible change, assembled by towncrier into `CHANGELOG.md` |
| `.devcontainer/` | Development container with Python, `uv`, `make` and the report libraries |

## Configuration

Settings come from a project file (`codekavach.toml`), a per-user file, `CODEKAVACH_*` environment variables, CLI flags and named profiles, in that order of increasing precedence. API keys are given as references (`env:`, `keyring:` or `file:`) and not written into a file; the loader refuses a plaintext key (E03-19). Start with `codekavach init`, then read the [CLI user guide](docs/guide/cli.md) and the [configuration guide](docs/configuration/README.md); every command and option is in the [command-line reference](docs/reference/cli.md); the [key reference](docs/configuration/reference.md) and the [error codes](docs/configuration/error-codes.md) are generated from the code.

## Development

Requires [uv](https://docs.astral.sh/uv/) and `make`; uv installs Python 3.12 if needed. No API key, token or login is needed.

```bash
uv sync --all-extras
uv run pre-commit install
uv run pytest
uv run codekavach --help
```

`make setup` runs the first two commands and `make check` runs every gate CI runs on the code; `make help` lists the other targets, and `make prepush` adds the documentation, changelog, licence and telemetry checks. [`CONTRIBUTING.md`](CONTRIBUTING.md) goes from a clone to a first commit.

Work is planned in one-week sprints on the project board; the rhythm and the rules for moving a card are in [`docs/process/sprint-cadence.md`](docs/process/sprint-cadence.md).

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) takes you from a clone to a first commit and says which document governs what. Coding agents and the core team work from [`AGENTS.md`](AGENTS.md).

## Security

Please report vulnerabilities privately, as described in [`SECURITY.md`](SECURITY.md). A bypass of a privacy invariant counts as a vulnerability.

## Academic context

CodeKavach is developed at the Thapar Institute of Engineering and Technology as an open-source project and the basis of a research paper on the privacy-utility trade-off in LLM-assisted vulnerability detection.

## Licence

[MIT](LICENSE)
