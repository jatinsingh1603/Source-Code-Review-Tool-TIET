# CodeKavach Architecture

Version 1.0 (2026-09-21). This document is normative for module names, interfaces and invariants. Issues refer to it; change it through an ADR in `docs/adr/`.

## 1. System context

```
                         client environment (trusted)                                   untrusted
 +------------------------------------------------------------------------------+   +--------------+
 |  repo --> ingest --> parsing --> analysis --> candidates                     |   |              |
 |                                                  |                           |   |              |
 |                                                  v                           |   |              |
 |                    privacy layer: policy -> slice -> redact -> pseudonymise  |   |              |
 |                                                  |                           |   |              |
 |                                                  v                           |   |              |
 |                          egress guard + ledger  ==== sanitised payload =====>|==>| LLM provider |
 |                                                  ^                           |   |  (any)       |
 |                                                  | structured verdict  <=====|<==|              |
 |                    restore (vault) <-------------+                           |   +--------------+
 |                          |                                                   |
 |                          v                                                   |
 |        risk rating --> report model --> renderers --> PDF DOCX HTML SARIF    |
 |                          |                                                   |
 |                          +--> integrations: GitHub issues, Projects, checks  |
 +------------------------------------------------------------------------------+
```

A local model (Ollama, vLLM) can sit inside the trusted boundary; policy may then permit lower privacy levels.

## 2. Technology decisions

| Concern | Choice | Reason |
|---------|--------|--------|
| Core language | Python 3.12 | Richest ecosystem for parsing, security engines, PII detection and LLM SDKs |
| Packaging | `uv`, `pyproject.toml`, `src/` layout | Fast, reproducible, lockfile |
| Data models | Pydantic v2 | Validation, JSON Schema export, used for LLM structured output |
| CLI | Typer + Rich | Typed commands, good terminal output |
| Parsing | tree-sitter (`tree-sitter-language-pack`) | One API for all target languages, error-tolerant, fast |
| External engines | Invoked as subprocesses or containers, results normalised through SARIF | Keeps licences separate, engines optional and replaceable |
| LLM transport | Own `LLMProvider` protocol; adapters for LiteLLM, native SDKs, OpenAI-compatible endpoints, Ollama, mock, replay | Provider neutrality without locking into one abstraction library |
| Local store | SQLite (SQLAlchemy 2) for CLI; PostgreSQL for server mode; Alembic migrations | Zero-setup locally, scalable on a server |
| Vault crypto | AES-256-GCM via `cryptography`; key from OS keyring, passphrase (scrypt) or KMS | Standard, audited primitives |
| Server | FastAPI, background workers, SSE for progress | Async, OpenAPI for free |
| Dashboard | React, TypeScript, Vite, Tailwind | Common, large talent pool for student contributors |
| Reports | Jinja2 + WeasyPrint (PDF), docxtpl (DOCX), self-contained HTML, XlsxWriter, Pygments for snippets | Pure Python, templates editable by auditors |
| Quality | ruff, mypy (strict), pytest, hypothesis, import-linter, pre-commit, GitHub Actions | Privacy invariants are enforced by tests and import contracts |

## 3. Repository layout

```
src/codekavach/
  cli/                 Typer app: scan, report, privacy, providers, vault, config, doctor, sync, eval
  config/              settings models, loader, profiles, key handling
  core/
    models/            Finding, Location, CodeRegion, TaintPath, Evidence, Candidate, Scan, Project ...
    pipeline/          Stage protocol, Orchestrator, RunContext, events, caching, resume
    plugins/           entry-point discovery and registry
    store/             local database and artefact store
  ingest/              sources (path, git, archive), discovery, language detection, filters, safety limits
  parsing/             tree-sitter loader, LanguageSpec, queries/, symbols, scopes, imports, call graph
  analysis/
    engines/           adapter base class + one module per external engine
    rules/             native rule DSL, matcher, pack loader
    taint/             def-use, propagation, summaries, framework models
    secrets/           hardcoded-secret findings
    sca/               manifests, advisories, SBOM
    iac/               IaC, container, pipeline configuration
    aggregate/         fingerprints, dedup, correlation, baselines, suppressions
  privacy/
    policy/            levels, policy-as-code, path overrides, provider trust tiers
    detect/            secret, PII and domain-term detectors used for redaction
    redact/            typed placeholder substitution
    pseudonymise/      identifier classifier, per-language renamers, literal and comment handling
    slicing/           slice strategies and stub generation
    ir/                abstract IR for L4
    vault/             encrypted mapping vault
    restore/           de-pseudonymisation of model output, slice-to-file line mapping
    egress/            guard (pre-flight leak checks), ledger (hash chain), transport (the only way out)
  llm/
    providers/         base protocol + adapters
    tasks/             triage, discover, explain, remediate, classify, summarise
    prompts/           versioned templates
    schema/            structured output schemas
    defence/           prompt-injection hardening, output validation
    budget.py cache.py consensus.py
  risk/                CVSS v4.0, OWASP risk rating, matrices, CWE database, taxonomy and compliance mappings
  report/
    model/             ReportDocument and section models
    narrative/         executive summary, methodology, impact narratives
    render/            html, pdf, docx, sarif, json, csv, xlsx, markdown
    templates/
  integrations/
    github/            REST and GraphQL client, issue sync, Projects v2 sync, checks, SARIF upload, App webhooks
    mcp/               MCP server
  server/              FastAPI app, routers, auth, RBAC, workers, DB models, migrations
  eval/                detection harness, leakage harness, datasets, metrics, attacker models
ui/                    web dashboard
extensions/vscode/     VS Code extension
action/                GitHub Action
rules/                 native rule packs (YAML)
data/                  taxonomy mapping tables
fixtures/kavachbank/   deliberately vulnerable sample application with planted secrets and business logic
tests/                 unit, integration, e2e, privacy (property-based)
deploy/                Docker, compose, Helm, air-gapped bundle
tools/                 project tooling that is not part of the shipped package (status reports, board coordinates, release helpers)
docs/                  plan, architecture, ADRs (adr/), threat model, research (research/), process guides (process/),
                       weekly status notes (status/), JSON schemas (schemas/), demo runbooks (demo/), sample reports (samples/)
```

## 4. Pipeline

A scan is an ordered list of stages run by the orchestrator. Each stage implements:

```python
class Stage(Protocol):
    name: str
    requires: frozenset[str]      # artefact keys this stage reads
    provides: frozenset[str]      # artefact keys this stage writes
    def run(self, ctx: RunContext) -> None: ...
```

`RunContext` carries configuration, the artefact store, the event bus, the cancellation token and the budget. Stages are discovered through the `codekavach.stages` entry-point group, so third parties can add languages, engines, detectors, providers and renderers without touching the core.

Default stage order: `ingest`, `parse`, `analyse` (engines, rules, taint, secrets, SCA, IaC run concurrently), `aggregate`, `privacy-prepare`, `llm-review`, `restore`, `rate`, `report`, `sync`.

## 5. Core data model (summary)

| Model | Purpose | Key fields |
|-------|---------|------------|
| `Location` | A place in the client's code | `path`, `start_line`, `end_line`, `start_col`, `end_col`, `symbol` |
| `TaintPath` | Ordered steps from source to sink | `steps: list[TaintStep]`, each with `Location`, `role` (source, propagator, sanitiser, sink), `note` |
| `Candidate` | Output of deterministic analysis, input to the privacy layer | `id`, `rule_id`, `engine`, `cwe`, `locations`, `taint_path`, `engine_severity`, `fingerprint` |
| `CodeSlice` | Minimal code context for a candidate | `segments` (file, line ranges), `stubs`, `strategy`, `token_estimate` |
| `SanitisedPayload` | What the LLM may see | `text`, `level`, `placeholders`, `pseudonym_count`, `line_map`, `payload_hash` |
| `LLMVerdict` | Structured model answer in pseudonym space | `is_vulnerable`, `confidence`, `cwe`, `reasoning`, `impact`, `remediation`, `needs_context` |
| `Finding` | Final, restored, rated result | `id`, `title`, `severity`, `cvss4_vector`, `cwe`, `owasp`, `compliance`, `locations`, `evidence`, `impact`, `likelihood`, `remediation`, `references`, `status`, `provenance` |
| `EgressRecord` | One ledger entry | `seq`, `timestamp`, `provider`, `model`, `level`, `payload_hash`, `prev_hash`, `entry_hash`, `token_counts`, `candidate_id` |

All models are Pydantic v2, frozen where practical, and export JSON Schema into `docs/schemas/`.

## 6. Privacy layer

### 6.1 Levels

| Level | Transformation | Typical use |
|-------|----------------|-------------|
| L0 | Nothing leaves. Only local engines or a local model | Air-gapped |
| L1 | Secrets and PII replaced by typed placeholders | Trusted local or private model |
| L2 | L1 + identifiers, literals and comments pseudonymised | Private cloud tenancy |
| L3 | L2 applied to the minimal slice only (default) | Public LLM APIs |
| L4 | No code; abstract data-flow facts and questions | Crown-jewel paths |

Policy resolves the effective level per file path and per provider trust tier. The stricter of the two wins. A `never-send` rule on a path overrides everything.

### 6.2 Processing order for one candidate

1. **Resolve policy** for every file the candidate touches.
2. **Slice.** Choose a strategy (enclosing function, taint-path slice, backward slice from sink). Replace out-of-slice callees with signature-only stubs. Enforce a token budget.
3. **Redact.** Run secret, PII and domain-term detectors on the slice. Replace hits with typed placeholders such as `<SECRET:aws_access_key:1>` or `<PII:email:2>`. The type is preserved because it is evidence of CWE-798 or CWE-359; the value is not.
4. **Pseudonymise.** Classify each identifier as *internal* (rename) or *public* (keep): language keywords, builtins, standard library and well-known third-party API names are kept because sources, sinks and sanitisers must stay recognisable. Internal identifiers are renamed to role-preserving tokens (`fn_1`, `cls_2`, `var_3`, `param_4`, `field_5`, `mod_6`, `const_7`). String literals keep their security-relevant shape (SQL skeleton, format specifiers, path separators, URL scheme) while domain words are replaced. Comments and docstrings are removed.
5. **Validate.** Re-parse the pseudonymised slice; the AST must be isomorphic to the original slice's AST modulo leaf text.
6. **Guard.** The egress guard scans the final payload for residual secrets, for any original identifier recorded in the vault, for domain dictionary terms, and checks size and aggregation budgets. Any failure blocks the request (fail closed).
7. **Record.** Append an entry to the hash-chained ledger and store the payload locally so the client can audit exactly what left.
8. **Send** through the egress transport to the configured provider.
9. **Restore.** Replace pseudonyms in the verdict with original names, map slice lines back to file lines, and validate the structured output.

### 6.3 Invariants (enforced by tests and import contracts)

- **I1 Single egress.** Only `codekavach.privacy.egress.transport` opens connections to LLM endpoints. `codekavach.llm.providers` builds requests but cannot send them without an `EgressTicket` issued by the guard. An import-linter contract and a socket-blocking test enforce this.
- **I2 No raw code in LLM modules.** `codekavach.llm` accepts `SanitisedPayload` only, never `CodeSlice` or file contents.
- **I3 Vault locality.** Vault contents are never logged, never included in reports sent to integrations, and never serialised outside the vault module.
- **I4 Fail closed.** An exception in any privacy step aborts the request for that candidate; the candidate is still reported from deterministic evidence.
- **I5 Determinism.** With the same scan salt, the same input yields the same pseudonyms, so responses can be cached and experiments reproduced.
- **I6 Completeness.** Property-based tests assert that no vault key (original identifier, literal or secret) of length four or more appears in any ledger payload, except names on the public allowlist.

### 6.4 Threat model (summary; full version in `docs/THREAT_MODEL.md`)

| Adversary | Capability | Goal | Defence |
|-----------|------------|------|---------|
| Honest-but-curious LLM provider, or whoever breaches its logs | Sees every payload, across time | Recover secrets and PII | Redaction before anything else; guard re-check; canary tests |
| Same | Same | Reconstruct business logic or recognise the client | Slicing, pseudonymisation, literal generalisation, aggregation budget, L4 for sensitive paths; leakage measured in E37 |
| Same | Runs identifier-recovery models | Recover meaningful names | Role-only pseudonyms; measure recovery rate; optional structure perturbation |
| Malicious repository content | Text in code, comments, strings, file names | Prompt-inject the reviewer, exfiltrate the vault, suppress findings | Comment and string neutralisation, structured outputs, output validation, no tool access for the model, deterministic findings never dropped on the model's say-so |
| Malicious or compromised engine | Code execution during scan | Read the repository or keys | Engines run sandboxed with no network and read-only mounts |
| Insider with ledger access | Reads stored payloads | Learn what was sent | Ledger payloads encrypted at rest; access audited |

## 7. LLM layer

```python
class LLMProvider(Protocol):
    id: str
    capabilities: ProviderCapabilities          # structured output, tool calling, context window, batch, local
    def prepare(self, task: ReviewTask, payload: SanitisedPayload) -> PreparedRequest: ...
    def parse(self, raw: RawResponse) -> LLMVerdict: ...
```

Sending is done by the egress transport, not by the provider. Adapters: LiteLLM, Anthropic, OpenAI, Google Gemini, xAI, AWS Bedrock, Azure OpenAI, Ollama, generic OpenAI-compatible (vLLM, SGLang, LM Studio), `mock` (deterministic, for tests and demos), `replay` (recorded cassettes, for CI), and a local CLI bridge for subscription-based tools.

Review tasks: `triage` (true or false positive with reasoning), `discover` (find issues in a hotspot slice), `explain` (impact narrative), `remediate` (guidance and a secure example in pseudonym space), `classify` (CWE), `summarise` (executive summary from aggregated, non-code facts). A task may answer `needs_context`; the orchestrator then asks the privacy layer for an additional slice, which goes through the same guard.

Deterministic findings are never discarded because a model disagrees. The model's verdict changes confidence and ordering and is shown to the auditor.

## 8. Risk rating and reporting

Every finding carries: CWE id, OWASP Top 10 category, ASVS requirement, CAPEC pattern where known, CVSS v4.0 vector and score, likelihood and impact on a five-by-five matrix, and compliance clauses (PCI DSS, ISO 27001, NIST SSDF, RBI and SEBI guidance). Mapping tables live in `data/` with their sources recorded.

The report model follows the structure used by professional audit firms: cover and document control, executive summary, scope and approach, methodology, risk rating method, summary of findings, detailed findings, remediation roadmap, privacy attestation (what left the environment, proven by the ledger), appendices (tools and versions, files reviewed, coverage, limitations). Renderers consume one `ReportDocument`, so every format stays consistent.

## 9. Integrations

`integrations.github` offers: SARIF upload to code scanning, check runs and pull-request annotations, **issue sync** (one issue per finding, fingerprint marker for idempotency, labels for severity and CWE, closed automatically when a later scan no longer reports it) and **Projects v2 sync** (add items, set Status, Severity and Sprint fields). Issue creation is rate-limited and resumable. There is no automatic code fixing.

The GitHub Action wraps the CLI in a container. The GitHub App adds webhooks, installation authentication and scheduled scans. The VS Code extension and the MCP server call the same core through the CLI or the REST API.

## 10. Evaluation

- **Detection harness:** OWASP Benchmark, Juliet, CVE-derived datasets; precision, recall and F1 per CWE, per language, per privacy level, per model; baselines are engines only, and the LLM on raw code.
- **Leakage harness:** canary secrets and PII (must be zero), identifier-recovery attacks, business-logic summarisation attacks scored against ground truth, slice re-assembly attacks, stylometric re-identification. Output is a privacy score per level that also appears in the report's privacy attestation.
