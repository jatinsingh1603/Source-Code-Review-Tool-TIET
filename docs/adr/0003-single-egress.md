# ADR-0003: Single egress

| | |
|---|---|
| Status | Accepted |
| Date | 2026-09-27 |
| Deciders | CodeKavach maintainers |
| Issue | #23 |
| Affects | docs/ARCHITECTURE.md sections 1, 6.2, 6.3 (I1, I2, I4) and 7; codekavach.privacy.egress; codekavach.llm.providers; .importlinter; ruff banned-API list |

## Context and problem statement

"One way out" is guiding principle 2 of `docs/PLAN.md`. Invariant I1 makes it concrete: only `codekavach.privacy.egress.transport` opens connections to LLM endpoints, and provider adapters cannot send without an `EgressTicket` issued by the guard. The privacy attestation in every audit report (`docs/ARCHITECTURE.md` section 8) rests on the egress ledger being a complete record of what left the machine. That is only true if there is no second exit. This record fixes what "single egress" means, how it is enforced, where enforcement has gaps, and how a legitimate non-LLM network user asks for an exception.

## Decision drivers

- The ledger must be complete: every byte sent to a model has exactly one ledger entry.
- The rule must be checkable by machines, in CI, before review.
- Import contracts work on module names and cannot tell an LLM endpoint from any other host.
- Some future features need network access for reasons unrelated to LLMs (advisories, GitHub sync, datasets, KMS).
- Provider neutrality (`docs/PLAN.md` principle 6): vendor SDKs must not become a second transport.

## Considered options

1. **Rule on LLM endpoints only**, as I1 is worded. Not enforceable statically: a contract cannot know which host a client library will talk to.
2. **Rule on all network clients, strict by default, with named exceptions granted by ADR.** Enforceable with import contracts and banned-API rules; exceptions are explicit and reviewable.
3. **Runtime-only enforcement** (a socket wrapper that allows known hosts). Catches dynamic imports but fails late, cannot be verified in review, and is easy to bypass from native code.

## Decision outcome

Chosen option: 2, combined with the test-time and runtime controls of option 3 as further layers.

### Rule

No module in `codekavach` other than `codekavach.privacy.egress.transport` may import a network client library or open a socket. This is deliberately stricter than the wording of I1 ("connections to LLM endpoints"), because an import contract cannot tell an LLM endpoint from any other host. The rule is strict by default; every other network user needs a named exception granted by an ADR.

LLM traffic is the traffic that carries a `SanitisedPayload` to a model provider and brings back its response. All other outbound traffic (advisory downloads, repository hosting APIs, key management) is not LLM traffic and never carries a payload, but it is still covered by the rule and needs an exception.

Inbound listening by the FastAPI server (E32) is not egress and needs no exception, but the server may not import client libraries either.

### Request flow

1. A provider adapter's `prepare(task, payload)` builds a `PreparedRequest` from a `SanitisedPayload` (I2). It does not send.
2. The egress guard inspects the `SanitisedPayload` (residual secrets, vault identifiers, domain terms, size and aggregation budgets) and, if every check passes, issues an `EgressTicket` bound to the payload hash.
3. The ledger appends a hash-chained `EgressRecord` and stores the payload locally.
4. The transport verifies the ticket and sends the request to the provider.
5. The adapter's `parse(raw)` reads the response into an `LLMVerdict`.

### Vendor SDKs

Provider SDKs perform their own sending, which conflicts with "adapters build, transport sends". Vendor SDKs may therefore be imported only by the transport module. E22 must either build plain HTTP requests in the adapters or host SDK calls inside the transport behind the ticket check, and records its choice in its own ADR. The vendor-SDK entries in the contracts are provisional until then.

### Fail closed

If the guard, the ledger or the ticket check raises, nothing is sent (I4). The candidate is still reported from deterministic evidence.

### Ledger completeness

Every send has exactly one `EgressRecord`. A send without a record is a security vulnerability to be reported under `SECURITY.md`.

### Exception procedure

A module that needs outbound network access is granted it only by an amendment record: a new ADR that supersedes nothing, is linked from this record and from the index, and states:

- exactly one module (for example `codekavach.integrations.github.client`), never a package wildcard;
- the destination class (for example "the client's own GitHub instance");
- why client code, secrets or vault contents cannot flow to that destination;
- the enforcement change (the `ignore_imports` line and the ruff per-file exemption) that implements it.

Granted exceptions:

| Module | Destination class | Granted by |
|--------|-------------------|------------|
| `codekavach.privacy.egress.transport` | Configured LLM provider endpoints | This record |

Expected future requests, none granted yet:

| Need | Owning epic |
|------|-------------|
| Advisory database download for SCA | E19 |
| GitHub client for issue and Projects sync; it sends finding text to the client's own repository | E34 |
| Dataset download for the evaluation harness | E36 |
| KMS access for vault keys | E10 |

### Consequences (positive, negative, neutral)

- Positive: the ledger can be complete by construction; a new network path cannot appear without a failing CI check and an ADR; review of privacy-relevant changes concentrates on one module.
- Negative: features that need the network pay the cost of an amendment record; vendor SDKs cannot be used in the familiar way.
- Neutral: the rule covers more than LLM traffic, so the wording of I1 is narrower than its enforcement. The invariant text is left unchanged.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

1. **Static.** An import-linter forbidden contract over external network client packages (`.importlinter`, contract `i1-single-egress`), plus ruff `TID251` banned-API entries for standard-library modules that import-linter cannot distinguish (`urllib.request`, `http.client`, `socket`, `ssl`, `ftplib`, `smtplib`, `xmlrpc.client`) and for namespace-package SDKs (E01-14). The contracts are self-tested with planted violations in `tests/privacy/test_import_contracts.py` (E01-15).
2. **Test-time.** Sockets are disabled in the test process (`tests/privacy/test_network_blocked.py`, E01-08), and importing any `codekavach` module has no network side effects (`tests/privacy/test_import_purity.py`, E01-08). E12 adds a process-level test that a full scan with the mock provider touches the network only through the transport.
3. **Runtime.** The transport refuses to send without a valid, unexpired, single-use `EgressTicket` bound to the payload hash (E12).

Known gaps:

- Dynamic imports (`importlib.import_module`, `__import__`) and native extensions bypass the static checks.
- Child processes bypass the in-process socket block.
- External analysis engines are separate programs; ADR-0002 handles them (no network in the sandbox).
- Third-party plugins loaded through entry points run in-process and could open sockets; plugin trust is handled in E04 and E40.

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

Strengthened. I1 is enforced for all network clients, not only for connections to LLM endpoints. The record also applies I4 (a failure in the guard, ledger or ticket check blocks the send) and I2 (adapters receive `SanitisedPayload` only). It must not be relaxed by a later issue without a superseding ADR.

## Implementation notes (optional; the only section that may grow after acceptance)

## Links

- `docs/ARCHITECTURE.md` sections 1, 6.2 (steps 6 to 8), 6.3 (I1, I2, I4), 7 and 8
- `docs/PLAN.md` section 4 (principles 2 and 7)
- `AGENTS.md` section 4
- ADR-0002 (external engines as subprocesses)
- import-linter, ruff `TID251`, pytest-socket
