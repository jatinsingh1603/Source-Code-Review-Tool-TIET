# ADR-0003 exception: key-management access for the vault

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-10 |
| Deciders | CodeKavach maintainers |
| Issue | #213 (E10-03) |
| Affects | `docs/ARCHITECTURE.md` sections 2 and 6.3 (I1, I3); `codekavach.privacy.vault.kms`; `.importlinter`; `privacy.vault.kms.*` settings |

This record is an amendment to [ADR-0003](0003-single-egress.md) under its exception procedure. It supersedes nothing.

## Context and problem statement

`docs/ARCHITECTURE.md` section 2 lists an external key-management service as a key source of the mapping vault, next to the operating-system keyring and a passphrase. Reaching a service means an outbound connection, and ADR-0003 allows exactly one module to import a network client. The service is not an LLM endpoint, so the exception is not covered by the existing grant. Without a grant, the key source cannot be built; with a careless one, a second exit appears next to the egress transport.

## Decision drivers

- Organisations that keep master keys in a managed service (HashiCorp Vault transit or a service with the same wire format) need the vault to use it.
- The egress ledger stays a complete record of what leaves the machine for an LLM; this path must be provably unable to carry code, mappings or payloads.
- Nothing in a default or air-gapped installation may open a connection.

## Considered options

1. **No external key source.** Simplest, but organisations with a key-management policy cannot adopt the vault.
2. **Route the key service through the egress transport.** The transport is built for `SanitisedPayload` and a ledger entry per send; key operations are neither, and mixing them weakens the invariant that the transport is the LLM path.
3. **One dedicated module with its own enforced policy (chosen).** A single module, a destination class, a host allow-list, TLS, no redirects, a timeout, and an import contract that keeps every other vault module off the network.

## Decision outcome

`codekavach.privacy.vault.kms` is granted permission to import `httpx`. It is the only module of the vault package that may, and, with `codekavach.privacy.egress.transport`, the only module in `codekavach` that may.

**Destination class.** The key-management service named by `privacy.vault.kms.endpoint`, and only if the host of that endpoint is in `privacy.vault.kms.host_allowlist`.

**What crosses the connection.** Exactly one 32-byte vault data key per `wrap` call (so the service can seal it) and its sealed form per `unwrap` call, plus the service credential in a header. The data key is sent in the clear inside TLS on `wrap`; the service therefore sees it, as any transit-style service does. No client code, no mapping, no pseudonym, no original, no file name and no scan content is an input of this module, and a test asserts that the request body holds one field. The master key never exists on this machine.

**Policy of the client, each enforced in code and asserted in tests against an in-process fake:**

- https only; any other scheme is refused when the client is built;
- the request host must be in the allow-list; an empty list refuses every host, and the check runs before anything is sent;
- certificate verification is on; ambient proxy and netrc settings are not read;
- redirects are not followed and a 3xx answer is an error;
- a timeout from `privacy.vault.kms.timeout_seconds` (0.5 to 30 s, default 5 s);
- an answer larger than 64 KiB, of the wrong shape, or carrying a key of the wrong length is an error whose message holds neither the credential nor the body.

**Availability.** The source is off by default (`key_source = "keyring"`). Selecting it in the `airgapped` profile is a configuration error (`CK-CFG-036`). A failure to reach the service fails the vault operation closed (I4); there is no fallback to another key source.

### Consequences (positive, negative, neutral)

- Positive: managed keys are possible without a second general-purpose network path; the exception is one file, reviewable in full.
- Negative: the service sees the data key at creation and rotation time; the adapter speaks one wire format, and other services implement `KmsClient`.
- Neutral: the ADR-0003 wording of I1 is unchanged; its enforcement gains one named exception.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

- `.importlinter`: contract `i1-single-egress` lists `codekavach.privacy.vault.kms -> httpx` in `ignore_imports`; the new contract `vault-network-only-in-kms` forbids network client libraries in `codekavach.privacy.vault` and ignores only that same edge.
- `tests/privacy/test_import_contracts.py` plants violations in a fake tree: a network import in another vault module breaks `vault-network-only-in-kms`; a network import elsewhere still breaks `i1-single-egress`; the granted edge passes.
- `tests/unit/privacy/vault/test_kms.py` covers each policy item above, and that a real connection is blocked by the test run's socket guard.
- `tests/unit/config/test_vault_kms.py` covers the settings rules, including the air-gapped refusal.
- Ruff's banned-API list (`socket`, `ssl`, `http.client`, `urllib.request`) still applies to this module; it needs no exemption because `httpx` is not on that list.

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

- I1: unchanged in meaning. The exception is not LLM traffic, is named, is limited to one module, and cannot carry a payload.
- I2: unchanged; the module does not touch `SanitisedPayload` or the LLM package.
- I3: unchanged; the vault's contents never reach this module. Only the data key, which protects them, does, and the vault stays unreadable without the service.
- I4: strengthened; every failure of the key service aborts the vault operation.
- I5 and I6: unchanged.

## Implementation notes

Cryptographic erasure ("crypto-shredding") by `destroy` removes the vault's own key entry; for a service-held key it cannot delete the key in the service, and says so in its result.

## Links

- [ADR-0003: Single egress](0003-single-egress.md)
- Issue #213 (E10-03)
