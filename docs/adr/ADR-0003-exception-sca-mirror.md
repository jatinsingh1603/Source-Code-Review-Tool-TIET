# ADR-0003 exception: advisory mirror refresh for software composition analysis

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-13 |
| Deciders | CodeKavach maintainers |
| Issue | #237 (E19-01) |
| Affects | `codekavach.analysis.sca.update`; `codekavach sca update`; `pyproject.toml` per-file lint exemption |

This record is an amendment to [ADR-0003](0003-single-egress.md) under its exception procedure. It supersedes nothing.

## Context

Matching dependencies against known vulnerabilities needs advisory data. Sending the dependency list of a client to a lookup service would disclose the supplier and architecture of the system, so advisory data comes to the machine instead: a snapshot of the public OSV database, the CISA KEV catalogue and the FIRST EPSS scores, stored under the user data directory. Fetching a snapshot is an outbound connection that is not an LLM request.

## Decision

`codekavach.analysis.sca.update` may use the standard-library `urllib.request` (the lint ban TID251 is lifted for this one file). It is the only module outside the egress transport that does.

- **Destination class.** Public vulnerability data only: `osv-vulnerabilities.storage.googleapis.com`, `www.cisa.gov`, `epss.empiricalsecurity.com`. Any other host is refused, and so is any non-HTTPS URL; redirects are followed only to a listed host.
- **What crosses the connection.** A GET request for a fixed snapshot file per ecosystem. No package name, version, project name or path is part of any request, and a test asserts the allow-list.
- **When.** Only when the user runs `codekavach sca update`. A scan never fetches. `--offline` and `CODEKAVACH_OFFLINE` make the command fail before any connection.
- **No LLM path.** The module imports nothing from `codekavach.llm` or the privacy layer, and the `dependencies` and `sbom` artefact keys are raw-data keys that no LLM-category stage may require.

## Consequences

The egress ledger still records every LLM request. This path is visible in the shell history and in the snapshot stamp (`snapshot.json`) written next to the mirror. A scan with no snapshot uses the small seed shipped with the package and says so in the finding text.
