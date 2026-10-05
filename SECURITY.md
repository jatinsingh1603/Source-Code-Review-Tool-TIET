# Security policy

CodeKavach asks organisations to trust it with their source code. A flaw that lets client code, a secret or a vault mapping reach an LLM provider is the worst failure this project can have. If you find one, please report it privately as described here.

## 1. Supported versions

Until version `1.0.0`, only the latest commit on `main` and the latest tagged release receive fixes. A table of supported versions will be added with `1.0.0`.

## 2. How to report

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. This needs no e-mail address and keeps the report private between you and the maintainers.

If that button is not visible, open a public issue that contains no technical details and asks for a private channel.

Do not put vulnerability details, client code, real secrets, or vault or ledger content in a public issue.

## 3. What to include

- The affected version or commit.
- The configuration: privacy level and provider type.
- A minimal reproduction that uses synthetic code and fake secrets only.
- What you observed and what you expected.
- Your assessment of the impact.

Severity is rated with CVSS v4.0, the method the product uses for its own findings (`docs/ARCHITECTURE.md` section 8).

## 4. Scope: what is treated as a vulnerability

Highest priority first.

1. **Any bypass of a privacy invariant** (`docs/ARCHITECTURE.md` section 6.3):
   - data reaching an LLM endpoint or any other network destination without passing the egress guard (I1);
   - raw code reaching `codekavach.llm` (I2);
   - vault contents in logs, reports, integrations or exports (I3);
   - a privacy step that fails open (I4);
   - an original identifier, literal or secret of length four or more in a ledger payload (I6).
2. A send that has no ledger record, or tampering with the ledger that the hash chain does not detect.
3. Prompt injection from repository content that exfiltrates data, suppresses or alters deterministic findings, or makes the tool act outside its task.
4. Code execution, path traversal, archive extraction or resource exhaustion through a malicious repository, rule pack, plugin, engine output or SARIF file.
5. Engine sandbox escapes; leakage of provider API keys or vault keys; weaknesses in vault cryptography or key handling.
6. Authentication, authorisation and multi-tenancy flaws in the server and dashboard; flaws in the GitHub App or Action that expose client repositories or tokens.
7. Supply-chain problems in this repository's build and release process.

## 5. Out of scope

- Vulnerabilities in `fixtures/kavachbank/` and other deliberately vulnerable samples. They are vulnerable on purpose.
- Missed detections and false positives. These are ordinary bugs: please open a normal issue.
- Findings that require an already compromised client machine or a malicious administrator.
- Vulnerabilities in third-party engines or providers themselves. Report them upstream, and tell us if our integration makes them worse.
- Output of automated scanners without a demonstrated impact.

## 6. What to expect

This is a university project, maintained alongside studies and teaching. The times below are targets, not commitments.

- An acknowledgement within seven days, and an initial assessment within fourteen.
- Fixes for bypasses of a privacy invariant take priority over all feature work.
- Coordinated disclosure, with a default embargo of ninety days or until a fix is released, whichever is sooner.
- Credit in the advisory and in the changelog, unless you prefer otherwise.

There is no bug bounty.

## 7. Good-faith research

Test only against your own installation and with synthetic data. Do not test against other people's deployments, against providers' production systems beyond normal API use, or with any client data.

## 8. Security-relevant design documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), section 6: the privacy layer, the invariants (6.3) and the threat model summary (6.4).
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): the full threat model, not written yet.
- [`docs/reference/cli-network-behaviour.md`](docs/reference/cli-network-behaviour.md): which commands can use the network, and through which component.
- [`docs/adr/0003-single-egress.md`](docs/adr/0003-single-egress.md) and [`docs/adr/0005-logging-and-no-telemetry.md`](docs/adr/0005-logging-and-no-telemetry.md).
