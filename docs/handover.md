# Hand-over: CodeKavach as delivered

For the team that receives CodeKavach at the Thapar Institute of Engineering and Technology: what is delivered, which versions, how to check that what you received is what was built, what to do before the first real use, and where the limits are. Installation is in the [Quickstart](guide/quickstart.md); running it day to day is in [Operations](guide/operations.md).

## What is delivered

| Item | Where | Notes |
|------|-------|-------|
| Source code | The repository `https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET`, branch `main` | MIT licence. Python core in `src/codekavach`, dashboard in `ui/`, VS Code extension in `extensions/vscode`, GitHub Action in `action/`. |
| Release files | The repository's Releases page | Wheel, source distribution, the VS Code extension (`.vsix`), a sample report (`codekavach-sample-report.zip`) and `SHA256SUMS`. |
| Server image | `ghcr.io/jatinsingh1603/codekavach` (amd64 and arm64) | Dashboard, REST API and CLI in one image. Tags: `main`, `sha-<short commit>`, and `<version>` plus `latest` on release tags. Each push carries an SBOM and a build provenance attestation. |
| Deployment files | `docker-compose.yml`, `.env.example`, `deploy/` | Compose stack with the `local-llm` and `airgapped` profiles, a Helm chart and the air-gapped bundle builder. |
| Sample projects | `fixtures/kavachbank`, `fixtures/demo-ledgerly`, `fixtures/demo-shopfront`, `fixtures/polyglot` | Synthetic and deliberately vulnerable, with planted fake secrets and a ground-truth manifest each. They are test and sample data. Do not deploy them, and do not treat their contents as findings about the product. |
| Sample reports | `docs/samples/kavachbank/` | Every report format from one scan of KavachBank, with an integrity manifest. |
| Documentation | `README.md`, `docs/` | Guides in [`docs/guide/`](guide/index.md), reference in `docs/reference/`, architecture and decision records in [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) and [`docs/adr/`](adr/README.md), limits in [`docs/KNOWN-LIMITATIONS.md`](KNOWN-LIMITATIONS.md). |
| Tests and evaluation | `tests/`, `codekavach eval`, [`docs/research/results/`](research/results/README.md) | The test suite (including the privacy invariant tests), the evaluation harness and its committed results. |

Not delivered: a model API key. CodeKavach runs offline with the `mock` provider and with local models; for a hosted model you use your own key. No credential of the authors is in the repository, the image or the release files.

## Versions

| Component | Version |
|-----------|---------|
| CodeKavach | Printed by `codekavach --version`, and shown on the dashboard's **Admin**, **System health** page. The version in this repository is the `version` field of `pyproject.toml`. |
| Python | 3.12 or 3.13 |
| Node.js (to build the dashboard or the extension from source) | 22 |
| Docker (for the container deployment) | 24 or newer, with the compose plugin |
| Opengrep (optional engine, in the image) | 1.33.1 |
| Bandit (optional engine, in the image) | 1.9.4 |
| Python and JavaScript dependencies | Pinned with hashes in `uv.lock`, `ui/package-lock.json` and `extensions/vscode/package-lock.json` |
| Container base images | Pinned by digest in `deploy/docker/Dockerfile` |

Changes between versions are in [`CHANGELOG.md`](../CHANGELOG.md); changes since the last release are the fragments in `changelog.d/`.

## Verifying integrity

Check before you install, on the machine that will run it.

**Release files.** Download the files and `SHA256SUMS` from the release, then:

```console
$ sha256sum -c SHA256SUMS --ignore-missing
```

Every file you downloaded must be reported as `OK`.

**Source.** The delivered state is a commit on `main`. Record its hash and compare it with the hash named in the hand-over message:

```console
$ git rev-parse HEAD
$ git status --short        # prints nothing on an unmodified checkout
```

**Server image.** The published image is an index with one manifest per platform and an attestation manifest for each. Read its digest and its build provenance, which names the commit it was built from:

```console
$ docker buildx imagetools inspect ghcr.io/jatinsingh1603/codekavach:main
$ docker buildx imagetools inspect ghcr.io/jatinsingh1603/codekavach:main --format '{{json .Provenance}}'
```

The first command prints the digest (`sha256:...`); run the image by that digest (`ghcr.io/jatinsingh1603/codekavach@sha256:...`) so that a moved tag cannot change what you run. In the provenance, `build-arg:REVISION` is the commit. The same commit is on the pulled image as a label: `docker inspect --format '{{json .Config.Labels}}' <image>`. With the GitHub CLI signed in, `gh attestation verify oci://ghcr.io/jatinsingh1603/codekavach:main -R jatinsingh1603/Source-Code-Review-Tool-TIET` also checks the signature on the attestation. An image you build yourself from the checkout (`docker compose up -d --build`) needs no such check: it is built from the source you verified.

**Air-gapped bundle.** The bundle carries its own checksum file, and its installer checks every file against `SHA256SUMS` before it does anything else ([Installation](guide/install.md#air-gapped-bundle)).

**Sample reports.** `sha256sum -c SHA256SUMS` in `docs/samples/kavachbank/`.

**The installation itself.** After installing, run the offline self-test ([Verifying an installation](guide/selftest.md)). It scans the bundled sample, verifies the egress ledger and searches every payload for the sample's planted secrets and terms; it must end with `zero_leak_passed  True`.

## Before the first real use

- [ ] The administrator account has a password that only your administrators know ([Quickstart](guide/quickstart.md#first-sign-in)).
- [ ] The vault passphrase is set or the generated one is backed up ([Operations](guide/operations.md#credentials-and-keys)). Without it, old scans cannot be mapped back to real names.
- [ ] `.env` is not in git: `git status` shows it as ignored or untracked.
- [ ] The dashboard is reachable only from where you intend. The default bind address is `127.0.0.1`; put a reverse proxy with TLS in front before you use another address.
- [ ] The organisation policy is in place: the minimum privacy level, `never-send` paths and the approved providers ([organisation policy](configuration/organisation-policy.md)).
- [ ] A backup of the data volume was made and a restore was rehearsed ([Operations](guide/operations.md#backup-and-restore)).
- [ ] The first scan of real code was made with **No-send (dry run)** at L3, and a person read the payloads in Privacy Inspect before anything was sent to a hosted provider.
- [ ] The people who will use it have read "Known limits" in the [README](../README.md#known-limits).

## Known limitations

State these to your users; none of them is hidden by the product.

- **Disclosure is reduced and measured, not eliminated.** At L2 and L3 the control flow of a slice, the shapes of literals and the names of public library APIs are visible to the provider. The zero-leak check is a verbatim search. See [Known limits](../README.md#known-limits) and the [whitepaper](guide/whitepaper.md).
- **L4 is not delivered.** A scan at L4 fails closed: nothing is sent and every candidate is withheld.
- **The egress ledger is tamper-evident, not tamper-proof.** Someone who can write to the scan's directory can truncate or recompute the chain. Keep the head hash printed in each report outside the server.
- **Detection quality is that of the engines and rules present.** Opengrep, Bandit and ESLint are optional; a scan without them reports fewer findings and says so in its log. On the small sample projects the scanner finds most planted flaws, not all, and flags some safe code. Measured figures are in the [evaluation results](research/results/README.md); no detection rate is claimed beyond them.
- **The `mock` provider has no judgement.** A scan with it exercises the pipeline and shows what would be sent; its verdicts say nothing about the code.
- **One server process.** The server keeps its state in SQLite on one volume and runs as one replica. It has no built-in TLS, single sign-on or e-mail notifications; put it behind your own reverse proxy.
- **The dashboard does not offer diff scans**; they are a command-line feature (`codekavach scan --diff-since`).
- **The VS Code extension** talks to the command line only, is not on the Marketplace, and its installation was not exercised on the build machine ([VS Code guide](guide/vscode.md#verification-status)).
- **The GitHub Action with a hosted provider** was checked locally, not on GitHub, because the repository stores no key ([GitHub Action guide](guide/github-action.md)).
- **Audit findings that were recorded and not fixed** are listed, with their severity and the reason, in [`KNOWN-LIMITATIONS.md`](KNOWN-LIMITATIONS.md).

## Support

- **Questions and defects.** Open an issue in the repository. State the version (`codekavach --version`), the command or the dashboard page, the error code and, if you can, the output of `codekavach doctor`. Do not paste code from a confidential project, keys, vault files or ledger payloads into an issue.
- **Vulnerabilities.** Report them privately as described in [`SECURITY.md`](../SECURITY.md). A bypass of a privacy invariant counts as a vulnerability.
- **Supported versions.** Until version 1.0.0, the latest commit on `main` and the latest tagged release receive fixes.
- **Changing the product.** [`CONTRIBUTING.md`](../CONTRIBUTING.md) goes from a clone to a first commit; [`AGENTS.md`](../AGENTS.md) holds the rules, including the privacy invariants that a change must not weaken.
