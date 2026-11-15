# Verifying an installation: the offline self-test

One command runs the whole product on the bundled sample application and checks the result, without a key and without a network connection. Use it after installing or upgrading, and whenever you want evidence that the privacy layer on this machine behaves as documented.

```console
$ uv run codekavach demo --out selftest-out
```

The command scans the sample bank application in `fixtures/kavachbank` with the `mock` provider. The mock answers on the machine and opens no connection, so the ledger shows what **would** have been sent to a model, not what was. The summary, the inspection page and the report all say so. Ambient `CODEKAVACH_*` settings are ignored, and any provider other than `mock` or `replay` is refused.

It takes under a minute on a laptop. A passing run ends with a summary that contains `zero_leak_passed  True` and exits 0. The command exits non-zero when a listed term occurs in any ledger payload, when the ledger does not verify, or when the scan fails.

## What it writes

Below the `--out` directory:

| File | What it is |
|------|------------|
| `inspect.html` | Original code and the exact payload side by side, with redactions and renames marked. It contains the sample's code. |
| `verification.txt` | The ledger chain check, the payload hash check and the zero-leak check, one line each. |
| `report.html` | The report: executive summary, risk matrix, findings with snippet evidence, privacy attestation. |
| `report.pdf` | The same report as a PDF. Written when the PDF engine's system libraries are installed; otherwise the summary says why it was skipped. |

Both HTML pages load nothing from the network. `--keep-state` keeps the scan's state directory for the manual sequence below.

## What a passing run shows, and what it does not

1. **A scan with no key.** The summary's provider line reads `mock`.
2. **Findings on the real files.** In `report.html` each finding names the original path, line and identifier, although the payloads contain only pseudonyms. The mapping was restored locally from the vault.
3. **Side by side.** In `inspect.html`, secrets are typed placeholders, identifiers are renamed, and only the slice around the finding is present, not the file.
4. **No listed value in the ledger.** In `verification.txt` the line `terms` says how many listed terms were searched in every ledger payload and that none occurs. The list is the sample's `ground-truth/terms.txt`: its planted secrets and business terms.

The zero-leak check is verbatim only. A paraphrased, split or encoded term would not be found, and structure (control flow, libraries, the shape of the code) is still disclosed at L3; the report's section "What this attestation does not cover" says so, and `codekavach eval leakage` measures structure. See [Known limits](../../README.md#known-limits).

## The same sequence by hand

One command at a time, on a throw-away copy of the sample, from the repository root (`<repo>` is the path of the checkout):

```console
$ cp -r fixtures/kavachbank /tmp/kb && rm -rf /tmp/kb/ground-truth && mkdir /tmp/kb/.git
$ export CODEKAVACH_HOME=/tmp/kb-home CODEKAVACH_DEMO_PASSPHRASE="$(openssl rand -hex 16)"
$ export CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE=passphrase CODEKAVACH_PRIVACY__VAULT__PASSPHRASE=env:CODEKAVACH_DEMO_PASSPHRASE
$ cd /tmp/kb
$ uv run --project <repo> codekavach scan . --provider mock
$ uv run --project <repo> codekavach privacy inspect . --list
$ uv run --project <repo> codekavach privacy inspect . --html inspect.html
$ uv run --project <repo> codekavach privacy ledger verify . --check-terms <repo>/fixtures/kavachbank/ground-truth/terms.txt --include-blocked
$ uv run --project <repo> codekavach report . --format html,pdf
```

The scan exits 1 when it finds anything at or above the `high` threshold; that is the planted findings, not a fault (`--fail-on none` turns the gate off). The vault needs a key source that works without a keyring prompt, hence the passphrase variables. `--include-blocked` matters when a payload is blocked by the guard: without it every hit in a blocked payload would be excused as "blocked, not sent". The self-test sets it. The [command-line tour](cli-tour.md) runs a longer version of this sequence with a line of explanation per step.

## If it fails

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `error[demo_verification_failed]` | A listed term occurs in a ledger payload, or the ledger does not verify | Read `verification.txt`; the line that says `FAILED` names the term's line in `terms.txt` and the payload hash. Do not send code to a hosted provider from this installation until it is understood; report it as described in [`SECURITY.md`](../../SECURITY.md). |
| `error[fixture_not_found]` | The sample project is not where the command looks | Run from the repository root or pass `--fixture PATH`. |
| `error[demo_remote_provider]` | The settings select a remote provider | The self-test only runs offline; check the project configuration. |
| `pdf: the PDF engine is not available` | Pango libraries missing | `apt install libpango-1.0-0 libpangoft2-1.0-0` (or `brew install pango`). The HTML report is complete without it; you can also print it to PDF from a browser. |

## Replay

The `replay` provider answers from recorded responses, keyed by payload hash, in `fixtures/kavachbank/cassettes/`. The self-test scans under a fixed salt, so the payload hashes are stable and the cassettes answer every payload of the sample. A replay run reproduces the mock run: the same findings and the same number of reviewed candidates, which `tests/integration/test_demo_replay.py` asserts on every push. Like the mock, replay answers on the machine and opens no connection, and the ledger shows what would have been sent.

When a change to the redactor, the pseudonymiser or the slicer alters a payload, its cassette no longer matches. A replay miss is an error, not a fallback to the mock, and the drift check fails:

```console
$ uv run python tools/gen_cassettes.py --check
$ uv run python tools/gen_cassettes.py
```

The first command lists every cassette that is missing, unused or different. The second rewrites the directory from a fresh scan on the mock provider; it is refused when `CI` is set, so a pipeline cannot rewrite the cassettes it replays. Review the diff before committing it.
