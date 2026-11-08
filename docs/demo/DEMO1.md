# Demo 1 runbook

Owning epic: E13. This is the script for the Demo 1 review: what to run, what to say for each exit criterion in [`docs/PLAN.md`](../PLAN.md), and what to check beforehand.

The demo scans the sample bank application in `fixtures/kavachbank` with the **mock provider**. The mock answers on the machine and opens no connection, so no API key is needed and nothing leaves the laptop. The ledger therefore shows what **would** have been sent to a model, not what was. Say this at the start; the tool says it too, in its summary, in the inspection page and in the report.

## One command

```console
$ uv sync --all-extras
$ uv run codekavach demo --out demo-out
```

It takes under a minute on a laptop (the CI job allows three). It writes, below `demo-out/`:

| File | What it is |
|------|------------|
| `inspect.html` | Original code and the exact payload side by side, redactions and renames marked. Contains the fixture's code; keep it on the machine. |
| `verification.txt` | The ledger chain check, the payload hash check and the zero-leak check, one line each. |
| `report.html` | The report: executive summary, risk matrix, findings with snippet evidence, privacy attestation. |
| `report.pdf` | The same report as a PDF. Written when WeasyPrint and its system libraries are installed; otherwise the summary says why it was skipped. |

The command exits non-zero when a listed term occurs in any ledger payload, when the ledger does not verify, or when the scan fails. Use `--keep-state` to keep the state directory for the manual path below.

The demo ignores ambient `CODEKAVACH_*` settings and refuses any provider other than `mock` or `replay`.

## Manual path

The same sequence, one command at a time, for when the audience wants to see each step. Run it from the repository root.

```console
$ uv run codekavach scan fixtures/kavachbank --no-send
$ uv run codekavach privacy inspect fixtures/kavachbank --list
$ uv run codekavach privacy inspect fixtures/kavachbank --html inspect.html
$ uv run codekavach privacy ledger verify fixtures/kavachbank --check-terms fixtures/kavachbank/ground-truth/terms.txt --include-blocked
$ uv run codekavach report fixtures/kavachbank --format html --format pdf
```

`--include-blocked` matters with `--no-send`: nothing is sent, so without it every hit would be excused as "blocked, not sent". The one-command demo sets it.

## Talking points per exit criterion

1. **A scan with no paid key.** `codekavach demo` completes with the mock provider. Point at the provider line in the summary.
2. **The sample application.** `fixtures/kavachbank` holds planted vulnerabilities, planted secrets and an interest and fee engine. `fixtures/kavachbank/ground-truth/manifest.yaml` lists every planted value and where it is.
3. **Side by side.** Open `inspect.html`. Left: the code as it is. Right: the payload. Secrets are typed placeholders (red), identifiers are renamed (blue), and only the slice around the finding is present, not the file.
4. **No planted value in the ledger.** Open `verification.txt`: the line `terms` says how many listed terms were searched in every ledger payload and that none occurs. The check is verbatim only. A paraphrased, split or encoded term would not be found, and structure (control flow, libraries, the shape of the code) is still disclosed; the report's "What this attestation does not cover" says so, and `codekavach eval leakage` (epic E37) measures structure. State that the mock run shows what would have left.
5. **Findings on the real files.** In `report.html` each finding names the original path, line and identifier, although the model only saw pseudonyms. The mapping was restored locally from the vault.
6. **HTML and PDF.** `report.html` and `report.pdf`: summary, risk matrix, findings with snippets, remediation, and the privacy attestation.

## Rehearsal checklist

- [ ] `git pull` and `uv sync --all-extras` on the demo machine; `uv run codekavach --version` works.
- [ ] `uv run codekavach demo --out demo-out` exits 0 and prints `zero_leak_passed  True`.
- [ ] `demo-out/report.pdf` exists. If the summary says the PDF engine is not available, install the Pango libraries (`apt install libpango-1.0-0 libpangoft2-1.0-0`, or `brew install pango`) or show `report.html` and print it to PDF from the browser.
- [ ] Open `inspect.html` and `report.html` in the browser the day before; both load nothing from the network.
- [ ] Turn the network off and run the demo once more; the result is the same.
- [ ] Delete `demo-out/` after the session if the machine is shared: `inspect.html` holds the fixture's code.

## If something fails

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `error[demo_verification_failed]` | A listed term occurs in a ledger payload, or the ledger does not verify | Read `demo-out/verification.txt`; the line that says `FAILED` names the term's line in `terms.txt` and the payload hash. Do not run the demo on stage until it is understood. |
| `error[fixture_not_found]` | Run outside a checkout | Run from the repository root or pass `--fixture PATH`. |
| `error[demo_remote_provider]` | The settings select a remote provider | The demo only runs offline; check the project configuration. |
| `pdf: the PDF engine is not available` | Pango libraries missing | See the checklist; the HTML report is complete without it. |

## Replay

The `replay` provider answers from recorded responses, keyed by payload hash, in `fixtures/kavachbank/cassettes/`. The demo scans under a fixed salt, so the payload hashes are stable and the cassettes answer every payload of the fixture. A replay run reproduces the mock run: the same findings and the same number of reviewed candidates, which `tests/integration/test_demo_replay.py` asserts on every push. Like the mock, replay answers on the machine and opens no connection, and the ledger shows what would have been sent.

The `demo` command itself runs on the mock provider. The replay run is `run_demo(fixture, out, provider="replay", send=True)` from Python, which is how the test does it.

When a change to the redactor, the pseudonymiser or the slicer alters a payload, its cassette no longer matches. A replay miss is an error, never a fallback to the mock, and the drift check fails:

```console
$ uv run python tools/gen_cassettes.py --check
$ uv run python tools/gen_cassettes.py
```

The first command lists every cassette that is missing, unused or different. The second rewrites the directory from a fresh scan on the mock provider; it is refused when `CI` is set, so a pipeline cannot rewrite the cassettes it replays. Review the diff before committing it.
