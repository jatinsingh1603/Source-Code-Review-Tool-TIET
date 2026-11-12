# Terminal demo runbook

One script, twelve steps, about ten minutes: [`scripts/demo-cli.sh`](../../scripts/demo-cli.sh). It runs the real CLI on a throw-away copy of the synthetic `fixtures/kavachbank` project and prints, after every step, one line saying what the step proves. A recorded run is in [`cli-transcript.md`](cli-transcript.md).

Audience is security people: say what was measured, and when something is "not measured yet", say so. Never claim more than [Known limits](../../README.md#known-limits) allows.

## Before the session

```console
$ git pull && uv sync --all-extras
$ uv run codekavach --version
$ scripts/demo-cli.sh --auto --out /tmp/rehearsal      # full dry run, no pauses, mock provider
```

- The script never touches your project, ledger or vault: it copies the fixture (without its answer key) to a work directory, points `CODEKAVACH_HOME` there and gives the vault a random passphrase that lives in the script's process only.
- A rehearsal that ends `0 failed` is the pass mark. `skipped` means a command is not in this build; the script says so and carries on.
- Make the terminal wide (at least 110 columns) and use a dark theme. The script uses colour only when stdout is a terminal; `NO_COLOR=1` turns it off.
- Network off is fine for the mock run (the PDF and HTML load nothing remotely).
- `doctor` shows two expected `WARN` lines on a laptop: `privacy:ner-model` (name recognition is an optional extra: install spaCy and `en_core_web_sm`) and `secrets:keyring` (headless or WSL machines have no secure keyring; the passphrase mode is used). Neither blocks a scan. Missing analysis engines (`opengrep`, `bandit`, `eslint`) show as `SKIP` when not selected, and as `WARN` with an install hint when the project selects them.

## Running it

```console
$ scripts/demo-cli.sh                    # presenter mode: Enter runs each step
$ scripts/demo-cli.sh --auto             # no pauses
$ scripts/demo-cli.sh --provider mock    # force the offline provider
$ scripts/demo-cli.sh --out ~/demo-out   # keep the files (inspect.html, reports/)
```

With a real model, put the key in the environment of your shell only. Never in a file in the repository, never as a GitHub secret on this repository:

```console
$ export CODEKAVACH_AGENTROUTER_API_KEY="$(cat /path/to/your/key-file)"
$ scripts/demo-cli.sh
```

When the variable is set and the `agentrouter` provider exists in this build, the script picks it, adds `--accept-egress` for the probe and the scan, and says so in its banner. Otherwise it uses the mock. At L3 the provider receives only the pseudonymised payloads that `privacy inspect` shows; the ledger records every one.

## What to say, step by step

| # | Command | Say | Proves |
|---|---------|-----|--------|
| 1 | `codekavach --version` | One installable tool, versioned. | Installed. |
| 2 | `codekavach doctor` | A health check before anything runs: runtime, parsers, storage, engines, providers. Optional parts warn and give an install hint. | The machine is ready; nothing fails silently. |
| 3 | `codekavach providers list` | The model is a plug-in. Each provider has a locality and a minimum privacy level. | Providers are explicit. |
| 4 | `codekavach providers test <provider>` | A constant probe, no code, before the first real payload. | The provider answers. |
| 5 | `codekavach scan .` | Engines find candidates, the model reviews slices. The exit code 1 only means findings at or above `high`. | Findings on the planted issues; the summary names the provider and how many payloads were recorded or blocked. |
| 6 | `codekavach privacy inspect . --list` | This is exactly what would leave the machine. | A payload is a slice with pseudonyms. |
| 7 | `codekavach privacy inspect . --html inspect.html` | Open the page: original on the left, payload on the right. | Secrets are typed placeholders, identifiers are renamed. |
| 8 | `codekavach privacy ledger verify . --check-terms terms.txt --include-blocked` | A hash-chained log of every payload, and a search for every planted term in every payload. | Chain intact, hashes match, zero verbatim occurrences. Then say the limit: the check is verbatim only; structure still leaks and `eval leakage` measures it. |
| 9 | `codekavach privacy explain <file>` | Why this file is at this level, axis by axis. | Privacy decisions are explainable. |
| 10 | `codekavach report . --format ...` | One scan, several readers: HTML and PDF for people, SARIF for code scanning, XLSX for triage, DOCX for the client. | The formats that exist in this build are produced; the script asks the build which ones. |
| 11 | `codekavach sync github --repo example-org/kavachbank --dry-run` | Findings become issues on a board, and the dry run changes nothing. | The tracker integration, without a token. |
| 12 | `codekavach eval leakage --level L3` | Privacy measured, not asserted: attack the payloads and report what is recovered. | Measurement exists. Shown only when the command is in the build. |

## If something fails

| Symptom | Cause | What to do |
|---------|-------|------------|
| `skipped: not in this build yet` on a step | The command belongs to a feature that has not landed on the checkout | `git pull && uv sync --all-extras`; otherwise say nothing and move on. |
| Step 5 ends `FAILED` with exit code other than 0 or 1 | A pipeline error; the log path is printed | Open the log. For a stage that failed closed (`privacy-prepare`), the scan continues without it and reports from deterministic evidence; the summary says so. |
| `error[consent_required]` or egress refused on a remote provider | No consent for a remote provider | The script passes `--accept-egress` for remote providers. Confirm the key variable is set in this shell and the provider is enabled. |
| Remote provider call fails (network, quota, 401/403) | The venue's network, or the key | Rerun with `--provider mock`; the story is identical, and the ledger still shows what would have been sent. Never paste a key into the terminal output. |
| `pdf` missing from the report step | Pango libraries missing | `apt install libpango-1.0-0 libpangoft2-1.0-0` (or `brew install pango`); the HTML report is complete without it. |
| `uv: command not found` | PATH | `export PATH=$HOME/.local/bin:$PATH`, or set `CODEKAVACH_BIN` to a codekavach executable. |

## After the session

`rm -rf` the `--out` directory (or the `codekavach-demo-*` directory the script prints): `inspect.html` contains the fixture's code. The fixture is synthetic, so nothing real is in it, but the habit is the point.

The one-command offline variant, `codekavach demo`, and its checklist are in [`DEMO1.md`](DEMO1.md).
