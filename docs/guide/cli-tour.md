# Command-line tour

A guided run of the command line on the sample project, twelve steps from `--version` to a leakage measurement. [`scripts/demo-cli.sh`](../../scripts/demo-cli.sh) runs the real CLI on a throw-away copy of the synthetic `fixtures/kavachbank` project and prints, after every step, one line saying what the step shows. A recorded run is in the [transcript](cli-tour-transcript.md). The task-oriented guide to the same commands is [Using the command line](cli.md); the dashboard equivalent is the [walkthrough](walkthrough.md).

The script needs a checkout of the repository. It does not touch your project, ledger or vault: it copies the sample (without its answer key) to a work directory, points `CODEKAVACH_HOME` there and gives the vault a random passphrase that lives in the script's process only.

## Running it

```console
$ uv sync --all-extras
$ scripts/demo-cli.sh                    # Enter runs each step
$ scripts/demo-cli.sh --auto             # no pauses
$ scripts/demo-cli.sh --provider mock    # force the offline provider
$ scripts/demo-cli.sh --out ~/codekavach-tour   # keep the files (inspect.html, reports/)
```

With the `mock` provider the tour takes about a minute on an idle laptop and a few minutes on a busy one, and needs no network. A run ends with a tally such as `12 ok, 0 skipped, 0 failed`. `skipped` means a command is not in the installed build; the script says so and carries on.

The script uses colour only when its output is a terminal; `NO_COLOR=1` turns it off. A terminal at least 110 columns wide shows the tables without wrapping.

### With a real model

Put the key in the environment of your shell only, not in a file inside the repository:

```console
$ export CODEKAVACH_AGENTROUTER_API_KEY="$(cat /path/to/your/key-file)"
$ scripts/demo-cli.sh
```

When the variable is set, the script picks the `agentrouter` provider, adds `--accept-egress` for the probe and the scan, and says so in its banner. Otherwise it uses `mock`. At L3 the provider receives only the pseudonymised payloads that `privacy inspect` shows, and the ledger records every one. A run against a hosted model takes about ten minutes, because every payload is a round trip.

## The twelve steps

| # | Command | What it does | What it shows |
|---|---------|--------------|---------------|
| 1 | `codekavach --version` | Prints the installed version. | The tool is installed. |
| 2 | `codekavach doctor` | Checks runtime, parsers, storage, engines and providers. Optional parts warn and give an install hint. | The machine is ready; nothing fails silently. |
| 3 | `codekavach providers list` | Lists the providers with their locality and minimum privacy level. | Providers are explicit configuration. |
| 4 | `codekavach providers test <provider>` | Sends a constant probe that contains no code. | The provider answers, before the first real payload. |
| 5 | `codekavach scan .` | Engines find candidates, the model reviews slices. Exit code 1 means findings at or above `high`. | Findings on the planted issues; the summary names the provider and how many payloads were recorded or blocked. |
| 6 | `codekavach privacy inspect . --list` | Lists the payloads prepared for the provider. | A payload is a slice with pseudonyms. |
| 7 | `codekavach privacy inspect . --html inspect.html` | Writes a page with the original on the left and the payload on the right. | Secrets are typed placeholders, identifiers are renamed. |
| 8 | `codekavach privacy ledger verify . --check-terms terms.txt --include-blocked` | Verifies the hash chain and searches every payload for every listed term. | Chain intact, hashes match, zero verbatim occurrences. The check is verbatim only; structure still leaves, and step 12 measures it. |
| 9 | `codekavach privacy explain <file>` | Explains the privacy level of one file, rule by rule. | Privacy decisions can be traced to a rule. |
| 10 | `codekavach report . --format ...` | Renders one scan for several readers: HTML and PDF for people, SARIF for code scanning, XLSX for tracking, DOCX for editing. | The formats this build supports are produced; the script asks the build which ones. |
| 11 | `codekavach sync github --repo example-org/kavachbank --dry-run` | Shows the issues that would be created; the dry run changes nothing and needs no token. | The tracker integration. |
| 12 | `codekavach eval leakage --level L3` | Attacks the payloads and reports what is recovered. | Disclosure is measured, not asserted. |

Step 8 prints "the log cannot be edited unnoticed". Read that as "an edit to a recorded entry is detected": the chain is tamper-evident, not tamper-proof, as the [auditor guide](auditor-guide.md#5-inspecting-the-evidence-yourself) explains.

`doctor` shows two expected `WARN` lines on a laptop: `privacy:ner-model` (name recognition is an optional extra: install spaCy and `en_core_web_sm`) and `secrets:keyring` (headless and WSL machines have no secure keyring; the passphrase mode is used). Neither blocks a scan. Analysis engines that are not installed (`opengrep`, `bandit`, `eslint`) show as `SKIP` when not selected, and as `WARN` with an install hint when the project selects them.

## Troubleshooting

| Symptom | Cause | What to do |
|---------|-------|------------|
| `skipped: not in this build yet` on a step | The command is not in the installed version | Update the checkout and run `uv sync --all-extras`. |
| Step 5 ends `FAILED` with an exit code other than 0 or 1 | A pipeline error; the log path is printed | Open the log. When a privacy stage failed closed, the scan continues without model review and reports from deterministic evidence; the summary says so. |
| Step 4 says the provider is not configured or has no credential | The key variable is not set in this shell | `codekavach providers list` shows whether the key is set. |
| A hosted provider call fails (network, quota, 401 or 403) | The network or the key | Rerun with `--provider mock`; the ledger then shows what would have been sent. |
| `pdf` missing from the report step | Pango libraries missing | `apt install libpango-1.0-0 libpangoft2-1.0-0` (or `brew install pango`); the HTML report is complete without it. |
| `uv: command not found` | PATH | `export PATH=$HOME/.local/bin:$PATH`, or set `CODEKAVACH_BIN` to a `codekavach` executable. |

## Afterwards

Delete the `--out` directory (or the temporary directory the script prints): `inspect.html` and the reports contain the scanned code. The sample is synthetic, but the same files made from your own project hold your code.
