# Developer scripts

Stand-alone scripts for contributors. They are not part of the shipped package and use only the standard library unless stated. Every issue that adds a script here appends a row.

| Script | Purpose | Makefile target | Owning issue |
|--------|---------|-----------------|--------------|
| `check_changelog_fragments.py` | Check that the files in `changelog.d/` are named `<issue>.<type>.md` or `+<slug>.<type>.md` with a Keep a Changelog type and are not empty | `make changelog-check` | #33 (E01-22) |
| `check_docs.py` | Check Markdown files offline: relative links (`DOC001`), heading anchors (`DOC002`), stale pending entries (`DOC003`), attribution phrases (`DOC004`), emoji (`DOC005`), local absolute paths (`DOC006`); `--claims` lists lines with claim words for the pre-push review | `make docs-check`, `make claims files="..."` | #34 (E01-23) |
| `check_licences.py` | Classify the licence of every installed distribution against `[tool.codekavach.licences]` in `pyproject.toml`: the runtime closure must be allowed or a recorded exception, dev-only tools (`--include-dev`) fail only when denied; `--format json` for the notices file (E39) | `make licences`; CI job `licences` | #41 (E01-30) |
| `check_no_telemetry.py` | Fail when a package in `uv.lock` matches the telemetry deny list of `[tool.codekavach.telemetry]` in `pyproject.toml` without a complete exception (reason, `verified_by`, `approved_in`) | `make telemetry-check`; CI `lint` job | #42 (E01-31) |
| `check_commit_msg.py` | Check commit messages against the convention of `AGENTS.md` section 5: a message file (the `commit-msg` hook), `--range A..B`, or `--ci` for the commits of a CI event | none; runs as the pre-commit hook `commit-msg-format` and as the CI job `commits` | #30 (E01-19) |
| `forbid_runtime_artefacts.py` | Reject staged paths that are runtime artefacts or local secrets: `.codekavach/` state, vaults, ledgers, scan and report output directories, `.env` files other than `.env.example`, key files outside the fixture directories | none; runs as the pre-commit hook `forbid-runtime-artefacts` | #28 (E01-17) |
| `importtime_report.py` | Run `python -X importtime` on the CLI start-up path (`--target`, default `codekavach.cli.app`) and print the slowest imports by cumulative time (`--top`, default 20); used when `tests/unit/test_import_budget.py` fails | none | #43 (E01-32) |
| `new_adr.py` | Create the next numbered ADR from the template and register it in `docs/adr/README.md`; `--check` verifies the index against the record files | `make adr title="..."` (added by E01-16) | #20 (E01-09) |
