# Developer scripts

Stand-alone scripts for contributors. They are not part of the shipped package and use only the standard library unless stated. Every issue that adds a script here appends a row.

| Script | Purpose | Makefile target | Owning issue |
|--------|---------|-----------------|--------------|
| `check_commit_msg.py` | Check commit messages against the convention of `AGENTS.md` section 5: a message file (the `commit-msg` hook), `--range A..B`, or `--ci` for the commits of a CI event | none; runs as the pre-commit hook `commit-msg-format` and as the CI job `commits` | #30 (E01-19) |
| `new_adr.py` | Create the next numbered ADR from the template and register it in `docs/adr/README.md`; `--check` verifies the index against the record files | `make adr title="..."` (added by E01-16) | #20 (E01-09) |
