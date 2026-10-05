# CLI help snapshots

Owning epic: E05 (issue E05-30).

Option names and help text of `codekavach` are a public contract: the GitHub Action, the editor extension, the pre-commit hook and users' scripts depend on them. Each command path therefore has a committed copy of its `--help` output, and a test compares the two. A change to the help text shows up as a diff in the commit that causes it.

## What is compared

`tests/unit/cli/test_help_snapshots.py` walks the command tree of `build_cli()` (the root, every group and every leaf command; hidden commands are left out) and runs one test per path. The expected text is in `tests/unit/cli/snapshots/help/<path-joined-by-dash>.txt`; the root help is `root.txt`.

The help is rendered through the CLI test harness (`tests/support/cli.py`): width 100, no colour, `TERM=dumb`, a temporary home directory and the program name `codekavach`. Trailing whitespace is removed from every line and the text ends with one newline. Rendering is made the same on all platforms: on Windows, Rich would otherwise draw redirected output one column narrower and with square boxes.

Further tests check that

- no snapshot file is left without a command (orphan check);
- no snapshot contains an ANSI escape sequence, a line longer than 100 characters or an absolute path;
- `root.txt` still contains the one-sentence description, the `Global options` block, the exit-code table and the name of every top-level command that `build_cli()` registers.

## When a diff is expected

- You added, renamed or removed a command or an option, or changed a help string, a default or a choice list.
- You changed a global option: every snapshot changes, because each command lists the global options.
- A dependency upgrade (Typer, Rich) changed the rendering. Update the snapshots in the same commit as the `uv.lock` change and say so in the commit message.

A diff you did not expect is the point of the test: find out which change caused it before updating anything.

## Updating

```bash
CODEKAVACH_UPDATE_SNAPSHOTS=1 uv run pytest tests/unit/cli/test_help_snapshots.py
uv run pytest tests/unit/cli/test_help_snapshots.py
git diff tests/unit/cli/snapshots/help
```

The first command rewrites the files and fails every snapshot test with `snapshot written; re-run without CODEKAVACH_UPDATE_SNAPSHOTS`. This is intended: a run in update mode does not pass, so a pipeline cannot accept its own rewrite. The second command must pass. Read the diff of the third before committing; it is what reviewers and users will see.

When a command is removed, delete its snapshot file by hand; the orphan check names it.

## Messages

| Message | Meaning |
|---------|---------|
| `help text changed for 'scan':` followed by a unified diff | The rendered help differs from the snapshot. |
| `no snapshot for 'vault rotate'; run CODEKAVACH_UPDATE_SNAPSHOTS=1 uv run pytest tests/unit/cli/test_help_snapshots.py` | A command has no snapshot yet. |
| `snapshot without a command, delete it: <file>` | A snapshot file belongs to no command. |
| `snapshot written; re-run without CODEKAVACH_UPDATE_SNAPSHOTS` | Update mode wrote the file. |

## Changed option names

Renaming or removing an option or a command breaks callers. Besides the snapshot update, such a change needs a `changed` or `removed` fragment in `changelog.d/` that names the old and the new spelling (see `changelog.d/README.md`).

## Related

- Golden files for command output: `tests/README.md`.
- Global options: `docs/reference/cli-global-options.md`. Exit codes: `docs/reference/exit-codes.md`.
