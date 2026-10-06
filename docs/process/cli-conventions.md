# CLI conventions

Rules for code under `src/codekavach/cli/`. They keep the command line fast and keep informational invocations harmless in any directory, including an untrusted repository.

## No back ends at module top level

A module in `codekavach.cli` imports only the standard library, `typer`, `rich` and other light `codekavach.cli` modules at top level. Anything that pulls in the configuration models, Pydantic, the store, the pipeline, plugins, the privacy layer, LLM clients or report renderers is imported inside the function that needs it. Imports needed only for annotations go under `if TYPE_CHECKING:`, with the annotations quoted.

```python
def scan_command(ctx: typer.Context, target: str = ".") -> None:
    """Scan a code base and print a severity summary."""
    from codekavach.cli.context import with_target  # lazy: loads the configuration models

    ...
```

**Why.** `codekavach --version`, `--help` and shell completion run on every TAB press and in every directory. They should be fast, and they should not import plugin code, read project configuration or touch the keyring (ARCHITECTURE section 6.4).

## Sub-commands are mounted lazily

The root group (`codekavach.cli.app.RootGroup`, a `LazyGroup` defined in the same module) lists its sub-commands in `LAZY_COMMANDS` as `name`, `module:attribute`, kind and short help.

- **Lazy import.** A command module is imported only when the command runs or its own help is shown.
- **Placeholders for listing.** Root `--help` and completion of command names use placeholders that carry the short help. A new command needs a row in the table, and its short help must equal the first paragraph of the command's docstring.
- **Global options.** These are attached when a command is resolved.

## Tests that keep it this way

- `tests/unit/cli/test_startup_imports.py` runs `--version`, `--help`, `scan --help` and a completion request in a fresh interpreter. It fails when a deny-listed package (Pydantic, SQLAlchemy, keyring, HTTP clients, report renderers, and the pipeline, plugin, privacy, LLM, analysis, report and integrations packages) appears in `sys.modules`. Pygments is not on the list: structlog imports it through `rich.traceback`.
- `tests/unit/cli/test_lazy_group.py` checks:
  - the order and listing;
  - import on first use;
  - unknown and broken targets;
  - short help against the real commands;
  - global options on lazy commands.
- `tests/perf/test_cli_startup.py` (marker `perf`) checks that the median of five runs is within 400 ms for `--version` and 600 ms for `--help`. The limits are scaled by `CODEKAVACH_PERF_FACTOR`, and the test is skipped with `CODEKAVACH_SKIP_PERF=1`.
