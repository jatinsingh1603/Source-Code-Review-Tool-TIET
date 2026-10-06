"""Shell completion: the ``completion`` command, the completion request handler and value lists.

Owning epic: E05.

``codekavach completion SHELL`` prints a completion script for bash, zsh, fish or PowerShell
(see ``docs/reference/cli-completion.md``). The shell then calls ``codekavach`` with the
environment variable ``_CODEKAVACH_COMPLETE`` set on every TAB press; ``run()`` hands such a
request to ``handle_request`` before any of CodeKavach's own processing, so no configuration is
loaded for command and option names.

Typer 0.27 vendors a reduced Click without its own shell classes; the four classes come from
Typer and are registered by ``typer._completion_classes.completion_init``. Click 8 spells an
instruction ``bash_complete``, the Typer scripts ``complete_bash``; both are accepted.

Value callbacks run on every TAB press. They are fast and silent: no logging, no network, no
keyring and no plugin discovery. Configured names (profiles, providers) are read with a time
budget, and any error falls back to the built-in names.
"""

import contextlib
import io
import os
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Annotated, Any

import typer
from typer import _click as click

from codekavach.cli import output
from codekavach.cli.errors import UsageError

PROG_NAME = "codekavach"
COMPLETE_VAR = "_CODEKAVACH_COMPLETE"
SHELLS = ("bash", "zsh", "fish", "powershell")
SHELL_ALIASES = {"pwsh": "powershell", "powershell": "powershell"}
CONFIG_BUDGET_SECONDS = 0.2
INSTALL_LINES = {
    "bash": "codekavach completion bash > ~/.local/share/bash-completion/completions/codekavach",
    "zsh": 'codekavach completion zsh > "${fpath[1]}/_codekavach"  '
    "# then: autoload -U compinit && compinit",
    "fish": "codekavach completion fish > ~/.config/fish/completions/codekavach.fish",
    "powershell": "codekavach completion powershell >> $PROFILE",
}
PRIVACY_LEVELS = ("L0", "L1", "L2", "L3", "L4")
FAIL_ON = ("critical", "high", "medium", "low", "info", "none")
LOG_LEVELS = ("debug", "info", "warning", "error", "critical")
LOG_FORMATS = ("console", "json")


# --- scripts -------------------------------------------------------------------------------


def _completion_class(shell: str) -> Any:
    from typer._click.shell_completion import get_completion_class  # noqa: PLC0415
    from typer._completion_classes import completion_init  # noqa: PLC0415

    completion_init()
    return get_completion_class(shell)


def completion_script(shell: str, command: click.Command) -> str:
    """The completion script of ``shell`` for ``command`` (the root command)."""
    completion_class = _completion_class(shell)
    if completion_class is None:  # an upstream rename; covered by a test
        raise UsageError(f"completion for {shell} is not available", code="shell_unknown")
    return _source(completion_class(command, {}, PROG_NAME, COMPLETE_VAR))


def _source(completer: Any) -> str:
    """The script, rendered from the class's template.

    ``source()`` is avoided on purpose: for bash it starts ``bash`` to print a version warning,
    and printing a script must start no process (the minimum bash version is documented instead).
    """
    return str(completer.source_template % completer.source_vars())


def detect_shell(environ: Mapping[str, str] | None = None) -> str | None:
    """The shell named by ``SHELL`` (or a PowerShell session), or None."""
    env = os.environ if environ is None else environ
    name = Path(env.get("SHELL", "")).name.lower().removesuffix(".exe")
    if name in SHELLS:
        return name
    if name in SHELL_ALIASES:
        return SHELL_ALIASES[name]
    if env.get("PSModulePath") and not name:
        return "powershell"
    return None


def completion_command(
    ctx: typer.Context,
    shell: Annotated[
        str | None,
        typer.Argument(
            help="bash, zsh, fish or powershell; detected from SHELL when omitted.",
            autocompletion=lambda: list(SHELLS),
            show_default=False,
        ),
    ] = None,
) -> None:
    """Print a shell completion script.

    Redirect it into your shell's completion directory; see docs/reference/cli-completion.md.
    """
    # A completion script is not a JSON document: --json is ignored for this command.
    output.fallback_output(json_mode=False, command="completion")
    chosen = (shell or "").strip().lower() or detect_shell()
    chosen = SHELL_ALIASES.get(chosen or "", chosen)
    if chosen not in SHELLS:
        raise UsageError(
            "cannot tell which shell to generate completion for",
            code="shell_unknown",
            hint=f"name it: codekavach completion {{{','.join(SHELLS)}}}",
        )
    script = completion_script(chosen, ctx.find_root().command)
    sys.stdout.write(script.rstrip("\n") + "\n")
    sys.stdout.flush()
    if sys.stdout.isatty():
        sys.stderr.write(
            f"\n# To install, redirect the script instead of printing it:\n"
            f"#   {INSTALL_LINES[chosen]}\n"
        )


# --- completion requests -------------------------------------------------------------------


def parse_instruction(instruction: str) -> tuple[str, str] | None:
    """``(action, shell)`` from ``complete_bash`` or ``bash_complete`` (and ``source``)."""
    first, _, second = instruction.strip().partition("_")
    for action, shell in ((first, second), (second, first)):
        if action in {"complete", "source"} and shell in {*SHELLS, "pwsh"}:
            return action, SHELL_ALIASES.get(shell, shell)
    return None


def handle_request(command: click.Command, instruction: str) -> int:
    """Answer one completion request; never raises, writes candidates (or a script) to stdout."""
    from codekavach.core.log import configure_logging  # noqa: PLC0415

    # Candidates go to stdout and nothing else may: silence every log event for this process.
    configure_logging(level="CRITICAL", stream=io.StringIO(), force=True)
    parsed = parse_instruction(instruction)
    if parsed is None:
        return 1
    action, shell = parsed
    try:
        completion_class = _completion_class(shell)
        if completion_class is None:
            return 1
        completer = completion_class(command, {}, PROG_NAME, COMPLETE_VAR)
        with contextlib.redirect_stderr(io.StringIO()):
            text = _source(completer) if action == "source" else completer.complete()
    except Exception:  # noqa: BLE001 - a TAB press must never print a traceback
        return 1
    if text:
        sys.stdout.write(str(text).rstrip("\n") + "\n")
    sys.stdout.flush()
    return 0


# --- value lists ---------------------------------------------------------------------------


def _within_budget(read: Callable[[], Any], budget: float = CONFIG_BUDGET_SECONDS) -> Any:
    """``read()`` in a daemon thread; None when it fails or takes longer than ``budget``."""
    result: list[Any] = []

    def work() -> None:
        with contextlib.suppress(Exception):
            result.append(read())

    thread = threading.Thread(target=work, name="codekavach-completion", daemon=True)
    thread.start()
    thread.join(budget)
    return result[0] if result else None


def _load_settings() -> Any:
    from codekavach.config import load_settings  # noqa: PLC0415 - only on a value TAB press

    return load_settings(target=Path.cwd()).settings


def configured_settings() -> Any:
    """The effective settings of the current directory, or None (error or over budget)."""
    with contextlib.redirect_stderr(io.StringIO()):
        return _within_budget(_load_settings)


def _matching(values: list[str], incomplete: str) -> list[str]:
    return [value for value in dict.fromkeys(values) if value.startswith(incomplete)]


def complete_profile(ctx: click.Context, args: list[str], incomplete: str) -> list[str]:
    """Built-in profile names plus the profiles defined in the user and project files."""
    from codekavach.config.profiles import BUILTIN_PROFILES  # noqa: PLC0415

    names = sorted(BUILTIN_PROFILES)
    settings = configured_settings()
    if settings is not None:
        names += sorted(getattr(settings, "profiles", {}) or {})
    return _matching(names, incomplete)


def complete_provider(ctx: click.Context, args: list[str], incomplete: str) -> list[str]:
    """Configured provider ids; ``mock`` is always available."""
    names = ["mock"]
    settings = configured_settings()
    if settings is not None:
        names += sorted(settings.llm.providers)
    return _matching(names, incomplete)


def fixed(values: tuple[str, ...]) -> Callable[[click.Context, list[str], str], list[str]]:
    """A completion callback offering ``values``."""

    def complete(ctx: click.Context, args: list[str], incomplete: str) -> list[str]:
        return _matching(list(values), incomplete)

    return complete


def complete_report_format(ctx: click.Context, args: list[str], incomplete: str) -> list[str]:
    """Report renderer names."""
    from codekavach.config.models.reporting import ReportFormat  # noqa: PLC0415

    return _matching([member.value for member in ReportFormat], incomplete)
