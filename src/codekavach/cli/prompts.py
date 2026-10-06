"""Confirmation prompts and the rule for sessions in which nobody can answer (E05-08).

Owning epic: E05.

Every command that asks a question uses these helpers. The rule is uniform: when a question
cannot be asked, the answer is "no". A prompt never blocks a pipeline and never defaults to "yes";
pre-approval is always an explicit parameter of the calling command (``--yes``,
``--accept-egress``), and no environment variable or configuration key means "yes". This keeps
the consent gate fail-closed (I4) and protects the vault, the only means of restoring
pseudonymised results, from accidental destruction.

Prompts are written to stderr and read from stdin, so stdout stays free for results.
"""

import os
import sys
from typing import Final

from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli.console import get_err_console
from codekavach.cli.errors import CliError

MAX_ATTEMPTS: Final = 3
CI_PROFILE: Final = "ci"
_NOT_CI: Final = frozenset({"", "0", "false"})
_YES: Final = frozenset({"y", "yes"})
_NO: Final = frozenset({"n", "no"})


def _is_terminal(stream: object) -> bool:
    isatty = getattr(stream, "isatty", None)
    try:
        return bool(callable(isatty) and isatty())
    except ValueError:  # a closed stream
        return False


def is_interactive(ctx: click.Context) -> bool:
    """True when a question can be asked and answered in this session.

    False with ``--no-input`` or ``--json``, when stdin or stderr is not a terminal, when ``CI``
    is set to anything but ``0`` or ``false``, and under the ``ci`` profile. The profile is read
    from the flag or from configuration that is already loaded; this never triggers a load.
    """
    from codekavach.cli.context import get_context  # noqa: PLC0415 - loads config models

    context = get_context(ctx)
    if context.no_input or context.json_mode:
        return False
    if not (_is_terminal(sys.stdin) and _is_terminal(sys.stderr)):
        return False
    if os.environ.get("CI", "").strip().lower() not in _NOT_CI:
        return False
    profile = context.profile
    if "loaded" in context.__dict__:
        profile = context.loaded.profile or profile
    return profile != CI_PROFILE


def _ask(prompt: str) -> str | None:
    """Write ``prompt`` to stderr and read one line; ``None`` when no answer can be read."""
    get_err_console().print(prompt, end="", markup=False, highlight=False, soft_wrap=True)
    try:
        line = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt, OSError, ValueError):
        return None
    if line == "":  # end of input
        return None
    return line.rstrip("\r\n")


def confirm(
    ctx: click.Context, question: str, *, assume_yes: bool = False, default: bool = False
) -> bool:
    """Ask a yes/no question on stderr.

    ``assume_yes`` answers yes without asking. A non-interactive session answers no without
    asking. Otherwise ``y``, ``yes``, ``n`` and ``no`` are accepted in any case, an empty answer
    gives ``default``, and after three invalid answers the result is no.
    """
    if assume_yes:
        return True
    if not is_interactive(ctx):
        return False
    choices = "[Y/n]" if default else "[y/N]"
    answers = {"": default, **dict.fromkeys(_YES, True), **dict.fromkeys(_NO, False)}
    for _ in range(MAX_ATTEMPTS):
        answer = _ask(f"{question} {choices} ")
        if answer is None:
            break
        if answer.strip().lower() in answers:
            return answers[answer.strip().lower()]
    return False


def confirm_typed(
    ctx: click.Context, question: str, *, expected: str, assume_yes: bool = False
) -> bool:
    """Ask the user to type ``expected`` exactly; anything else is a no."""
    if assume_yes:
        return True
    if not is_interactive(ctx):
        return False
    answer = _ask(f"{question}\nType {expected} to confirm: ")
    return answer is not None and answer == expected


def require_confirmation(
    ctx: click.Context,
    question: str,
    *,
    refusal: CliError,
    typed: str | None = None,
    assume_yes: bool = False,
) -> None:
    """Raise ``refusal`` unless the question is confirmed; the caller chooses the exit code.

    With ``typed`` the user must type that text exactly (``confirm_typed``).
    """
    if typed is not None:
        confirmed = confirm_typed(ctx, question, expected=typed, assume_yes=assume_yes)
    else:
        confirmed = confirm(ctx, question, assume_yes=assume_yes)
    if not confirmed:
        raise refusal
