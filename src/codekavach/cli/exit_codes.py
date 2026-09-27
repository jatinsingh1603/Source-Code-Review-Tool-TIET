"""The process exit codes: a public contract for pipelines, the GitHub Action and hooks.

Owning epic: E05.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes of every ``codekavach`` invocation."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    PRIVACY_BLOCK = 3
    INTERNAL = 4
    CANCELLED = 130


EXIT_CODE_HELP = """\
Exit codes:
  0    OK             completed; nothing at or above the threshold
  1    FINDINGS       completed; problems at or above the threshold
  2    USAGE          cannot run as invoked (options, configuration, input, missing back end)
  3    PRIVACY_BLOCK  a privacy control refused the operation
  4    INTERNAL       unexpected failure inside CodeKavach
  130  CANCELLED      interrupted by the user
Precedence at the end of a command: 4 over 3 over 1 over 0; 2 only before work starts."""
