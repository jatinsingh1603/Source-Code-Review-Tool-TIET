"""Print the slowest imports on the CLI start-up path (E01-32).

Usage::

    python tools/dev/importtime_report.py [--target MODULE] [--top N]

Runs ``python -X importtime -c "import <target>"`` in a subprocess, parses the timing lines it
writes to stderr and prints the ``N`` imports with the largest cumulative time. Use it when the
import-budget test (``tests/unit/test_import_budget.py``) fails, to see which import is slow and
which module pulled it in.
"""

import argparse
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_TARGET = "codekavach.cli.app"
DEFAULT_TOP = 20
PREFIX = "import time:"


@dataclass(frozen=True)
class ImportTime:
    """One line of ``-X importtime`` output."""

    module: str
    self_us: int
    cumulative_us: int
    depth: int


def parse(text: str) -> list[ImportTime]:
    """Parse ``-X importtime`` output; the header and unrelated lines are skipped."""
    rows: list[ImportTime] = []
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        parts = line[len(PREFIX) :].split("|")
        if len(parts) != 3:  # noqa: PLR2004 - self | cumulative | module
            continue
        self_text, cumulative_text, name = parts
        try:
            self_us, cumulative_us = int(self_text), int(cumulative_text)
        except ValueError:
            continue  # the header line: "self [us] | cumulative | imported package"
        stripped = name.lstrip()
        depth = (len(name) - len(stripped) - 1) // 2
        rows.append(ImportTime(stripped.strip(), self_us, cumulative_us, max(depth, 0)))
    return rows


def slowest(rows: Sequence[ImportTime], top: int = DEFAULT_TOP) -> list[ImportTime]:
    """The ``top`` rows by cumulative time, slowest first (ties by name)."""
    return sorted(rows, key=lambda row: (-row.cumulative_us, row.module))[:top]


def render(rows: Sequence[ImportTime]) -> str:
    """A fixed-width table: cumulative ms, self ms, module."""
    lines = [f"{'cumulative ms':>14}  {'self ms':>8}  module"]
    lines += [
        f"{row.cumulative_us / 1000:>14.1f}  {row.self_us / 1000:>8.1f}  {row.module}"
        for row in rows
    ]
    return "\n".join(lines)


def measure(target: str = DEFAULT_TARGET) -> str:
    """The ``-X importtime`` output of importing ``target`` in a fresh interpreter."""
    completed = subprocess.run(  # noqa: S603 - our own interpreter, fixed arguments
        [sys.executable, "-X", "importtime", "-c", f"import {target}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stderr


def report(target: str = DEFAULT_TARGET, top: int = DEFAULT_TOP) -> str:
    """The rendered table of the slowest imports of ``target``."""
    return render(slowest(parse(measure(target)), top))


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description="Show the slowest imports of a module.")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--top", type=int, default=DEFAULT_TOP)
    args = parser.parse_args(argv)
    sys.stdout.write(report(args.target, args.top) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
