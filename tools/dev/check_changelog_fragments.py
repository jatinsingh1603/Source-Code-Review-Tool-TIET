"""Check the names of the changelog fragments in ``changelog.d/`` (E01-22, ADR-0004).

Usage::

    python tools/dev/check_changelog_fragments.py [DIRECTORY]

A fragment is ``<issue-number>.<type>.md`` or ``+<short-slug>.<type>.md``, optionally with a
counter before ``.md`` (``12.added.2.md``), and is not empty. The types are the categories of
Keep a Changelog. ``towncrier check`` is not used: it compares against a branch, which says
nothing when commits go directly to ``main``.
"""

import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

TYPES: Final = ("added", "changed", "deprecated", "removed", "fixed", "security")
FRAGMENT: Final = re.compile(rf"^(\d+|\+[a-z0-9-]+)\.({'|'.join(TYPES)})(\.\d+)?\.md$")
ALLOWED: Final = frozenset({"README.md"})
DEFAULT_DIRECTORY: Final = Path(__file__).resolve().parents[2] / "changelog.d"


def invalid_fragments(directory: Path) -> list[str]:
    """Names of the files in ``directory`` that are not valid fragments, with the reason."""
    problems = []
    for path in sorted(directory.iterdir()):
        if path.name in ALLOWED:
            continue
        if not path.is_file() or not FRAGMENT.match(path.name):
            problems.append(
                f"{path.name}: not '<issue>.<type>.md' or '+<slug>.<type>.md' "
                f"with a type of {', '.join(TYPES)}"
            )
        elif not path.read_text(encoding="utf-8").strip():
            problems.append(f"{path.name}: the fragment is empty")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    """Check the fragment directory; 0 valid, 1 with the invalid names on stderr, 2 if missing."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    directory = Path(arguments[0]) if arguments else DEFAULT_DIRECTORY
    if not directory.is_dir():
        print(f"error: {directory} is not a directory", file=sys.stderr)
        return 2
    problems = invalid_fragments(directory)
    for problem in problems:
        print(f"{directory.name}/{problem}", file=sys.stderr)
    if problems:
        print("see changelog.d/README.md for the naming of fragments", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
