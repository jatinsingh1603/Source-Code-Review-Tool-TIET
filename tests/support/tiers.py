"""Test tiers and the mapping from a test file path to its tier."""

from pathlib import Path
from typing import Final

TIERS: Final = ("unit", "integration", "e2e", "privacy")


def tier_of(path: Path, tests_root: Path) -> str | None:
    """Return the tier of a test file, or None when it is not inside a tier directory."""
    try:
        relative = path.resolve().relative_to(tests_root.resolve())
    except ValueError:
        return None
    if len(relative.parts) < 2:
        return None
    first = relative.parts[0]
    return first if first in TIERS else None
