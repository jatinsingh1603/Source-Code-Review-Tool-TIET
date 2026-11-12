"""Scan-to-scan delta: which findings are new, fixed or unchanged (#240).

Identity is the fingerprint, which does not depend on line numbers or on a secret's value, so a
finding that moved or whose credential was rotated is ``unchanged`` and not both fixed and new.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Delta:
    """The difference between a previous set of fingerprints and the current one."""

    new: tuple[str, ...] = field(default=())
    fixed: tuple[str, ...] = field(default=())
    unchanged: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict[str, int]:
        """Counts for the API and the report."""
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "unchanged": len(self.unchanged),
        }


def compute_delta(previous: Iterable[str], current: Iterable[str]) -> Delta:
    """Compare two fingerprint collections."""
    before, after = set(previous), set(current)
    return Delta(
        new=tuple(sorted(after - before)),
        fixed=tuple(sorted(before - after)),
        unchanged=tuple(sorted(after & before)),
    )
