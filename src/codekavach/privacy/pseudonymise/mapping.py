"""The pseudonym-to-original pairs of a scan, on their way to the vault.

Owning epic: E09 (issue E09-01).

These hold originals, so they are raw client data. They mirror the vault's ``MappingRecord``
(E10-01) without importing it: the vault is only reachable from the privacy layer's own modules
(invariant I3). They are plain dataclasses and not models, so nothing here has a JSON form, and
their ``repr`` shows counts only, so a stray log line or a traceback shows no original.
"""

from dataclasses import dataclass
from typing import ClassVar

from codekavach.core.models.location import Location
from codekavach.privacy.pseudonymise.generator import PseudonymKind


@dataclass(frozen=True, slots=True, repr=False)
class MappingEntry:
    """One pseudonym and the original it stands for."""

    __ck_never_persist__: ClassVar[bool] = True

    pseudonym: str
    original: str
    kind: PseudonymKind
    scope: str
    first_location: Location | None = None

    def __repr__(self) -> str:
        return "MappingEntry(1 mapping)"


@dataclass(frozen=True, slots=True, repr=False)
class MappingBatch:
    """The mappings one scan hands to the vault in a single transaction."""

    __ck_never_persist__: ClassVar[bool] = True

    scan_id: str
    entries: tuple[MappingEntry, ...] = ()

    def __repr__(self) -> str:
        return f"MappingBatch({len(self.entries)} mappings)"

    def __len__(self) -> int:
        return len(self.entries)
