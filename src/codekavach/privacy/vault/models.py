"""The record the vault stores for one pseudonym.

Owning epic: E10.

``MappingRecord`` holds an original, so it is raw client data. Only the vault and the restore
engine may import this module (an import contract enforces it, invariant I3). It is a plain
dataclass and not a model, so it has no JSON form and cannot appear in an artefact schema, and its
``repr`` shows the pseudonym and the kind only.
"""

from dataclasses import dataclass
from typing import ClassVar

from codekavach.core.models.base import DataClassification
from codekavach.core.models.location import Location
from codekavach.privacy.pseudonymise.generator import PseudonymKind


@dataclass(frozen=True, slots=True, repr=False)
class MappingRecord:
    """One pseudonym, the original it stands for, and where it was first seen."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    __ck_never_persist__: ClassVar[bool] = True

    pseudonym: str
    original: str
    kind: PseudonymKind
    scope: str
    first_location: Location | None = None

    def __repr__(self) -> str:
        return f"MappingRecord({self.pseudonym}, {self.kind.value})"

    __str__ = __repr__
