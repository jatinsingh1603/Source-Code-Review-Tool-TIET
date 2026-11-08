"""What a scan records about its payloads without the sanitised text.

Owning epic: E13. MVP; extended by E11, which adds per-candidate rounds.

``DisclosureRows`` holds counts and fractions for the report's privacy attestation. ``PayloadStub``
is a payload minus its text: the text of a payload is held only by the ledger (it is never
serialised into an artefact), so ``privacy inspect`` rebuilds a payload from its stub and the
ledger entry with the same hash. Neither holds a path, a symbol or code.
"""

from typing import ClassVar

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.ids import CandidateIdField, PayloadIdField, SliceIdField
from codekavach.core.models.payload import LineMapEntry, PayloadFacts


class DisclosureRows(KavachModel):
    """Named figures such as ``repository_fraction_pct`` and ``files``, in print order."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    rows: tuple[tuple[str, str], ...] = ()

    def get(self, name: str, default: str = "0") -> str:
        """The value of figure ``name``, or ``default`` when it was not recorded."""
        return dict(self.rows).get(name, default)


class PayloadStub(KavachModel):
    """A sanitised payload without its text; ``payload_hash`` names the ledger entry holding it."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    id: PayloadIdField
    candidate_id: CandidateIdField
    slice_id: SliceIdField | None
    level: PrivacyLevel
    pseudonym_count: int = Field(ge=0)
    line_map: tuple[LineMapEntry, ...] = ()
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    facts: PayloadFacts | None = None
