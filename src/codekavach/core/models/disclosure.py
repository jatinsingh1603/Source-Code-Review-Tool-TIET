"""The disclosure figures of one scan, as the report's privacy attestation prints them.

Owning epic: E13. MVP; extended by E11, which adds per-candidate rounds.

Counts and fractions only: no path, symbol or code, so the model is metadata and may be stored and
read by any stage (``privacy-prepare`` writes it, the report reads it).
"""

from typing import ClassVar

from codekavach.core.models.base import DataClassification, KavachModel


class DisclosureRows(KavachModel):
    """Named figures such as ``repository_fraction_pct`` and ``files``, in print order."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    rows: tuple[tuple[str, str], ...] = ()

    def get(self, name: str, default: str = "0") -> str:
        """The value of figure ``name``, or ``default`` when it was not recorded."""
        return dict(self.rows).get(name, default)
