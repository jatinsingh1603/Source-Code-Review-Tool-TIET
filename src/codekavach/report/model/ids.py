"""Stable, human-readable report identifiers such as ``CK-2026-001``.

Owning epic: E30 (E30-02).

Identifiers are assigned in report order (most severe first) and keyed by the finding's
fingerprint, so a retest that passes the previous assignment keeps every surviving finding's
identifier and numbers new findings after the highest one already used.
"""

import re
from collections.abc import Mapping, Sequence
from typing import ClassVar

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.finding import Finding


class ReportIdScheme(KavachModel):
    """How report identifiers are formed."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    prefix: str = Field(default="CK", pattern=r"^[A-Z][A-Z0-9]{0,9}$")
    year_component: bool = True
    width: int = Field(default=3, ge=1, le=6)
    round_component: str | None = Field(default=None, pattern=r"^[A-Z0-9]{1,6}$")

    def format(self, number: int, year: int) -> str:
        """The identifier of ``number`` in ``year``."""
        parts = [self.prefix]
        if self.year_component:
            parts.append(str(year))
        if self.round_component:
            parts.append(self.round_component)
        parts.append(str(number).zfill(self.width))
        return "-".join(parts)


_TRAILING = re.compile(r"(\d+)$")


def assign_report_ids(
    findings: Sequence[Finding],
    *,
    scheme: ReportIdScheme | None = None,
    year: int,
    previous: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Report identifiers keyed by fingerprint, in the order of ``findings``."""
    chosen = scheme or ReportIdScheme()
    kept = dict(previous or {})
    used = [int(m.group(1)) for value in kept.values() if (m := _TRAILING.search(value))]
    counter = max(used, default=0)
    result: dict[str, str] = {}
    for finding in findings:
        if finding.fingerprint in result:
            # Two findings with one fingerprint: the second is keyed by its finding id.
            counter += 1
            result[str(finding.id)] = chosen.format(counter, year)
            continue
        if finding.fingerprint in kept:
            result[finding.fingerprint] = kept[finding.fingerprint]
            continue
        counter += 1
        result[finding.fingerprint] = chosen.format(counter, year)
    return result
