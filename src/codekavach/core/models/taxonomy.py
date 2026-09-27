"""Taxonomy identifiers shared by several models.

Owning epic: E02. ``CweId`` is an integer in JSON; engines and models often produce the string
form (``CWE-89``), which the before-validator accepts.
"""

import re
from typing import Annotated, ClassVar

from pydantic import BeforeValidator, Field, field_validator

from codekavach.core.models.base import DataClassification, KavachModel

_CWE = re.compile(r"^(?:cwe[-_ ])?([0-9]+)$", re.IGNORECASE)
_MAX_CWE = 99999


def parse_cwe(value: int | str) -> int:
    """Return the CWE number for ``89``, ``"89"``, ``"CWE-89"``, ``"cwe_89"`` or ``"CWE 89"``.

    Raises:
        ValueError: the value is not a CWE identifier between 1 and 99999 (bools included).
    """
    if isinstance(value, bool):
        raise ValueError("a CWE identifier cannot be a boolean")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        match = _CWE.match(value.strip())
        if not match:
            raise ValueError("not a CWE identifier")
        number = int(match.group(1))
    else:
        raise ValueError("a CWE identifier must be an int or a str")
    if not 1 <= number <= _MAX_CWE:
        raise ValueError("CWE number must be between 1 and 99999")
    return number


def format_cwe(cwe: int) -> str:
    """Return the display form, for example ``CWE-89``."""
    return f"CWE-{cwe}"


CweId = Annotated[int, BeforeValidator(parse_cwe), Field(ge=1, le=_MAX_CWE)]


_SCHEME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,31}$")


class TaxonomyRef(KavachModel):
    """A reference into a taxonomy or compliance framework, for example OWASP Top 10 A03."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    scheme: str = Field(
        description="Lower-case slug such as owasp-top10, owasp-asvs, capec, pci-dss, nist-ssdf."
    )
    id: str = Field(min_length=1, max_length=64)
    title: str | None = Field(default=None, max_length=300)
    version: str | None = Field(default=None, max_length=32)

    @field_validator("scheme")
    @classmethod
    def _check_scheme(cls, value: str) -> str:
        if not _SCHEME.match(value):
            raise ValueError("scheme must be a lower-case slug of 2 to 32 characters")
        return value


class Reference(KavachModel):
    """An external reference shown with a finding."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    title: str = Field(min_length=1, max_length=300)
    url: str | None = Field(default=None, max_length=2000)

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        if value is not None and not value.lower().startswith(("https://", "http://")):
            raise ValueError("reference URLs must use http or https")
        return value
