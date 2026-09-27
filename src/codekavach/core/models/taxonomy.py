"""Taxonomy identifiers shared by several models.

Owning epic: E02. ``CweId`` is an integer in JSON; engines and models often produce the string
form (``CWE-89``), which the before-validator accepts.
"""

import re
from typing import Annotated

from pydantic import BeforeValidator, Field

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
