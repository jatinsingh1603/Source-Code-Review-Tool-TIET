"""Conventions shared by every settings section.

Owning epic: E03.

Every section model:

- derives from ``SectionModel`` (unknown keys rejected, frozen, input hidden in errors, so a key
  pasted into the wrong field is never echoed);
- gives every field a default and a one-sentence description ending with a full stop;
- puts units in field names (``max_file_size_kb``, ``timeout_seconds``);
- uses ``pathlib.Path`` for paths; a relative path means "relative to the project root" and only
  ``LoadedConfig.resolve_path()`` (E03-13) resolves it;
- never holds a secret value (secrets are ``SecretRef`` strings, E03-04);
- raises ``ValueError`` whose message starts with the code in square brackets, for example
  ``[CK-CFG-003] scan.jobs must be between 0 and 256``, and never contains the input value.
"""

from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict

from codekavach.core.models import PrivacyLevel

INVALID = "[CK-CFG-003]"


class SectionModel(BaseModel):
    """Base class of every configuration section."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )


def split_csv(value: Any) -> Any:
    """Split a comma-separated string into a list; lists pass unchanged; empty items drop."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


StrList = Annotated[list[str], BeforeValidator(split_csv)]


def _upper(value: Any) -> Any:
    return value.upper() if isinstance(value, str) else value


# Accepts "l3" as well as "L3".
PrivacyLevelField = Annotated[PrivacyLevel, BeforeValidator(_upper)]


def in_range(low: int, high: int, key: str) -> AfterValidator:
    """A validator that rejects integers outside ``[low, high]`` with a CK-CFG-003 message."""

    def check(value: int) -> int:
        if not low <= value <= high:
            raise ValueError(f"{INVALID} {key} must be between {low} and {high}")
        return value

    return AfterValidator(check)


def bounds(low: int, high: int) -> dict[str, Any]:
    """JSON Schema bounds that document an ``in_range`` validator."""
    return {"minimum": low, "maximum": high}


def sensitive() -> dict[str, Any]:
    """Mark a field whose value is masked in every output (E03-20)."""
    return {"x-ck-sensitive": True}


def volatile() -> dict[str, Any]:
    """Mark a field that is excluded from the settings fingerprint (E03-39)."""
    return {"x-ck-volatile": True}


def union_merge() -> dict[str, Any]:
    """Mark a list field that layers merge by union instead of replacement (E03-13)."""
    return {"x-ck-merge": "union"}


def restricted() -> dict[str, Any]:
    """Mark a field that an untrusted project configuration may not set (E03-25)."""
    return {"x-ck-restricted": True}
