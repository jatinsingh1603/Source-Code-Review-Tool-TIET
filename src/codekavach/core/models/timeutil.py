"""UTC timestamps with one fixed serialised form.

Owning epic: E02. Naive datetimes are rejected, aware ones are converted to UTC, and JSON output
is always ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` so that hashes never depend on whether the microsecond
part of the clock happened to be zero.
"""

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, PlainSerializer


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


UtcDatetime = Annotated[
    AwareDatetime,
    AfterValidator(_to_utc),
    PlainSerializer(_format_utc, return_type=str, when_used="json"),
]


def utc_now() -> datetime:
    """Return the current time in UTC; the only place the models read the clock."""
    return datetime.now(UTC)
