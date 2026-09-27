from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from codekavach.core.models import KavachModel, UtcDatetime, utc_now


class Stamped(KavachModel):
    at: UtcDatetime


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError):
        Stamped(at=datetime(2026, 10, 5, 10, 0))  # noqa: DTZ001 - deliberately naive


def test_non_utc_converted() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    model = Stamped(at=datetime(2026, 10, 5, 10, 0, tzinfo=ist))
    assert model.at.tzinfo == UTC
    assert model.at.hour == 4


def test_json_from_offset_string() -> None:
    model = Stamped.model_validate({"at": "2026-10-05T10:00:00+05:30"})
    assert model.model_dump_json() == '{"at":"2026-10-05T04:30:00.000000Z"}'


def test_json_keeps_six_fraction_digits() -> None:
    model = Stamped(at=datetime(2026, 1, 2, 3, 4, 5, 7, tzinfo=UTC))
    assert model.model_dump(mode="json")["at"] == "2026-01-02T03:04:05.000007Z"


def test_utc_now_is_aware_utc() -> None:
    now = utc_now()
    assert now.tzinfo == UTC
