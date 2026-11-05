"""``PlaceholderNumbering``: stable, value-keyed, 1-based, contiguous per bucket (E08-01)."""

import threading

import pytest

from codekavach.core.models import PlaceholderKind
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.errors import RedactionError
from codekavach.privacy.redact import numbering as numbering_module
from codekavach.privacy.redact.numbering import PlaceholderNumbering
from tests.support.synthetic import AWS_EXAMPLE_ACCESS_KEY_ID, AWS_EXAMPLE_SECRET_ACCESS_KEY

SECRET = PlaceholderKind.SECRET
PII = PlaceholderKind.PII
SALT = ScanSalt.from_hex("11" * 32)  # pragma: allowlist secret


def test_the_same_value_always_gets_the_same_index() -> None:
    numbering = PlaceholderNumbering(SALT)
    first = numbering.index_for(SECRET, "aws_access_key", AWS_EXAMPLE_ACCESS_KEY_ID)
    assert first == 1
    assert [numbering.index_for(SECRET, "aws_access_key", AWS_EXAMPLE_ACCESS_KEY_ID)] * 3 == [1] * 3


def test_different_values_get_contiguous_one_based_indices() -> None:
    numbering = PlaceholderNumbering(SALT)
    indices = [numbering.index_for(SECRET, "aws_access_key", f"value-{n}") for n in range(5)]
    assert indices == [1, 2, 3, 4, 5]
    assert numbering.index_for(SECRET, "aws_access_key", "value-2") == 3


def test_buckets_number_independently() -> None:
    numbering = PlaceholderNumbering(SALT)
    assert numbering.index_for(SECRET, "aws_access_key", "same") == 1
    assert numbering.index_for(SECRET, "jwt", "same") == 1
    assert numbering.index_for(PII, "email", "same") == 1
    assert numbering.index_for(SECRET, "aws_access_key", "other") == 2
    assert numbering.counts() == {
        (SECRET, "aws_access_key"): 2,
        (SECRET, "jwt"): 1,
        (PII, "email"): 1,
    }


def test_the_numbering_is_per_scan_not_global() -> None:
    first, second = PlaceholderNumbering(SALT), PlaceholderNumbering(SALT)
    first.index_for(SECRET, "jwt", "a")
    assert second.index_for(SECRET, "jwt", "b") == 1


def test_repr_prints_counts_and_no_value() -> None:
    numbering = PlaceholderNumbering(SALT)
    numbering.index_for(SECRET, "aws_access_key", AWS_EXAMPLE_ACCESS_KEY_ID)
    numbering.index_for(SECRET, "aws_secret_key", AWS_EXAMPLE_SECRET_ACCESS_KEY)
    shown = repr(numbering)
    assert shown == "PlaceholderNumbering(SECRET:aws_access_key=1, SECRET:aws_secret_key=1)"
    assert AWS_EXAMPLE_ACCESS_KEY_ID not in shown
    assert AWS_EXAMPLE_SECRET_ACCESS_KEY not in shown


def test_the_object_holds_no_plain_value_anywhere() -> None:
    numbering = PlaceholderNumbering(SALT)
    numbering.index_for(SECRET, "aws_access_key", AWS_EXAMPLE_ACCESS_KEY_ID)
    assert not hasattr(numbering, "__dict__")
    holders = [numbering._buckets, repr(numbering._buckets)]
    assert all(AWS_EXAMPLE_ACCESS_KEY_ID not in repr(item) for item in holders)
    (bucket,) = numbering._buckets.values()
    assert all(len(key) == 16 for key in bucket)


def test_the_object_is_marked_never_to_be_persisted() -> None:
    assert PlaceholderNumbering.__ck_never_persist__ is True


@pytest.mark.parametrize("salt", [None, b"0" * 32, "11" * 32, object()])
def test_a_salt_is_required_there_is_no_plain_dictionary_fallback(salt: object) -> None:
    with pytest.raises(TypeError):
        PlaceholderNumbering(salt)  # type: ignore[arg-type]


def test_too_many_distinct_values_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(numbering_module, "MAX_INDEX", 3)
    numbering = PlaceholderNumbering(SALT)
    for value in "abc":
        numbering.index_for(PII, "email", value)
    with pytest.raises(RedactionError) as caught:
        numbering.index_for(PII, "email", "overflow-value")
    assert "overflow-value" not in str(caught.value)
    assert numbering.index_for(PII, "email", "a") == 1  # known values still resolve


def test_concurrent_use_assigns_each_value_one_unique_index() -> None:
    numbering = PlaceholderNumbering(SALT)
    seen: dict[str, set[int]] = {}
    lock = threading.Lock()

    def work() -> None:
        for number in range(200):
            value = f"value-{number}"
            index = numbering.index_for(PII, "email", value)
            with lock:
                seen.setdefault(value, set()).add(index)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(len(indices) == 1 for indices in seen.values())
    assert sorted(next(iter(i)) for i in seen.values()) == list(range(1, 201))
