"""The false-positive filters: each one tested to change the result when it is switched off."""

import base64
import hashlib
from importlib import resources

import pytest

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, RawCode
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_with_report
from codekavach.privacy.detect.secrets import entropy as entropy_module
from codekavach.privacy.detect.secrets.entropy import EntropyDetector
from codekavach.privacy.detect.secrets.filters import (
    FILTER_NAMES,
    FILTERS,
    REPEAT_THRESHOLD,
    FilterContext,
    Verdict,
    first_match,
    is_placeholder,
    placeholder_values,
)
from codekavach.privacy.detect.secrets.stats import ScanSecretStats
from tests.support.synthetic import synthetic_value

SALT = ScanSalt.from_hex("55" * 32)  # pragma: allowlist secret
ENTROPIC = synthetic_value("secret", "high_entropy_string", 3)
HEX_64 = hashlib.sha256(b"example").hexdigest()
SRI = "sha512-" + base64.b64encode(hashlib.sha512(b"example").digest()).decode()
WORDS = base64.b64encode(
    b"the quick brown fox jumps over the lazy dog and then it runs away"
).decode()
UUID = "123e4567-e89b-12d3-a456-426614174000"


def detect(
    text: str,
    path: str = "src/app.py",
    *,
    disabled: tuple[str, ...] = (),
    stats: ScanSecretStats | None = None,
) -> list[str]:
    data = text.encode()
    detector = EntropyDetector(stats, disabled_filters=disabled)
    spans = detector.detect(RawCode(text), path=path, language=Language.PYTHON)
    return [data[s.start_byte : s.end_byte].decode() for s in spans]


@pytest.fixture
def everything_is_entropic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the entropy test accept any candidate, so a filter is the only thing deciding."""
    monkeypatch.setattr(entropy_module, "is_high_entropy", lambda _value: True)


def test_the_filter_names_are_the_documented_set() -> None:
    assert {
        "hash_in_manifest",
        "uuid",
        "base64_text",
        "placeholder_value",
        "example_marker",
        "repeated_value",
    } == FILTER_NAMES
    assert [rule.verdict for rule in FILTERS if rule.name == "repeated_value"] == [
        Verdict.DOWNGRADE
    ]
    assert all(rule.description.endswith(".") for rule in FILTERS)


def test_an_unknown_name_to_disable_is_an_error_not_a_silent_no_op() -> None:
    with pytest.raises(ValueError, match="unknown filter names"):
        first_match("x", FilterContext(path="a.py"), frozenset({"hash_in_mainfest"}))


# --- hash_in_manifest ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "path", "text"),
    [
        (HEX_64, "pnpm-lock.yaml", f"checksum: {HEX_64}\n"),
        (HEX_64[:40], "uv.lock", f"checksum: {HEX_64[:40]}\n"),
        (HEX_64, "src/app.py", f'integrity = "{HEX_64}"\n'),  # an integrity field, any file
    ],
)
def test_hash_in_manifest_drops_digests_in_lockfiles_and_integrity_fields(
    value: str, path: str, text: str
) -> None:
    assert detect(text, path) == []
    assert detect(text, path, disabled=("hash_in_manifest",)) == [value]


def test_a_subresource_integrity_digest_is_a_manifest_hash(everything_is_entropic: None) -> None:
    text = f'  "integrity": "{SRI}",\n'
    assert detect(text, "package-lock.json") == []
    assert detect(text, "package-lock.json", disabled=("hash_in_manifest",)) == [SRI]
    assert detect(f'x = "{SRI}"\n', "src/app.py") == [SRI]  # a digest elsewhere is not filtered


def test_the_same_hex_string_elsewhere_is_still_reported() -> None:
    assert detect(f'seed = "{HEX_64}"\n', "src/app.py") == [HEX_64]


def test_hex_of_a_length_that_is_not_a_digest_is_not_filtered_in_a_lockfile() -> None:
    odd = HEX_64[:50]
    assert detect(f"checksum: {odd}\n", "pnpm-lock.yaml") == [odd]


# --- uuid, placeholder_value ---------------------------------------------------------------


def test_uuid_drops_a_canonical_uuid(everything_is_entropic: None) -> None:
    text = f'request_id = "{UUID}"\n'
    assert detect(text) == []
    assert detect(text, disabled=("uuid",)) == [UUID]
    assert detect(f'request_id = "{UUID[:-1]}"\n') == [UUID[:-1]]  # not canonical: one short


@pytest.mark.parametrize(
    "value",
    [
        "your-api-key-here",
        "<your-key-goes-here>",
        "x" * 20,
        "${DB_PASSWORD_VALUE}",
    ],
)
def test_placeholder_value_drops_placeholders(everything_is_entropic: None, value: str) -> None:
    assert is_placeholder(value)
    # Only the quote-free forms are candidates, so test the ones the extractor can see.
    if all(char.isalnum() or char in "-_" for char in value):
        text = f'token = "{value}"\n'
        assert detect(text) == []
        assert detect(text, disabled=("placeholder_value",)) == [value]


def test_the_denylist_matches_the_whole_literal_not_a_substring() -> None:
    assert is_placeholder("changeme")
    assert is_placeholder("ChangeMe")
    assert not is_placeholder("changeme123!")
    assert not is_placeholder("mychangeme")


def test_every_denylist_entry_has_a_reason() -> None:
    text = (
        resources.files("codekavach.privacy.detect.secrets.data")
        .joinpath("placeholder_values.txt")
        .read_text(encoding="utf-8")
    )
    entries = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    assert len(entries) == len(placeholder_values())
    assert all(" # " in line and line.split(" # ", 1)[1].strip() for line in entries)


@pytest.mark.parametrize(
    "value", ["aaaa", "xxxxxxxx", "********", "${NAME}", "{{ name }}", "%(name)s", "<redacted>"]
)
def test_placeholder_shapes(value: str) -> None:
    assert is_placeholder(value)


# --- base64_text, example_marker -----------------------------------------------------------


def test_base64_text_drops_base64_of_words() -> None:
    text = f'banner = "{WORDS}"\n'
    assert detect(text) == []
    assert detect(text, disabled=("base64_text",)) == [WORDS]


def test_base64_of_binary_is_not_text() -> None:
    blob = base64.b64encode(hashlib.sha512(b"x").digest()).decode().rstrip("=")
    assert detect(f'k = "{blob}"\n') == [blob]


@pytest.mark.parametrize(
    "path", ["tests/test_client.py", "docs/guide/client.py", "examples/app.py", "src/fixtures/a.py"]
)
def test_example_marker_drops_an_example_value_in_a_test_or_docs_path(path: str) -> None:
    text = f'blob = "{ENTROPIC}"  # example value\n'
    assert detect(text, path) == []
    assert detect(text, path, disabled=("example_marker",)) == [ENTROPIC]


def test_example_marker_needs_both_the_path_and_the_marker() -> None:
    assert detect(f'blob = "{ENTROPIC}"  # example value\n', "src/app.py") == [ENTROPIC]
    assert detect(f'blob = "{ENTROPIC}"\n', "tests/test_client.py") == [ENTROPIC]


# --- repeated_value ------------------------------------------------------------------------


def lines(count: int) -> str:
    return "".join(f'k{i} = "{ENTROPIC}"\n' for i in range(count))


def spans_of(text: str, stats: ScanSecretStats | None = None) -> list[tuple[bool, str]]:
    data = text.encode()
    found = EntropyDetector(stats).detect(
        RawCode(text), path="src/app.py", language=Language.PYTHON
    )
    return [(s.downgraded, data[s.start_byte : s.end_byte].decode()) for s in found]


def test_a_value_seen_more_than_20_times_is_downgraded_not_dropped() -> None:
    assert REPEAT_THRESHOLD == 20
    twenty = spans_of(lines(20))
    assert len(twenty) == 20
    assert not any(downgraded for downgraded, _ in twenty)
    twenty_one = spans_of(lines(21))
    assert len(twenty_one) == 21  # recall first: still reported
    assert all(downgraded for downgraded, _ in twenty_one)  # all of them, not only the 21st


def test_disabling_the_repeated_value_filter_keeps_every_span_at_full_standing() -> None:
    text = lines(25)
    detector = EntropyDetector(disabled_filters=["repeated_value"])
    found = detector.detect(RawCode(text), path="a.py", language=Language.PYTHON)
    assert len(found) == 25
    assert not any(span.downgraded for span in found)


def test_the_count_spans_the_scan_through_the_stats_object() -> None:
    stats = ScanSecretStats(SALT)
    first = spans_of(lines(12), stats)
    second = spans_of(lines(12), stats)
    assert not any(downgraded for downgraded, _ in first)
    assert all(downgraded for downgraded, _ in second)  # 24 occurrences in the scan
    assert stats.count(ENTROPIC) == 24


def test_the_downgrade_is_visible_in_the_detection_report() -> None:
    registry = DetectorRegistry([EntropyDetector()])
    text = lines(25)
    spans, report = detect_with_report(
        RawCode(text),
        path="a.py",
        language=Language.PYTHON,
        settings=Settings(),
        registry=registry,
    )
    assert report.downgraded == 25
    assert len(spans) == 25
    assert all(span.downgraded and span.confidence is Confidence.LOW for span in spans)
    assert ENTROPIC not in report.model_dump_json()


def test_a_raised_floor_drops_downgraded_spans_with_the_other_low_ones() -> None:
    registry = DetectorRegistry([EntropyDetector()])
    settings = Settings.model_validate({"privacy": {"detect": {"min_confidence": "medium"}}})
    spans, report = detect_with_report(
        RawCode(lines(25)),
        path="a.py",
        language=Language.PYTHON,
        settings=settings,
        registry=registry,
    )
    assert (spans, report.below_floor) == ((), 25)


# --- ScanSecretStats -----------------------------------------------------------------------


def test_stats_count_values_without_holding_them() -> None:
    stats = ScanSecretStats(SALT)
    assert [stats.observe("value-a"), stats.observe("value-a"), stats.observe("value-b")] == [
        1,
        2,
        1,
    ]
    assert (stats.count("value-a"), stats.count("value-b"), stats.count("never-seen")) == (2, 1, 0)
    assert repr(stats) == "ScanSecretStats(distinct=2)"
    assert "value-a" not in repr(stats)
    assert not hasattr(stats, "__dict__")
    assert all(len(key) == 16 for key in stats._counts)
    assert ScanSecretStats.__ck_never_persist__ is True


def test_stats_with_a_different_salt_key_the_same_value_differently() -> None:
    first, second = (
        ScanSecretStats(SALT),
        ScanSecretStats(ScanSalt.from_hex("66" * 32)),
    )  # pragma: allowlist secret
    first.observe("v")
    second.observe("v")
    assert set(first._counts) != set(second._counts)


@pytest.mark.parametrize("salt", [None, b"0" * 32, "55" * 32])
def test_stats_need_a_scan_salt(salt: object) -> None:
    with pytest.raises(TypeError):
        ScanSecretStats(salt)  # type: ignore[arg-type]
