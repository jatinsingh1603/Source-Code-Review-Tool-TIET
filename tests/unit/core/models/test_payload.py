from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import DataClassification, PrivacyLevel, sha256_hex
from codekavach.core.models.enums import PlaceholderKind
from codekavach.core.models.ids import new_candidate_id, new_payload_id, new_slice_id
from codekavach.core.models.payload import (
    LineMapEntry,
    PlaceholderRef,
    SanitisedPayload,
    find_placeholders,
    format_placeholder,
    parse_placeholder,
)
from codekavach.core.models.text import RawCode, SanitisedText

EXAMPLE_TEXT = "def fn_1(param_2):\n    return param_2\n"
EXAMPLE_HASH = (
    "564f164d9b913418ddc386d366d422ebd5cb11cd0ff1469f6b3aed202849e847"  # pragma: allowlist secret
)
FORBIDDEN_NAMES = {
    "path",
    "file",
    "original",
    "value",
    "secret",
    "symbol",
    "name",
    "identifier",
    "location",
    "snippet",
    "code",
    "raw",
}


def build(text: str, **overrides: Any) -> SanitisedPayload:
    fields: dict[str, Any] = {
        "candidate_id": new_candidate_id(),
        "slice_id": new_slice_id(),
        "text": SanitisedText(text),
        "level": PrivacyLevel.L3,
    }
    fields.update(overrides)
    return SanitisedPayload.build(**fields)


def fields_of(payload: SanitisedPayload, **overrides: Any) -> dict[str, Any]:
    data = payload.model_dump()
    data.update(overrides)
    return data


# placeholder grammar


def test_format_parse_find() -> None:
    token = format_placeholder(PlaceholderKind.SECRET, "aws_access_key", 1)
    assert token == "<SECRET:aws_access_key:1>"
    assert parse_placeholder("<PII:email:2>") == (PlaceholderKind.PII, "email", 2)
    text = "a <SECRET:aws_access_key:1> b <PII:email:2> <SECRET:aws_access_key:1>"
    assert find_placeholders(text) == [
        "<SECRET:aws_access_key:1>",
        "<PII:email:2>",
        "<SECRET:aws_access_key:1>",
    ]


@pytest.mark.parametrize(
    "near_miss", ["<secret:x:1>", "<SECRET:X:1>", "<SECRET:aws:0>", "<SECRET:aws>", "<TOKEN:a:1>"]
)
def test_near_misses_do_not_match(near_miss: str) -> None:
    assert find_placeholders(near_miss) == []
    with pytest.raises(ValueError, match="placeholder"):
        parse_placeholder(near_miss)


def test_format_rejects_invalid_parts() -> None:
    with pytest.raises(ValueError):
        format_placeholder(PlaceholderKind.TERM, "Domain", 1)
    with pytest.raises(ValueError):
        format_placeholder(PlaceholderKind.TERM, "domain", 0)


def test_placeholder_ref_token_must_match() -> None:
    with pytest.raises(ValidationError, match="token"):
        PlaceholderRef(
            token="<PII:email:2>",
            kind=PlaceholderKind.PII,
            subtype="email",
            index=1,
            occurrences=1,
        )


# build and validation


def test_example_hash_and_classification() -> None:
    payload = build(EXAMPLE_TEXT)
    assert payload.payload_hash == EXAMPLE_HASH
    for model in (PlaceholderRef, LineMapEntry, SanitisedPayload):
        assert model.DATA_CLASSIFICATION is DataClassification.SANITISED


def test_build_counts_placeholders() -> None:
    text = "k = <SECRET:aws_access_key:1>\nj = <SECRET:aws_access_key:1>\nm = <PII:email:1>\n"
    payload = build(text)
    assert [(p.token, p.occurrences) for p in payload.placeholders] == [
        ("<SECRET:aws_access_key:1>", 2),
        ("<PII:email:1>", 1),
    ]
    assert payload.payload_hash == sha256_hex(text)


def test_text_must_be_sanitised_text_in_python_mode() -> None:
    payload = build(EXAMPLE_TEXT)
    for bad in (EXAMPLE_TEXT, RawCode(EXAMPLE_TEXT)):
        with pytest.raises(ValidationError):
            SanitisedPayload.model_validate(fields_of(payload, text=bad))
    assert SanitisedPayload.model_validate_json(payload.model_dump_json()) == payload


def test_wrong_hash_rejected() -> None:
    payload = build(EXAMPLE_TEXT)
    with pytest.raises(ValidationError, match="payload_hash"):
        SanitisedPayload.model_validate(fields_of(payload, payload_hash="0" * 64))


def test_undeclared_placeholder_rejected() -> None:
    payload = build("x = <PII:email:1>\n")
    with pytest.raises(ValidationError, match="differ"):
        SanitisedPayload.model_validate(fields_of(payload, placeholders=()))


def test_declared_placeholder_missing_from_text_rejected() -> None:
    payload = build("x = 1\n")
    ref = PlaceholderRef(
        token="<PII:email:1>", kind=PlaceholderKind.PII, subtype="email", index=1, occurrences=1
    )
    with pytest.raises(ValidationError, match="differ"):
        SanitisedPayload.model_validate(fields_of(payload, placeholders=(ref,)))


def test_wrong_occurrences_rejected() -> None:
    payload = build("x = <PII:email:1> <PII:email:1>\n")
    wrong = payload.placeholders[0].evolve(occurrences=1)
    with pytest.raises(ValidationError, match="occurrences"):
        SanitisedPayload.model_validate(fields_of(payload, placeholders=(wrong,)))


def entry(a: int, b: int, segment: int = 0, file_line: int = 10) -> LineMapEntry:
    return LineMapEntry(
        payload_start_line=a, payload_end_line=b, segment_index=segment, file_start_line=file_line
    )


FIVE_LINES = "".join(f"line_{i}\n" for i in range(1, 6))


@pytest.mark.parametrize(
    ("line_map", "message"),
    [
        ((entry(1, 3), entry(3, 4)), "ascending"),
        ((entry(4, 5), entry(1, 2)), "ascending"),
        ((entry(1, 6),), "beyond"),
    ],
)
def test_invalid_line_maps_rejected(line_map: tuple[LineMapEntry, ...], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        build(FIVE_LINES, line_map=line_map)


def test_line_map_entry_order() -> None:
    with pytest.raises(ValidationError):
        entry(3, 2)


def test_l4_rules() -> None:
    abstract = build("source flows to sink\n", level=PrivacyLevel.L4, slice_id=None)
    assert abstract.slice_id is None
    with pytest.raises(ValidationError, match="L4"):
        build(FIVE_LINES, level=PrivacyLevel.L4, slice_id=None, line_map=(entry(1, 2),))
    with pytest.raises(ValidationError, match="slice_id"):
        build(FIVE_LINES, slice_id=None)


def test_l0_is_allowed() -> None:
    assert build("print('unmodified local code')\n", level=PrivacyLevel.L0).level is PrivacyLevel.L0


def test_map_line() -> None:
    payload = build(FIVE_LINES, line_map=(entry(1, 2, 0, 40), entry(4, 5, 1, 7)))
    assert payload.map_line(1) == (0, 40)
    assert payload.map_line(2) == (0, 41)
    assert payload.map_line(3) is None
    assert payload.map_line(5) == (1, 8)
    assert payload.map_line(9) is None


def test_json_schema_has_no_forbidden_property_names() -> None:
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "properties" and isinstance(child, dict):
                    found.update(child)
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(SanitisedPayload.model_json_schema())
    assert found
    assert not (found & FORBIDDEN_NAMES), found & FORBIDDEN_NAMES


def test_hash_does_not_depend_on_id() -> None:
    payload = build(EXAMPLE_TEXT)
    other = SanitisedPayload.model_validate(fields_of(payload, id=new_payload_id()))
    assert other.payload_hash == payload.payload_hash


# properties

_fragment = st.text(alphabet="abcdefghij _=()\n", max_size=12)
_token = st.builds(
    format_placeholder,
    st.sampled_from(PlaceholderKind),
    st.sampled_from(["aws_access_key", "email", "domain", "pan_number"]),
    st.integers(1, 5),
)


@given(st.lists(st.one_of(_fragment, _token), max_size=12))
def test_random_text_builds_and_tokens_round_trip(parts: list[str]) -> None:
    text = "".join(parts)
    payload = build(text)
    for token in find_placeholders(text):
        assert format_placeholder(*parse_placeholder(token)) == token
    assert sum(p.occurrences for p in payload.placeholders) == len(find_placeholders(text))


@given(st.text(min_size=1, max_size=40), st.data())
def test_hash_changes_with_any_character(text: str, data: st.DataObject) -> None:
    position = data.draw(st.integers(0, len(text) - 1))
    replacement = data.draw(st.characters(codec="utf-8").filter(lambda c: c != text[position]))
    changed = text[:position] + replacement + text[position + 1 :]
    assert sha256_hex(changed) != sha256_hex(text)


@st.composite
def line_maps(draw: st.DrawFn) -> tuple[int, tuple[LineMapEntry, ...]]:
    total = draw(st.integers(1, 40))
    entries: list[LineMapEntry] = []
    line = 1
    while line <= total:
        line += draw(st.integers(0, 2))
        if line > total:
            break
        end = min(total, line + draw(st.integers(0, 5)))
        entries.append(entry(line, end, draw(st.integers(0, 3)), draw(st.integers(1, 500))))
        line = end + 1
    return total, tuple(entries)


@given(line_maps())
def test_map_line_inverts_linear_mapping(data: tuple[int, tuple[LineMapEntry, ...]]) -> None:
    total, line_map = data
    payload = build("x\n" * total, line_map=line_map)
    for item in line_map:
        for payload_line in range(item.payload_start_line, item.payload_end_line + 1):
            offset = payload_line - item.payload_start_line
            assert payload.map_line(payload_line) == (
                item.segment_index,
                item.file_start_line + offset,
            )
