import copy
import logging
import pickle
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

import codekavach.core.models
from codekavach.core.models import KavachModel
from codekavach.core.models.text import RawCode, SanitisedText, split_lines

CANARY = "CANARY_9f3a"
WRAPPERS = [RawCode, SanitisedText]


class Both(KavachModel):
    raw: RawCode
    clean: SanitisedText


class WithSibling(KavachModel):
    raw: RawCode
    n: int


class OnlyClean(KavachModel):
    clean: SanitisedText


# construction and value semantics


@pytest.mark.parametrize("cls", WRAPPERS)
@pytest.mark.parametrize("value", [1, None, b"x", RawCode("x"), SanitisedText("x")])
def test_constructor_rejects_non_str(cls: type[RawCode | SanitisedText], value: object) -> None:
    with pytest.raises(TypeError):
        cls(value)  # type: ignore[arg-type]  # runtime check under test


def test_equality_and_hashing() -> None:
    assert RawCode("x") == RawCode("x")
    assert RawCode("x") != RawCode("y")
    assert RawCode("x") != SanitisedText("x")
    assert RawCode("x") != "x"
    assert SanitisedText("x") != "x"
    assert hash(RawCode("x")) == hash(RawCode("x"))
    assert len({RawCode("x"), RawCode("x"), SanitisedText("x")}) == 2


@pytest.mark.parametrize("cls", WRAPPERS)
def test_len_bool_and_line_count(cls: type[RawCode | SanitisedText]) -> None:
    assert len(cls("abc")) == 3
    assert not cls("")
    assert cls("a")
    assert cls("a\nb\n").line_count == 2


@pytest.mark.parametrize("cls", WRAPPERS)
def test_immutable(cls: type[RawCode | SanitisedText]) -> None:
    value = cls("x")
    with pytest.raises(AttributeError):
        value._value = "y"
    with pytest.raises(AttributeError):
        value.other = 1
    with pytest.raises(AttributeError):
        del value._value
    assert value.expose() == "x"


# line model

LINE_TABLE = [
    ("", [], 0),
    ("a", ["a"], 1),
    ("a\n", ["a"], 1),
    ("a\nb", ["a", "b"], 2),
    ("a\r\nb\r\n", ["a", "b"], 2),
    ("\n", [""], 1),
    ("a\n\n", ["a", ""], 2),
    ("a\rb", ["a\rb"], 1),
    ("a\x0cb\u2028c", ["a\x0cb\u2028c"], 1),
]


@pytest.mark.parametrize(
    ("text", "lines", "count"), LINE_TABLE, ids=[repr(r[0]) for r in LINE_TABLE]
)
def test_split_lines_table(text: str, lines: list[str], count: int) -> None:
    assert split_lines(text) == lines
    assert RawCode(text).line_count == count


_line = st.text().filter(lambda s: "\n" not in s and not s.endswith("\r"))


@given(st.lists(_line, min_size=1))
def test_split_lines_inverts_join(xs: list[str]) -> None:
    assert split_lines("\n".join(xs) + "\n") == xs


@given(st.text())
def test_crlf_equals_lf(s: str) -> None:
    assert split_lines(s) == split_lines(s.replace("\r\n", "\n"))


def test_no_splitlines_in_models_package() -> None:
    root = Path(codekavach.core.models.__file__).parent
    offenders = [p.name for p in root.rglob("*.py") if ".splitlines(" in p.read_text("utf-8")]
    assert offenders == []


# redaction


@pytest.mark.parametrize("cls", WRAPPERS)
def test_representations_never_show_text(cls: type[RawCode | SanitisedText]) -> None:
    value = cls(f"password = '{CANARY}'")
    for rendered in (repr(value), str(value), f"{value}", f"{value:>40}", "%s" % value):  # noqa: UP031
        assert CANARY not in rendered
        assert rendered.startswith(f"{cls.__name__}(<redacted,")


def test_redacted_form_example() -> None:
    # pragma: allowlist nextline secret
    assert repr(RawCode("password = 'hunter2'")) == "RawCode(<redacted, 20 chars, 1 line>)"
    assert f"{SanitisedText('x = fn_1()')}" == "SanitisedText(<redacted, 10 chars, 1 line>)"
    assert repr(RawCode("")) == "RawCode(<redacted, 0 chars, 0 lines>)"


def test_logging_never_shows_text(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test_text")
    with caplog.at_level(logging.INFO, logger="test_text"):
        logger.info("raw=%s clean=%r", RawCode(CANARY), SanitisedText(CANARY))
    assert caplog.records
    assert CANARY not in caplog.text


def test_sibling_field_error_does_not_leak_raw() -> None:
    with pytest.raises(ValidationError) as info:
        WithSibling(raw=RawCode(CANARY), n="bad")  # type: ignore[arg-type]  # wrong type on purpose
    assert CANARY not in str(info.value)
    assert CANARY not in repr(info.value.errors(include_input=False))


def test_rejected_str_is_not_echoed() -> None:
    with pytest.raises(ValidationError) as info:
        OnlyClean(clean=CANARY)  # type: ignore[arg-type]  # str is rejected in Python mode
    assert CANARY not in str(info.value)


# pydantic


def test_sanitised_field_python_mode_rejects_str_and_raw() -> None:
    with pytest.raises(ValidationError):
        OnlyClean.model_validate({"clean": "x"})
    with pytest.raises(ValidationError):
        OnlyClean.model_validate({"clean": RawCode("x")})
    assert OnlyClean.model_validate_json('{"clean":"x"}').clean == SanitisedText("x")


def test_raw_field_accepts_str_and_instance_but_not_sanitised() -> None:
    assert WithSibling(raw="x", n=1).raw == RawCode("x")  # type: ignore[arg-type]  # str accepted
    assert WithSibling(raw=RawCode("x"), n=1).raw == RawCode("x")
    with pytest.raises(ValidationError):
        WithSibling.model_validate({"raw": SanitisedText("x"), "n": 1})


def test_json_dump_schema_and_python_round_trip() -> None:
    model = Both(raw=RawCode("a = 1"), clean=SanitisedText("v_1 = 1"))
    assert model.model_dump_json() == '{"raw":"a = 1","clean":"v_1 = 1"}'
    assert model.model_dump(mode="json") == {"raw": "a = 1", "clean": "v_1 = 1"}
    dumped = model.model_dump()
    assert isinstance(dumped["raw"], RawCode)
    assert isinstance(dumped["clean"], SanitisedText)
    assert Both.model_validate(dumped) == model
    assert Both.model_validate_json(model.model_dump_json()) == model
    props = Both.model_json_schema()["properties"]
    assert props["raw"] == {"title": "Raw", "type": "string"}
    assert props["clean"] == {"title": "Clean", "type": "string"}


def test_evolve_keeps_wrappers() -> None:
    model = Both(raw=RawCode("a"), clean=SanitisedText("b"))
    assert model.evolve(raw=RawCode("c")).clean == SanitisedText("b")


@given(st.text())
def test_expose_and_json_round_trip(s: str) -> None:
    assert RawCode(s).expose() == s
    model = Both(raw=RawCode(s), clean=SanitisedText(s))
    restored = Both.model_validate_json(model.model_dump_json())
    assert restored.raw.expose() == s
    assert restored.clean.expose() == s


def test_json_round_trip_long_and_crlf() -> None:
    s = "line\r\n" * 50_000 + "é\x01\t"
    restored = Both.model_validate_json(
        Both(raw=RawCode(s), clean=SanitisedText(s)).model_dump_json()
    )
    assert restored.raw.expose() == s


# copying and pickling


@pytest.mark.parametrize("cls", WRAPPERS)
@pytest.mark.parametrize("protocol", [2, 3, 4, 5])
def test_pickle_round_trip(cls: type[RawCode | SanitisedText], protocol: int) -> None:
    value = cls("x = 1\n")
    restored = pickle.loads(pickle.dumps(value, protocol=protocol))  # noqa: S301 - own data
    assert restored == value
    assert type(restored) is cls


@pytest.mark.parametrize("cls", WRAPPERS)
def test_copy_round_trip(cls: type[RawCode | SanitisedText]) -> None:
    value = cls("x")
    assert copy.copy(value) == value
    assert copy.deepcopy(value) == value
