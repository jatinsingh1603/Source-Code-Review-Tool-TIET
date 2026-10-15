"""The ``parse`` entry point (E07-01)."""

from collections.abc import Iterator

import pytest

from codekavach.config.models.parsing import ParsingSettings
from codekavach.core.models import Language, RawCode
from codekavach.parsing.models import TIMED_OUT
from codekavach.parsing.parser import ParseUnavailableError, SourceTooLargeError, parse
from codekavach.parsing.spec import REGISTRY
from tests.support.parsing import TrivialSpec


@pytest.fixture
def trivial_spec() -> Iterator[TrivialSpec]:
    """Register the test-only Python spec for the duration of one test, then remove it."""
    spec = TrivialSpec()
    REGISTRY.register(spec)
    try:
        yield spec
    finally:
        REGISTRY._specs.pop(Language.PYTHON, None)


def test_parse_a_clean_file_has_no_errors() -> None:
    result = parse("a.py", Language.PYTHON, "x = 1\n")
    assert result.error_count == 0
    assert not result.timed_out
    assert isinstance(result.source, RawCode)
    assert result.source.expose() == "x = 1\n"


def test_parse_an_erroring_file_reports_errors_without_raising() -> None:
    result = parse("a.py", Language.PYTHON, "def f(:\n    pass\n")
    assert result.error_count > 0
    assert not result.timed_out


def test_parse_an_oversized_source_raises_source_too_large() -> None:
    with pytest.raises(SourceTooLargeError):
        parse("a.py", Language.PYTHON, "a" * 100, settings=ParsingSettings(max_source_bytes=10))


def test_parse_a_pathological_input_times_out() -> None:
    pathological = "(" * 500_000 + ")" * 500_000
    result = parse(
        "a.py",
        Language.PYTHON,
        pathological,
        settings=ParsingSettings(timeout_seconds=0.1, max_source_bytes=10_000_000),
    )
    assert result.timed_out
    assert result.error_count == TIMED_OUT


def test_parse_raises_parse_unavailable_for_an_unpinned_language() -> None:
    with pytest.raises(ParseUnavailableError):
        parse("a.yaml", Language.YAML, "a: 1\n")


def test_parse_without_a_registered_spec_extracts_nothing() -> None:
    result = parse("a.py", Language.PYTHON, "x = 'hello'\n# comment\n")
    assert result.identifiers() == ()
    assert result.string_literals() == ()
    assert result.comments() == ()


def test_parse_with_a_registered_spec_extracts_identifiers_strings_and_comments(
    trivial_spec: TrivialSpec,
) -> None:
    result = parse("a.py", Language.PYTHON, "x = 'hello'\n# comment\n")
    identifiers = result.identifiers()
    assert len(identifiers) == 1
    assert identifiers[0].symbol is None
    assert identifiers[0].start_line == 1

    literals = result.string_literals()
    assert len(literals) == 1
    assert literals[0].kind == "natural"
    assert "hello" in literals[0].raw_text

    comments = result.comments()
    assert len(comments) == 1
    assert comments[0].start_line == 2


def test_parse_locations_use_the_real_path() -> None:
    result = parse("src/widget.py", Language.PYTHON, "x = 1\n")
    assert result.path == "src/widget.py"


def test_parse_reports_hidden_characters_from_normalise_source() -> None:
    zero_width_space = "\U0000200b"
    result = parse("a.py", Language.PYTHON, f"x = 'a{zero_width_space}b'\n")
    assert result.hidden_chars.count == 1
