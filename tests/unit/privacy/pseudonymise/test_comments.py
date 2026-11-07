"""Comment and docstring blanking (E09-03), against spans from the real parser.

The line map must stay linear: same line count, every newline at the same byte offset. A Python
docstring must still parse after blanking, which is why it becomes a string literal rather than
whitespace.
"""

import ast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import Language, Location
from codekavach.parsing import parse
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.comments import blank_comments

PY_SOURCE = (
    "import os\n"
    "# an internal note about the ledger\n"
    "def load(account):\n"
    '    """Load the premium ledger for one account."""\n'
    "    value = os.environ.get('RATE')  # rate in basis points\n"
    "    return value\n"
)
JS_SOURCE = (
    "const a = 1; // remember the admin override\n"
    "/* internal\n"
    "   note about tokens */\n"
    "/** JSDoc for the handler */\n"
    "function handler() { return a; }\n"
)


def blank(text: str, language: Language, marker: str = "x") -> str:
    parsed = parse("sample", language, text)
    return blank_comments(text, parsed.comments(), marker=marker)


def newline_offsets(text: str) -> list[int]:
    data = text.encode("utf-8")
    return [index for index, byte in enumerate(data) if byte == ord("\n")]


def test_python_comments_are_blanked_and_lines_do_not_move() -> None:
    out = blank(PY_SOURCE, Language.PYTHON)
    assert "internal note" not in out
    assert "basis points" not in out
    assert out.count("\n") == PY_SOURCE.count("\n")
    assert newline_offsets(out) == newline_offsets(PY_SOURCE)
    assert len(out.encode()) == len(PY_SOURCE.encode())


def test_python_docstring_becomes_a_same_length_string_and_the_file_still_parses() -> None:
    out = blank(PY_SOURCE, Language.PYTHON)
    assert "Load the premium" not in out
    ast.parse(out)
    docstring_line = out.split("\n")[3]
    original_line = PY_SOURCE.split("\n")[3]
    assert len(docstring_line) == len(original_line)
    assert docstring_line.strip().startswith('"""') and docstring_line.strip().endswith('"""')


def test_python_docstring_length_is_exact_for_a_single_quote_form() -> None:
    source = 'def f():\n    "Doc text here."\n    return 1\n'
    out = blank(source, Language.PYTHON)
    ast.parse(out)
    assert len(out) == len(source)
    assert out.split("\n")[1].strip().startswith('"') and out.split("\n")[1].strip().endswith('"')


def test_javascript_line_block_and_jsdoc_comments_are_blanked() -> None:
    out = blank(JS_SOURCE, Language.JAVASCRIPT)
    for leaked in ("admin override", "internal", "tokens", "JSDoc", "/*", "//"):
        assert leaked not in out
    assert newline_offsets(out) == newline_offsets(JS_SOURCE)
    assert "function handler()" in out


def test_non_ascii_comment_keeps_byte_offsets() -> None:
    source = "x = 1  # café au lait\ny = 2\n"
    out = blank(source, Language.PYTHON)
    assert len(out.encode()) == len(source.encode())
    assert newline_offsets(out) == newline_offsets(source)


def test_placeholder_inside_a_comment_is_kept_byte_for_byte() -> None:
    source = "x = 1  # contact <PII:email:2> about it\n"
    out = blank(source, Language.PYTHON)
    assert "<PII:email:2>" in out
    assert "contact" not in out


def test_marker_must_be_a_single_printable_non_quote_character() -> None:
    source = "# note\nx = 1\n"
    for bad in ('"', "'", "\\", "ab", "", " ", "\n"):
        with pytest.raises(PseudonymError):
            blank_comments(source, parse("s", Language.PYTHON, source).comments(), marker=bad)


def test_span_outside_the_text_fails_closed() -> None:
    bad = Location(path="s.py", start_line=50, end_line=50, start_col=1, end_col=2)
    with pytest.raises(PseudonymError):
        blank_comments("x = 1\n", (bad,), marker="x")


def test_no_spans_returns_the_text_unchanged() -> None:
    assert blank_comments(PY_SOURCE, (), marker="x") == PY_SOURCE


@given(
    lines=st.lists(
        st.one_of(
            st.just("x = 1"),
            st.just("y = 'value'"),
            st.text(alphabet="abcdef ghijk-é.", min_size=1, max_size=30).map(lambda t: "# " + t),
        ),
        min_size=1,
        max_size=12,
    )
)
@settings(max_examples=120, deadline=None)
def test_blanking_preserves_line_count_and_every_newline_offset(lines: list[str]) -> None:
    source = "\n".join(lines) + "\n"
    out = blank(source, Language.PYTHON)
    assert len(out.split("\n")) == len(source.split("\n"))
    assert newline_offsets(out) == newline_offsets(source)
    assert len(out.encode()) == len(source.encode())


@pytest.mark.parametrize(
    ("language", "source"),
    [
        (Language.PYTHON, "x = 1  # contact <PII:email:2> about it\n"),
        (Language.JAVASCRIPT, "const a = 1; // contact <PII:email:2> about it\n"),
        (Language.JAVASCRIPT, "const a = 1; /* contact <PII:email:2> about it */\n"),
    ],
)
def test_a_comment_that_holds_a_placeholder_keeps_its_delimiters_and_still_parses(
    language: Language, source: str
) -> None:
    out = blank(source, language)
    assert "<PII:email:2>" in out
    assert "contact" not in out
    assert parse("sample", language, out).error_count == 0
    assert len(out.encode()) == len(source.encode())
