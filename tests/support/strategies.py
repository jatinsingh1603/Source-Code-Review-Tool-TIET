"""Shared hypothesis strategies. E02 adds model strategies to this module."""

import keyword
import string

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from tests.support.synthetic import SECRET_SHAPES, build_secret

# ECMAScript reserved words: never valid identifiers in JavaScript.
_JS_RESERVED = frozenset(
    {
        "await", "break", "case", "catch", "class", "const", "continue", "debugger",
        "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally",
        "for", "function", "if", "implements", "import", "in", "instanceof", "interface",
        "let", "new", "null", "package", "private", "protected", "public", "return", "static",
        "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void", "while",
        "with", "yield",
    }
)  # fmt: skip
_NON_ASCII_LETTERS = "éñßøçλπждü"
_LOWER = string.ascii_lowercase + _NON_ASCII_LETTERS
_WORD = st.text(alphabet=_LOWER, min_size=1, max_size=8)


def _join(words: list[str], style: str) -> str:
    if style == "snake":
        return "_".join(words)
    return words[0] + "".join(w[:1].upper() + w[1:] for w in words[1:])


def _is_valid(name: str) -> bool:
    return (
        name.isidentifier()
        and not keyword.iskeyword(name)
        and name not in _JS_RESERVED
        and name.isprintable()
    )


def identifiers(min_size: int = 1, max_size: int = 40) -> SearchStrategy[str]:
    """Valid Python and JavaScript identifiers, never a keyword.

    Covers snake_case, camelCase, leading underscores, digit suffixes and non-ASCII letters.
    """

    @st.composite
    def build(draw: st.DrawFn) -> str:
        words = draw(st.lists(_WORD, min_size=1, max_size=4))
        name = _join(words, draw(st.sampled_from(["snake", "camel"])))
        name = "_" * draw(st.integers(0, 2)) + name
        if draw(st.booleans()):
            name += str(draw(st.integers(0, 99)))
        name = name[:max_size]
        if len(name) < min_size:
            name += "x" * (min_size - len(name))
        return name

    return build().filter(_is_valid)


def fake_secrets() -> SearchStrategy[tuple[str, str]]:
    """Pairs of (kind, value) whose value matches the kind's detector pattern."""

    @st.composite
    def build(draw: st.DrawFn) -> tuple[str, str]:
        kind = draw(st.sampled_from(sorted(SECRET_SHAPES)))
        body = draw(st.from_regex(SECRET_SHAPES[kind].body_pattern, fullmatch=True))
        return kind, build_secret(kind, body)

    return build()


def nested_json(leaves: SearchStrategy[object]) -> SearchStrategy[object]:
    """Dicts, lists and tuples nested up to depth 4, always holding at least one leaf."""

    def containers(children: SearchStrategy[object]) -> SearchStrategy[object]:
        items = st.lists(children, min_size=1, max_size=4)
        return st.one_of(
            items,
            items.map(tuple),
            st.dictionaries(st.text(max_size=8), children, min_size=1, max_size=4),
        )

    level: SearchStrategy[object] = leaves
    for _ in range(3):
        level = st.one_of(leaves, containers(level))
    return containers(level)
