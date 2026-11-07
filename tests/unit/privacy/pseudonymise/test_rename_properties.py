"""Properties of the renamers over generated programs with known bindings (E09-04).

The generated names are lower-case words of four to nine letters that no allowlist rule keeps, so
every one of them is an internal binding. For each program: no such name survives (invariant I6),
the public names the program uses are untouched, the output parses, its node-type sequence equals
the input's, and renaming is deterministic. The leak check is the control the issue names for I6.

Idempotence is not a property of these renamers, and is not tested: an original name spelled like
a token (``fn_1``) must be renamed like any other (I6), as it is for literals (E09-03), so a
second pass renames the first pass's tokens.
"""

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.parsing import parse
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from tests.support.rename import expanded_starts, node_types, rename_text

PYTHON_ALLOWLIST = PublicAllowlist.bundled(Language.PYTHON)
JAVASCRIPT_ALLOWLIST = PublicAllowlist.bundled(Language.JAVASCRIPT)
WORD = st.from_regex(r"[a-z]{4,9}", fullmatch=True)


def internal_names(allowlist: PublicAllowlist, count: int) -> st.SearchStrategy[list[str]]:
    free = WORD.filter(lambda word: not allowlist.is_public(word) and not word.startswith("tok"))
    return st.lists(free, min_size=count, max_size=count, unique=True)


PYTHON_TEMPLATE = (
    "def {f}({p}, {q}=1):\n"
    "    {l} = {p} + {q}\n"
    "    for {i} in range({l}):\n"
    "        print({i}, {l}, {c}.{m})\n"
    "    return {l}\n"
)
JAVASCRIPT_TEMPLATE = (
    "function {f}({p}, {q} = 1) {{\n"
    "  const {l} = {p} + {q};\n"
    "  const {{ {a}, {b} }} = {l};\n"
    "  console.log({a}, {b}, {c}.{m});\n"
    "  return {{ {a}, {b}, {k}: {l} }};\n"
    "}}\n"
)


def python_program(names: list[str]) -> str:
    f, p, q, i, c, m, l = names  # noqa: E741 - the template's own letters
    return PYTHON_TEMPLATE.format(f=f, p=p, q=q, i=i, c=c, m=m, l=l)


def javascript_program(names: list[str]) -> str:
    f, p, q, a, b, c, m, k, l = names  # noqa: E741
    return JAVASCRIPT_TEMPLATE.format(f=f, p=p, q=q, a=a, b=b, c=c, m=m, k=k, l=l)


@settings(max_examples=60, deadline=None)
@given(names=internal_names(PYTHON_ALLOWLIST, 7))
def test_python_every_internal_name_is_replaced_and_public_names_are_not(names: list[str]) -> None:
    source = python_program(names)
    renamed = rename_text(Language.PYTHON, source, extra=())
    words = set(re.findall(r"\w+", renamed.text))
    assert not set(names) & words
    assert {"print", "range"} <= words
    again = parse("o.py", Language.PYTHON, renamed.text)
    assert again.error_count == 0
    assert node_types(again.tree) == node_types(renamed.parsed.tree)
    assert rename_text(Language.PYTHON, source, extra=()).text == renamed.text


@settings(max_examples=60, deadline=None)
@given(names=internal_names(JAVASCRIPT_ALLOWLIST, 9))
def test_javascript_every_internal_name_is_replaced_or_kept_only_as_a_shorthand_key(
    names: list[str],
) -> None:
    source = javascript_program(names)
    renamed = rename_text(Language.JAVASCRIPT, source, extra=())
    keys = set(names[3:5])  # the two names written as shorthand
    for name in names:
        for found in re.finditer(rf"\b{name}\b", renamed.text):
            assert name in keys, name
            assert re.match(r": (?:var|param)_\d+", renamed.text[found.end() :]), name
    assert "console.log" in renamed.text
    again = parse("o.js", Language.JAVASCRIPT, renamed.text)
    assert again.error_count == 0
    assert node_types(again.tree) == node_types(
        renamed.parsed.tree, expanded=expanded_starts(renamed)
    )
    assert rename_text(Language.JAVASCRIPT, source, extra=()).text == renamed.text


@settings(max_examples=30, deadline=None)
@given(names=internal_names(PYTHON_ALLOWLIST, 7))
def test_the_second_pass_still_parses_and_keeps_the_shape(names: list[str]) -> None:
    once = rename_text(Language.PYTHON, python_program(names), extra=())
    twice = rename_text(Language.PYTHON, once.text, extra=())
    assert node_types(parse("o.py", Language.PYTHON, twice.text).tree) == node_types(
        once.parsed.tree
    )
    assert not set(names) & set(re.findall(r"\w+", twice.text))
