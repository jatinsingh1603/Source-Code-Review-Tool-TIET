"""The isomorphism check of E09-05: what it accepts, what it rejects, what it says.

It is run over every rename fixture of E09-04 and over deliberately corrupted outputs. A failure
message holds node types and indices only, never a piece of source text.
"""

import pytest

from codekavach.core.models import Language, RawCode
from codekavach.parsing import REGISTRY
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.validate import assert_ast_isomorphic, ast_signature
from tests.support.rename import FIXTURES, expanded_starts, rename_text

PY = REGISTRY.get(Language.PYTHON)
JS = REGISTRY.get(Language.JAVASCRIPT)


def cases(folder: str, language: Language) -> list[tuple[Language, str]]:
    return [
        (language, path.name)
        for path in sorted((FIXTURES / folder).iterdir())
        if not path.name.endswith(".golden.txt")
    ]


ALL = (
    cases("python", Language.PYTHON)
    + cases("javascript", Language.JAVASCRIPT)
    + cases("typescript", Language.TYPESCRIPT)
)
FOLDER = {Language.PYTHON: "python", Language.JAVASCRIPT: "javascript"}


@pytest.mark.parametrize(("language", "name"), ALL)
def test_every_rename_fixture_is_isomorphic_to_its_input(language: Language, name: str) -> None:
    folder = {**FOLDER, Language.TYPESCRIPT: "typescript"}[language]
    text = (FIXTURES / folder / name).read_text(encoding="utf-8")
    renamed = rename_text(language, text, path=name)
    assert_ast_isomorphic(
        RawCode(text), renamed.text, REGISTRY.get(language), expanded=expanded_starts(renamed)
    )


def test_the_signature_has_anonymous_nodes_and_neither_comments_nor_leaf_text() -> None:
    signature = ast_signature("x = f(1)  # note\n", PY)
    assert signature[0] == "module"
    assert "(" in signature
    assert "comment" not in signature
    assert "x" not in signature


def test_leaf_text_does_not_matter() -> None:
    assert ast_signature("alpha = beta(1)\n", PY) == ast_signature("a = b(22)\n", PY)
    assert_ast_isomorphic(RawCode("alpha = beta(1)\n"), "var_1 = fn_1(1)\n", PY)


def test_a_comment_does_not_matter() -> None:
    assert_ast_isomorphic(RawCode("x = 1  # about money\n"), "x = 1\n", PY)


def test_a_structural_difference_fails_with_the_index_and_the_types() -> None:
    with pytest.raises(PseudonymError) as caught:
        assert_ast_isomorphic(RawCode("x = f(1)\n"), "x = f(1) + 2\n", PY)
    message = str(caught.value)
    assert "not isomorphic" in message
    assert "first difference at node" in message
    assert "original" in message
    assert "'binary_operator'" in message or "'+'" in message


def test_a_failure_message_never_holds_source_text() -> None:
    client_name = "AccountLedgerSecret"
    with pytest.raises(PseudonymError) as caught:
        assert_ast_isomorphic(RawCode(f"{client_name} = 1\n"), f"{client_name} = (1\n", PY)
    assert client_name not in str(caught.value)
    with pytest.raises(PseudonymError) as caught:
        assert_ast_isomorphic(
            RawCode(f"{client_name} = 1\n"), f"{client_name} = 1 + {client_name}\n", PY
        )
    assert client_name not in str(caught.value)


def test_a_new_error_node_always_fails() -> None:
    with pytest.raises(PseudonymError, match="syntax error"):
        assert_ast_isomorphic(RawCode("x = 1\n"), "x = = 1\n", PY)


def test_a_new_error_node_fails_even_when_the_input_has_errors_too() -> None:
    broken = "def f(:\n    pass\nx = 1\n"
    worse = "def f(:\n    pass\nx = = 1\n"
    with pytest.raises(PseudonymError):
        assert_ast_isomorphic(RawCode(broken), worse, PY)


def test_the_same_error_in_both_is_tolerated() -> None:
    broken = "def f(:\n    pass\nx = 1\n"
    assert_ast_isomorphic(RawCode(broken), broken.replace("x = 1", "y = 1"), PY)


def test_a_missing_closing_quote_changes_many_nodes_and_fails() -> None:
    with pytest.raises(PseudonymError):
        assert_ast_isomorphic(RawCode('a = "text"\nb = 2\n'), 'a = "text\nb = 2\n', PY)


def test_a_shorthand_property_is_compared_as_the_pair_it_became() -> None:
    original = "const { a, b } = c;\nf({ a, b });\n"
    expanded = "const { a: var_1, b: var_2 } = var_3;\nfn_1({ a: var_1, b: var_2 });\n"
    starts = [
        original.index("a,"),
        original.index("b }"),
        original.rindex("a,"),
        original.rindex("b"),
    ]
    assert_ast_isomorphic(RawCode(original), expanded, JS, expanded=starts)
    with pytest.raises(PseudonymError):
        assert_ast_isomorphic(RawCode(original), expanded, JS)  # not declared: a difference


def test_an_expanded_property_with_a_default_is_compared_as_a_pair_of_the_default() -> None:
    original = "const { a = 1 } = c;\n"
    assert_ast_isomorphic(
        RawCode(original), "const { a: var_1 = 1 } = var_2;\n", JS, expanded=[original.index("a")]
    )


def test_a_longer_output_names_the_end_of_the_original() -> None:
    with pytest.raises(PseudonymError, match="first difference"):
        assert_ast_isomorphic(RawCode("x = 1\n"), "x = 1\ny = 2\n", PY)
