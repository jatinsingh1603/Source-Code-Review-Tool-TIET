"""Tree-sitter query loading and caching (E07-01)."""

import pytest

from codekavach.core.models import Language
from codekavach.parsing.queries import QueryError, QueryNotFoundError, load_query


def test_load_query_compiles_and_caches() -> None:
    first = load_query(Language.PYTHON, "_fixture")
    second = load_query(Language.PYTHON, "_fixture")
    assert first is second


def test_load_query_raises_not_found_for_a_missing_file() -> None:
    with pytest.raises(QueryNotFoundError):
        load_query(Language.PYTHON, "_does_not_exist")


def test_load_query_raises_query_error_naming_the_file_and_grammar_version() -> None:
    with pytest.raises(QueryError) as excinfo:
        load_query(Language.PYTHON, "_fixture_invalid")
    error = excinfo.value
    assert error.name == "_fixture_invalid"
    assert error.language is Language.PYTHON
    assert error.version
    assert "_fixture_invalid" in str(error)
    assert error.version in str(error)
