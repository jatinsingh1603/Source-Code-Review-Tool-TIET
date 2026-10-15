"""Tree-sitter query loading and compilation caching (E07-01).

Owning epic: E07.

Queries are data files (``.scm``), not string literals, so a contributor can run one through the
tree-sitter playground directly, and a grammar bump produces a compile error in a named file
rather than a silent change in matching behaviour. ``load_query`` compiles each query once per
``(language, name, grammar_version)`` and caches the result: compiling the same query again for
every file of a scan would be wasted work, and keying on the grammar version means a pinned-grammar
bump (E07-01's own drift test) gets a fresh compile instead of a stale cached one.
"""

import importlib.resources
from threading import Lock

from tree_sitter import Query as TSQuery
from tree_sitter import QueryError as _TreeSitterQueryError

from codekavach.core.models import Language
from codekavach.parsing.loader import grammar_version, load_language

QUERIES_PACKAGE = "codekavach.parsing.queries"


class QueryError(Exception):
    """A ``.scm`` query file did not compile against its pinned grammar."""

    def __init__(self, language: Language, name: str, version: str, reason: str) -> None:
        self.language = language
        self.name = name
        self.version = version
        self.reason = reason
        super().__init__(
            f"query {name!r} for {language.value!r} does not compile against grammar "
            f"{version!r}: {reason}"
        )


class QueryNotFoundError(FileNotFoundError):
    """No ``<name>.scm`` file exists for ``language``."""

    def __init__(self, language: Language, name: str) -> None:
        self.language = language
        self.name = name
        super().__init__(f"no query file {name!r} for language {language.value!r}")


_lock = Lock()
_cache: dict[tuple[Language, str, str], TSQuery] = {}


def _read_query_source(language: Language, name: str) -> str:
    resource = importlib.resources.files(QUERIES_PACKAGE).joinpath(language.value, f"{name}.scm")
    try:
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
        raise QueryNotFoundError(language, name) from None


def load_query(language: Language, name: str) -> TSQuery:
    """Return the compiled, cached query ``name`` of ``language``.

    Raises:
        QueryNotFoundError: no ``<name>.scm`` file exists for ``language``.
        QueryError: the file does not compile against the pinned grammar.
    """
    version = grammar_version(language)
    key = (language, name, version)
    with _lock:
        cached = _cache.get(key)
        if cached is not None:
            return cached
        source = _read_query_source(language, name)
        grammar = load_language(language)
        try:
            query = TSQuery(grammar, source)
        except _TreeSitterQueryError as error:
            raise QueryError(language, name, version, str(error)) from error
        _cache[key] = query
        return query
