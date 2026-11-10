"""The grammar probe that ``codekavach doctor`` calls (E07-05).

Owning epic: E07.

``doctor`` reaches this module through ``load_backend("codekavach.parsing.grammars",
"load_grammar")``, so the command line does not import tree-sitter unless a check runs.
"""

from codekavach.core.models import Language
from codekavach.parsing.loader import grammar_version, load_language


def load_grammar(language: str) -> str:
    """Load the pinned grammar of ``language`` and return its pinned version string.

    Raises:
        ValueError: ``language`` is not a ``Language`` value.
        LookupError: the language has no pinned grammar, or the grammar library is missing.
    """
    parsed = Language(language)
    load_language(parsed)
    return grammar_version(parsed)
