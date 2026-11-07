"""Helpers for the native-matcher tests (E13-01): run the built-in matchers over a source string."""

from codekavach.analysis.rules.builtin import BUILTIN_MATCHERS
from codekavach.analysis.rules.engine import NodeMatcher, run_matchers
from codekavach.core.models import Candidate, Language
from codekavach.parsing import parse

EXTENSIONS = {Language.PYTHON: "py", Language.JAVASCRIPT: "js"}


def candidates_in(
    code: str,
    language: Language,
    *,
    path: str | None = None,
    matchers: tuple[NodeMatcher, ...] = BUILTIN_MATCHERS,
) -> list[Candidate]:
    """The candidates the matchers report for ``code`` (no symbol table)."""
    name = path or f"src/sample.{EXTENSIONS[language]}"
    return run_matchers(matchers, parse(name, language, code), None)


def found(code: str, language: Language) -> list[tuple[str, int]]:
    """``(rule_id, start_line)`` of every candidate in ``code``, in report order."""
    return [(c.rule_id, c.primary_location.start_line) for c in candidates_in(code, language)]
