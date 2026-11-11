"""Helpers for the native-matcher tests (E13-01) and the rule-engine tests (E16-02)."""

from collections.abc import Sequence
from typing import Any

from codekavach.analysis.rules.builtin import BUILTIN_MATCHERS
from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.engine import NodeMatcher, run_matchers
from codekavach.analysis.rules.matcher import Matcher, RuleMatch
from codekavach.analysis.rules.pack import CatalogueEntry, CatalogueKind
from codekavach.core.models import Candidate, Language
from codekavach.parsing import parse
from tests.support.rule_files import rule_data

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


def rule_of(match: dict[str, Any], **changes: Any) -> RuleDef:
    """A valid rule whose match block is ``match``."""
    return RuleDef.model_validate(rule_data(match=match, **changes))


def matches_of(
    code: str,
    match: dict[str, Any],
    *,
    language: Language = Language.PYTHON,
    matcher: Matcher | None = None,
    extra: Sequence[RuleDef] = (),
    **changes: Any,
) -> list[RuleMatch]:
    """The matches of one inline rule over ``code``."""
    rule = rule_of(match, **changes)
    name = f"src/sample.{EXTENSIONS[language]}"
    parsed = parse(name, language, code)
    return (matcher or Matcher()).match_file(parsed, [rule, *extra])


def lines_of(code: str, matches: Sequence[RuleMatch]) -> list[int]:
    """1-based start lines of ``matches``."""
    data = code.encode("utf-8")
    return [data[: item.start_byte].count(10) + 1 for item in matches]


def catalogue_entry(entry_id: str, pattern: str) -> CatalogueEntry:
    """A catalogue entry of kind sink."""
    return CatalogueEntry(id=entry_id, kind=CatalogueKind.SINK, pattern=pattern)
