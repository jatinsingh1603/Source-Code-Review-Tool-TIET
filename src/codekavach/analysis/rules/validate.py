"""Semantic checks of a rule, each with a stable ``CK-RULE-nnn`` code (E16-01).

Owning epic: E16. The models in ``dsl`` check the shape of a file; this module checks what it
means. ``CK-RULE-011`` (a pattern that does not parse in its language grammar) is declared here and
produced by the matcher of E16-02, which owns the grammars.

The regular-expression check is a deliberately conservative heuristic, not a proof: it rejects an
unbounded quantifier applied to a group that itself contains an unbounded quantifier, and an
over-long expression. Real rule sets contain super-linear expressions (INSIGHTS section 7), and
refusing a few safe ones is the cheaper error.
"""

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from codekavach.analysis.engines.sarif.cwe import PILLARS
from codekavach.analysis.rules.dsl import (
    MAX_REGEX_LENGTH,
    METAVARIABLE,
    NODE_KINDS,
    RULE_ID,
    RuleDef,
)
from codekavach.core.models.enums import Language

TOO_BROAD: Final = frozenset({20})
LANGUAGES: Final = frozenset(item.value for item in Language)
_BOUND: Final = re.compile(r"\$\.\.\.[A-Z][A-Z0-9_]*|\$[A-Z][A-Z0-9_]*")
_OPEN_BOUND: Final = re.compile(r"\{\d*,\}")


class RuleCode(StrEnum):
    """The validation codes; the first twelve are the E16-01 series."""

    UNKNOWN_LANGUAGE = "CK-RULE-001"
    BAD_ID = "CK-RULE-002"
    EMPTY_MATCH = "CK-RULE-003"
    CLAUSE_KINDS = "CK-RULE-004"
    UNBOUND_METAVARIABLE = "CK-RULE-005"
    UNKNOWN_CATALOGUE = "CK-RULE-006"
    UNSAFE_REGEX = "CK-RULE-007"
    MISSING_CWE = "CK-RULE-008"
    BAD_CWE = "CK-RULE-009"
    DUPLICATE_ID = "CK-RULE-010"
    PATTERN_PARSE = "CK-RULE-011"
    LICENCE_MISMATCH = "CK-RULE-012"
    UNKNOWN_REF = "CK-RULE-013"
    BAD_CONSTRAINT = "CK-RULE-014"
    REF_CYCLE = "CK-RULE-015"
    FILE_UNUSABLE = "CK-RULE-100"


@dataclass(frozen=True, slots=True)
class RuleIssue:
    """One problem found in a rule or a file."""

    code: RuleCode
    message: str
    rule_id: str | None = None
    path: str | None = None


def unsafe_regex_reason(text: str) -> str | None:
    """Why ``text`` is refused as a regular expression, or ``None`` when it is accepted."""
    if len(text) > MAX_REGEX_LENGTH:
        return f"longer than {MAX_REGEX_LENGTH} characters"
    try:
        re.compile(text)
    except re.error:
        return "does not compile"
    stack: list[bool] = []  # per open group: does it contain an unbounded quantifier?
    inner = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_class(text, index)
            continue
        if char == "(":
            stack.append(inner)
            inner = False
        elif char == ")" and stack:
            contained = inner
            inner = stack.pop() or contained
            if _unbounded_at(text, index + 1):
                if contained:
                    return "nested unbounded quantifiers"
                inner = True
        elif char in "*+{" and _unbounded_at(text, index):
            inner = True
        index += 1
    return None


def _skip_class(text: str, start: int) -> int:
    index = start + 1
    if index < len(text) and text[index] == "^":
        index += 1
    if index < len(text) and text[index] == "]":
        index += 1
    while index < len(text) and text[index] != "]":
        index += 2 if text[index] == "\\" else 1
    return index + 1


def _unbounded_at(text: str, index: int) -> bool:
    if index >= len(text):
        return False
    return text[index] in "*+" or _OPEN_BOUND.match(text, index) is not None


class _Issues:
    """Collects the issues of one rule."""

    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id
        self.items: list[RuleIssue] = []

    def add(self, code: RuleCode, message: str) -> None:
        self.items.append(RuleIssue(code, message, rule_id=self.rule_id))


def validate_rule(
    rule: RuleDef,
    *,
    catalogue_ids: Collection[str] | None = None,
    licence_dir: str | None = None,
    check_patterns: bool = False,
) -> list[RuleIssue]:
    """Every semantic problem of ``rule``; ``catalogue_ids=None`` skips the catalogue checks.

    ``check_patterns`` also parses every pattern with the grammar of each declared language
    (``CK-RULE-011``). It is off by default because parsing costs far more than the other checks;
    ``codekavach rules validate`` and ``rules test`` turn it on.
    """
    found = _Issues(rule.id)
    if not rule.languages or any(name not in LANGUAGES for name in rule.languages):
        found.add(RuleCode.UNKNOWN_LANGUAGE, "languages must name known languages")
    if not RULE_ID.fullmatch(rule.id):
        found.add(RuleCode.BAD_ID, "the id looks like python.sqli.cursor-execute-concat")
    if not rule.match.clauses and rule.taint is None:
        found.add(RuleCode.EMPTY_MATCH, "the match block has no clause and no taint spec")
    _check_clauses(rule, found)
    _check_bindings(rule, found)
    if catalogue_ids is not None:
        _check_catalogues(rule, set(catalogue_ids), found)
    for text in rule.regexes:
        reason = unsafe_regex_reason(text)
        if reason:
            found.add(RuleCode.UNSAFE_REGEX, f"a regular expression is refused: {reason}")
    cwe = rule.metadata.cwe
    if not cwe:
        found.add(RuleCode.MISSING_CWE, "metadata.cwe needs at least one weakness")
    elif any(number in PILLARS or number in TOO_BROAD for number in cwe):
        found.add(RuleCode.BAD_CWE, "metadata.cwe names a Pillar or CWE-20")
    if check_patterns:
        _check_patterns(rule, found)
    if licence_dir is not None and rule.metadata.licence.lower() != licence_dir.lower():
        found.add(RuleCode.LICENCE_MISMATCH, "metadata.licence differs from the licence directory")
    return found.items


def _check_patterns(rule: RuleDef, found: _Issues) -> None:
    # Imported here: only validation with check_patterns needs the parsers loaded.
    from codekavach.analysis.rules.compile import (  # noqa: PLC0415
        PatternSyntaxError,
        compile_pattern,
    )
    from codekavach.core.models import Language  # noqa: PLC0415
    from codekavach.parsing.loader import grammar_available  # noqa: PLC0415

    for name in rule.languages:
        try:
            language = Language(name)
        except ValueError:
            continue  # CK-RULE-001 already says so
        if not grammar_available(language):
            continue  # nothing to parse with here; the rule is checked where the grammar is
        for pattern in rule.patterns:
            try:
                compile_pattern(pattern, language)
            except PatternSyntaxError:
                found.add(RuleCode.PATTERN_PARSE, f"a pattern does not parse as {name}")


def _ref_cycles(rules: list[RuleDef]) -> list[str]:
    """Ids of the rules that take part in a ``ref`` cycle."""
    edges = {rule.id: [c.ref for c in rule.match.clauses if c.ref is not None] for rule in rules}
    cyclic: list[str] = []
    for start, targets in edges.items():
        stack, seen = list(targets), set()
        while stack:
            current = stack.pop()
            if current == start:
                cyclic.append(start)
                break
            if current in seen or current not in edges:
                continue
            seen.add(current)
            stack.extend(edges[current])
    return cyclic


def _check_clauses(rule: RuleDef, found: _Issues) -> None:
    for clause in rule.match.clauses:
        if len(clause.kinds) != 1:
            found.add(RuleCode.CLAUSE_KINDS, "a clause has exactly one pattern kind")
        for constraint in clause.where:
            if len(constraint.conditions) != 1:
                found.add(RuleCode.BAD_CONSTRAINT, "a constraint has exactly one condition")
            if constraint.kind is not None and constraint.kind not in NODE_KINDS:
                found.add(RuleCode.BAD_CONSTRAINT, "a constraint names an unknown node kind")


def _check_bindings(rule: RuleDef, found: _Issues) -> None:
    bound: set[str] = set()
    for clause in rule.match.clauses:
        for text in (clause.pattern, clause.pattern_inside):
            if text:
                bound.update(_BOUND.findall(text))
    bound.update(name.replace("...", "") for name in tuple(bound))
    for clause in rule.match.clauses:
        for constraint in clause.where:
            name = constraint.metavariable
            if METAVARIABLE.fullmatch(name) and name not in bound:
                found.add(
                    RuleCode.UNBOUND_METAVARIABLE,
                    "a where clause uses a metavariable that no pattern binds",
                )


def _check_catalogues(rule: RuleDef, known: set[str], found: _Issues) -> None:
    wanted: list[str] = []
    if rule.taint is not None:
        wanted.extend((*rule.taint.sources, *rule.taint.sinks, *rule.taint.sanitisers))
    for clause in rule.match.clauses:
        wanted.extend(item.catalogue for item in clause.where if item.catalogue is not None)
    for entry in sorted(set(wanted)):
        if entry not in known:
            found.add(RuleCode.UNKNOWN_CATALOGUE, "a catalogue entry id is in no loaded catalogue")


def validate_rules(
    rules: Iterable[RuleDef],
    *,
    catalogue_ids: Collection[str] | None = None,
    licence_dir: str | None = None,
    check_patterns: bool = False,
) -> list[RuleIssue]:
    """Validate a pack's rules, plus pack-level checks: duplicate ids, bad ``ref``."""
    listed = list(rules)
    found: list[RuleIssue] = []
    seen: set[str] = set()
    for rule in listed:
        if rule.id in seen:
            message = "the rule id occurs twice in the pack"
            found.append(RuleIssue(RuleCode.DUPLICATE_ID, message, rule.id))
        seen.add(rule.id)
        found.extend(
            validate_rule(
                rule,
                catalogue_ids=catalogue_ids,
                licence_dir=licence_dir,
                check_patterns=check_patterns,
            )
        )
    message = "ref leads back to the rule itself"
    found.extend(RuleIssue(RuleCode.REF_CYCLE, message, rule_id) for rule_id in _ref_cycles(listed))
    for rule in listed:
        for clause in rule.match.clauses:
            if clause.ref is not None and clause.ref not in seen:
                message = "ref names a rule that is not in the pack"
                found.append(RuleIssue(RuleCode.UNKNOWN_REF, message, rule.id))
    return found
