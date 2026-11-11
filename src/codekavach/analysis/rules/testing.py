"""Testing rules against annotated fixtures (E16-02).

Owning epic: E16.

A fixture is a source file at ``<fixtures root>/<language>/<rule-id>.<ext>``. A comment line

* ``# ruleid: <rule-id>`` asserts that the rule matches on the next non-comment line,
* ``# ok: <rule-id>`` asserts that it does not, and
* ``# todoruleid: <rule-id>`` records a known gap: it never fails, and it is counted.

The comment token follows the language. A match that no annotation accounts for is a failure too,
so a rule that starts matching more than its author meant is noticed. ``update_fixture`` rewrites
annotations from actual behaviour; the CLI refuses to call it in continuous integration.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.matcher import Matcher
from codekavach.analysis.rules.pack import RulePack
from codekavach.core.models import Language
from codekavach.core.models.text import split_lines
from codekavach.parsing import parse

EXTENSIONS: Final = {
    "python": "py",
    "javascript": "js",
    "typescript": "ts",
    "java": "java",
    "go": "go",
    "ruby": "rb",
    "php": "php",
    "csharp": "cs",
    "c": "c",
    "cpp": "cpp",
    "rust": "rs",
    "kotlin": "kt",
    "sql": "sql",
    "yaml": "yaml",
}
HASH_LANGUAGES: Final = frozenset({"python", "ruby", "yaml"})
DASH_LANGUAGES: Final = frozenset({"sql"})
_ANNOTATION: Final = re.compile(
    r"^\s*(?:#|//|--)\s*(?P<kind>ruleid|ok|todoruleid):\s*(?P<rule>[A-Za-z0-9_.\-]+)\s*$"
)
_COMMENT_LINE: Final = re.compile(r"^\s*(?:#|//|--|/\*|\*)")


def comment_token(language: str) -> str:
    """The line-comment token of ``language``."""
    if language in HASH_LANGUAGES:
        return "#"
    return "--" if language in DASH_LANGUAGES else "//"


@dataclass(frozen=True, slots=True)
class Annotations:
    """The annotated lines of one fixture for one rule (1-based line numbers)."""

    ruleid: frozenset[int]
    ok: frozenset[int]
    todo: frozenset[int]


@dataclass(frozen=True, slots=True)
class RuleTestResult:
    """The outcome for one rule in one language."""

    rule_id: str
    language: str
    fixture: str
    missing: tuple[int, ...] = ()
    unexpected: tuple[int, ...] = ()
    todo_open: int = 0
    todo_fixed: int = 0
    problem: str | None = None

    @property
    def passed(self) -> bool:
        """True when every annotation held and nothing else matched."""
        return not (self.missing or self.unexpected or self.problem)


@dataclass(frozen=True, slots=True)
class RuleTestReport:
    """All results of a run."""

    results: list[RuleTestResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True when every result passed."""
        return all(result.passed for result in self.results)

    @property
    def known_gaps(self) -> int:
        """Annotated gaps that are still open."""
        return sum(result.todo_open for result in self.results)


def fixture_path(root: Path, language: str, rule_id: str) -> Path:
    """Where the fixture of ``rule_id`` for ``language`` lives."""
    return root / language / f"{rule_id}.{EXTENSIONS.get(language, language)}"


def annotations_of(text: str, rule_id: str) -> Annotations:
    """The lines annotated for ``rule_id``; each refers to the next non-comment line."""
    found: dict[str, set[int]] = {"ruleid": set(), "ok": set(), "todoruleid": set()}
    pending: list[str] = []
    for number, line in enumerate(split_lines(text), start=1):
        note = _ANNOTATION.match(line)
        if note:
            if note["rule"] == rule_id:
                pending.append(note["kind"])
            continue
        if not line.strip() or _COMMENT_LINE.match(line):
            continue
        for kind in pending:
            found[kind].add(number)
        pending = []
    return Annotations(
        frozenset(found["ruleid"]), frozenset(found["ok"]), frozenset(found["todoruleid"])
    )


def _actual_lines(matcher: Matcher, rule: RuleDef, language: Language, text: str) -> set[int]:
    parsed = parse(f"fixture.{EXTENSIONS.get(language.value, 'txt')}", language, text)
    index = parsed.line_index
    if index is None:
        return set()
    result = matcher.match_detailed(parsed, [rule])
    if result.failures:
        raise RuntimeError(result.failures[0].code)
    return {index.position(match.start_byte)[0] for match in result.matches}


def check_rule(matcher: Matcher, rule: RuleDef, language: str, root: Path) -> RuleTestResult:
    """Run ``rule`` over its fixture for ``language``."""
    path = fixture_path(root, language, rule.id)
    shown = f"{language}/{path.name}"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return RuleTestResult(rule.id, language, shown, problem="no fixture")
    try:
        actual = _actual_lines(matcher, rule, Language(language), text)
    except Exception as error:  # noqa: BLE001 - a broken rule is a failed test, not a crash
        return RuleTestResult(rule.id, language, shown, problem=type(error).__name__)
    notes = annotations_of(text, rule.id)
    return RuleTestResult(
        rule.id,
        language,
        shown,
        missing=tuple(sorted(notes.ruleid - actual)),
        unexpected=tuple(sorted(actual - notes.ruleid - notes.todo)),
        todo_open=len(notes.todo - actual),
        todo_fixed=len(notes.todo & actual),
    )


def run_rule_tests(
    packs: Sequence[RulePack],
    fixtures_root: Path,
    *,
    pack_id: str | None = None,
    rule_id: str | None = None,
) -> RuleTestReport:
    """Test every selected rule of ``packs`` against the fixtures under ``fixtures_root``."""
    selected = [pack for pack in packs if pack_id is None or pack.id == pack_id]
    matcher, _ = Matcher.for_packs(selected)
    report = RuleTestReport()
    for pack in selected:
        for rule in pack.rules:
            if rule_id is not None and rule.id != rule_id:
                continue
            for language in rule.languages:
                report.results.append(check_rule(matcher, rule, language, fixtures_root))
    return report


def update_fixture(matcher: Matcher, rule: RuleDef, language: str, root: Path) -> bool:
    """Rewrite the annotations of one fixture from actual behaviour; ``True`` when it changed.

    An actual match without an annotation gains ``ruleid``; a ``ruleid`` annotation that no longer
    matches becomes ``todoruleid``. ``ok`` annotations are kept.
    """
    path = fixture_path(root, language, rule.id)
    text = path.read_text(encoding="utf-8")
    actual = _actual_lines(matcher, rule, Language(language), text)
    notes = annotations_of(text, rule.id)
    token = comment_token(language)
    lines = split_lines(text)
    edits: list[tuple[int, str, str | None]] = [
        (number, f"{token} ruleid: {rule.id}", None)
        for number in sorted(actual - notes.ruleid - notes.todo)
    ]
    edits.extend(
        (number, f"{token} todoruleid: {rule.id}", f"ruleid: {rule.id}")
        for number in sorted(notes.ruleid - actual)
    )
    for number, line, replaces in sorted(edits, reverse=True):
        indent = re.match(r"\s*", lines[number - 1])
        prefix = indent.group(0) if indent else ""
        if replaces is None:
            lines.insert(number - 1, prefix + line)
            continue
        above = number - 2
        while above >= 0 and replaces not in lines[above]:
            above -= 1
        if above >= 0:
            lines[above] = prefix + line
    updated = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    if updated == text:
        return False
    path.write_text(updated, encoding="utf-8", newline="\n")
    return True
