"""Helpers for the identifier-classification tests (E09-02).

Owning epic: not a ``codekavach`` module; a test-only helper, so it carries no "Owning epic"
docstring requirement.

``classify_text`` runs the real pipeline (parse, symbol table, import origins, classification) on
a source string, so the tests exercise what the pseudonymiser will run. ``render`` gives the
stable text form that the golden files under ``tests/fixtures/pseudonymise/classification`` hold.
"""

from pathlib import Path

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable, build_symbol_table
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import (
    ClassificationResult,
    IdentifierClass,
    IdentifierClassifier,
    classify_all,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "pseudonymise" / "classification"
PROJECT_ROOT = FIXTURES
# A relative import is internal by construction; any other module name is classified by the
# resolver, with no project file on disk to make it internal.
EXTENSIONS = {
    Language.PYTHON: "py",
    Language.JAVASCRIPT: "js",
    Language.TYPESCRIPT: "ts",
    Language.JAVA: "java",
    Language.GO: "go",
}


def table_and_parsed(language: Language, text: str) -> tuple[ParsedFile, SymbolTable]:
    """Parse ``text`` and build its symbol table with the import origins attached."""
    parsed = parse(f"case.{EXTENSIONS[language]}", language, text)
    table = build_symbol_table(parsed, REGISTRY.get(language))
    table = attach_imports(
        table, parsed, DefaultImportResolver(language), project_root=PROJECT_ROOT
    )
    return parsed, table


def classify_text(
    language: Language, text: str, *, allowlist: PublicAllowlist | None = None
) -> ClassificationResult:
    """Classify ``text`` with the real pipeline and the bundled (or given) allowlist."""
    parsed, table = table_and_parsed(language, text)
    return classify_all(parsed, table, allowlist=allowlist)


def classifier_for(language: Language, text: str) -> IdentifierClassifier:
    """A classifier over ``text`` with the parsed file attached, for per-symbol checks."""
    parsed, table = table_and_parsed(language, text)
    classifier = IdentifierClassifier(
        table, DefaultImportResolver(language), PublicAllowlist.bundled(language)
    )
    classifier.attach(parsed)
    return classifier


def decisions_by_name(result: ClassificationResult) -> dict[str, set[IdentifierClass]]:
    """Every distinct decision made for each name, for compact assertions."""
    grouped: dict[str, set[IdentifierClass]] = {}
    for decision in result.decisions:
        grouped.setdefault(decision.name, set()).add(decision.classification)
    return grouped


def render(result: ClassificationResult, *, name: str, allowlist_version: str) -> str:
    """The stable text form of a result, one line per occurrence, for golden files."""
    lines = [f"file: {name}", f"allowlist: {allowlist_version}"]
    for decision in result.decisions:
        location = decision.location
        notes = ",".join(sorted(decision.notes))
        suffix = f" [{notes}]" if notes else ""
        lines.append(
            f"{location.start_line}:{location.start_col} {decision.name} {decision.kind} "
            f"-> {decision.classification.value} {decision.rule.value}{suffix}"
        )
    counts = result.counts
    lines.append(
        "counts: "
        f"unresolved_base={counts.unresolved_base} unresolved_name={counts.unresolved_name} "
        f"incomplete_table={counts.incomplete_table} kept_identifier={counts.kept_identifier} "
        f"dynamic_name_marked={counts.dynamic_name_marked} dynamic_code={counts.dynamic_code}"
    )
    lines.append("kept_public: " + ", ".join(result.kept_public_names()))
    lines.append("kept_dynamic: " + ", ".join(sorted(result.kept_dynamic)))
    return "\n".join(lines) + "\n"
