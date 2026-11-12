"""Helpers for the renamer tests (E09-04).

Owning epic: not a ``codekavach`` module; a test-only helper, so it carries no "Owning epic"
docstring requirement.

``rename_text`` runs what the pseudonymise stage will run: parse, symbol table with import
origins, classification, plan, validation and application. ``node_types`` is the sequence the
differential test compares: the named node types of a tree in pre-order, without comments, with
each shorthand property that the renamer expanded written as the pair it became.
"""

import re
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Node, Tree

from codekavach.core.models import Language, RawCode
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import ClassificationResult, classify_all
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.plan import EditReason, RenamePlan
from codekavach.privacy.pseudonymise.renamers.base import RenameReport
from codekavach.privacy.pseudonymise.renamers.registry import default_registry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "pseudonymise" / "rename"
SALT = ScanSalt(bytes(range(32)))
EXTENSIONS = {
    Language.PYTHON: "py",
    Language.JAVASCRIPT: "js",
    Language.TYPESCRIPT: "ts",
    Language.JAVA: "java",
    Language.GO: "go",
    Language.KOTLIN: "kt",
    Language.PHP: "php",
    Language.CSHARP: "cs",
    Language.RUBY: "rb",
    Language.C: "c",
    Language.CPP: "cpp",
}
_DIRECTIVE = re.compile(r"^(?:#|//)\s*extra:\s*(?P<names>.*)$")


@dataclass(frozen=True)
class Renamed:
    """Everything a test wants to look at after renaming one text."""

    text: str
    plan: RenamePlan
    report: RenameReport
    parsed: ParsedFile
    classification: ClassificationResult


def extras_of(text: str) -> tuple[str, ...]:
    """The names a fixture declares public: a first line ``# extra: a, b`` (``//`` in JS)."""
    first = text.split("\n", 1)[0]
    match = _DIRECTIVE.match(first)
    if match is None:
        return ()
    return tuple(name.strip() for name in match.group("names").split(",") if name.strip())


def rename_text(
    language: Language,
    text: str,
    *,
    extra: Collection[str] | None = None,
    path: str | None = None,
    generator: PseudonymGenerator | None = None,
) -> Renamed:
    """Rename ``text`` the way the pseudonymise stage does."""
    names = tuple(extra) if extra is not None else extras_of(text)
    name = path or f"case.{EXTENSIONS[language]}"
    parsed = parse(name, language, text)
    table = build_symbol_table(parsed, REGISTRY.get(language))
    table = attach_imports(table, parsed, DefaultImportResolver(language), project_root=FIXTURES)
    allowlist = PublicAllowlist.bundled(language, extra=names)
    classification = classify_all(parsed, table, allowlist=allowlist)
    renamer = default_registry().get(language)
    plan, report = renamer.plan_with_report(
        parsed,
        classification,
        generator or PseudonymGenerator(SALT),
        allowlist=allowlist,
    )
    return Renamed(
        text=renamer.rename(RawCode(text), plan),
        plan=plan,
        report=report,
        parsed=parsed,
        classification=classification,
    )


_EXPANDED_PAIR = {
    "shorthand_property_identifier": ("pair", "property_identifier", "identifier"),
    "shorthand_property_identifier_pattern": ("pair_pattern", "property_identifier", "identifier"),
}


def _walk(node: Node, expanded: Collection[int]) -> Iterator[str]:
    if node.type == "comment":
        return
    if node.start_byte in expanded and node.type in _EXPANDED_PAIR:
        yield from _EXPANDED_PAIR[node.type]
        return
    if (
        node.type == "object_assignment_pattern"
        and node.children
        and node.children[0].start_byte in expanded
    ):
        # ``{ a = 1 }`` became ``{ a: var_1 = 1 }``: a pair whose value has the default.
        yield "pair_pattern"
        yield "property_identifier"
        yield "assignment_pattern"
        yield "identifier"
        for child in node.children[1:]:
            yield from _walk(child, expanded)
        return
    if node.is_named:
        yield node.type
    for child in node.children:
        yield from _walk(child, expanded)


def node_types(tree: Tree | None, *, expanded: Collection[int] = ()) -> list[str]:
    """The named node types of ``tree`` in pre-order, without comments."""
    assert tree is not None
    return list(_walk(tree.root_node, expanded))


def expanded_starts(renamed: Renamed) -> list[int]:
    """The start bytes in the original of the shorthand properties the plan expanded."""
    return [e.start_byte for e in renamed.plan.edits if e.reason is EditReason.SHORTHAND_KEY]
