"""JSON Schemas and the field reference of the rule models (E16-01).

Owning epic: E16. The schemas are written to ``docs/schemas/rules/`` so that editors and continuous
integration can validate rule files, and the field reference to ``docs/reference/rule-metadata.md``.
Both are generated from the models, never edited by hand::

    uv run python -m codekavach.analysis.rules.schema          # write
    uv run python -m codekavach.analysis.rules.schema --check  # exit 1 when a file is stale
"""

import argparse
import json
import sys
from pathlib import Path
from types import UnionType
from typing import Annotated, Any, Final, Union, get_args, get_origin

from pydantic import BaseModel

from codekavach.analysis.rules.dsl import (
    Constraint,
    MatchBlock,
    PatternClause,
    RuleDef,
    RuleMeta,
    TaintSpec,
)
from codekavach.analysis.rules.pack import Catalogue, CatalogueEntry, PackManifest

ROOT: Final = Path(__file__).resolve().parents[4]
SCHEMA_DIR: Final = ROOT / "docs" / "schemas" / "rules"
REFERENCE: Final = ROOT / "docs" / "reference" / "rule-metadata.md"
SCHEMAS: Final[dict[str, type[BaseModel]]] = {
    "rule": RuleDef,
    "pack": PackManifest,
    "catalogue": Catalogue,
}
REFERENCE_MODELS: Final[tuple[type[BaseModel], ...]] = (
    RuleDef,
    RuleMeta,
    MatchBlock,
    PatternClause,
    Constraint,
    TaintSpec,
    PackManifest,
    Catalogue,
    CatalogueEntry,
)
FIELD_NOTES: Final[dict[str, str]] = {
    "RuleDef.id": "Unique id, `<language>.<class>.<specific>`, for example `python.sqli.cursor-execute-concat`.",
    "RuleDef.languages": "Languages the rule applies to (names of the `Language` enum).",
    "RuleDef.message": "One-line statement of the problem, shown in the report.",
    "RuleDef.severity": "`info`, `low`, `medium`, `high` or `critical`.",
    "RuleDef.confidence": "`low`, `medium` or `high`: how often a match is a real weakness.",
    "RuleDef.kind": "`vulnerability` (default) or `hotspot`: a hotspot marks code for review and asserts no weakness.",
    "RuleDef.metadata": "What a report says about the weakness (see `RuleMeta`).",
    "RuleDef.match": "The match block (see `MatchBlock`).",
    "RuleDef.taint": "Optional taint spec: catalogue entry ids for sources, sinks and sanitisers.",
    "RuleDef.fixtures": "Paths of the positive and negative test files, relative to the pack.",
    "RuleMeta.cwe": "At least one CWE number; never a Pillar and never CWE-20.",
    "RuleMeta.owasp": "OWASP Top 10 ids such as `A03:2021`.",
    "RuleMeta.asvs": "OWASP ASVS requirement ids such as `5.3.4`.",
    "RuleMeta.capec": "CAPEC attack pattern numbers.",
    "RuleMeta.references": "URLs that explain the weakness.",
    "RuleMeta.remediation": "How to fix it, at most 2,000 characters.",
    "RuleMeta.licence": "SPDX id of the rule's licence; `MIT` for everything under `rules/mit/`.",
    "RuleMeta.source": "Provenance when the rule was adapted from another MIT-licensed pack.",
    "RuleMeta.added_in": "Pack version that introduced the rule.",
    "MatchBlock.any": "Alternatives: at least one clause must hold.",
    "MatchBlock.all": "Every clause must hold.",
    "MatchBlock.none": "No clause may hold.",
    "PatternClause.pattern": "Code pattern with metavariables.",
    "PatternClause.pattern_inside": "The match must lie inside code matching this pattern.",
    "PatternClause.pattern_not_inside": "The match must not lie inside code matching this pattern.",
    "PatternClause.pattern_regex": "Regular expression over the matched text (at most 512 characters).",
    "PatternClause.function_regex": (
        "Regular expression the text of the enclosing function, with its decorators, must match "
        "(at most 512 characters); combine with `none` to exclude handlers that already check."
    ),
    "PatternClause.ref": "Id of another rule in the same pack, for reuse.",
    "PatternClause.where": "Constraints on the clause's metavariables.",
    "Constraint.metavariable": "The metavariable the condition applies to, such as `$Q`.",
    "Constraint.regex": "The bound text must match this expression.",
    "Constraint.not_regex": "The bound text must not match this expression.",
    "Constraint.kind": "Node kind: concatenation, call, literal, identifier, attribute, interpolation or argument.",
    "Constraint.is_constant": "True when the bound node must be a compile-time constant.",
    "Constraint.min_length": "Minimum length of the bound text.",
    "Constraint.equals": "The bound text must equal this value.",
    "Constraint.one_of": "The bound text must equal one of these values.",
    "Constraint.catalogue": "The bound node must match this catalogue entry id (by symbol or pattern).",
    "Constraint.inadequate_for": "The bound node must be a call to a catalogued sanitiser that does not cover this context.",
    "TaintSpec.sources": "Catalogue entry ids of taint sources.",
    "TaintSpec.sinks": "Catalogue entry ids of taint sinks.",
    "TaintSpec.sanitisers": "Catalogue entry ids of sanitisers.",
    "TaintSpec.require_path": "True when a match needs a proven source-to-sink path.",
    "PackManifest.id": "Pack id, lower-case words joined by hyphens.",
    "PackManifest.version": "Semantic version; part of the finding provenance.",
    "PackManifest.licence": "SPDX id; must equal the licence directory the pack lives in.",
    "PackManifest.description": "What the pack covers.",
    "PackManifest.languages": "Languages the pack has rules for.",
    "Catalogue.language": "Language the entries apply to.",
    "Catalogue.framework": "Framework or library the entries describe.",
    "Catalogue.id": "Optional id of the catalogue.",
    "Catalogue.entry_points": "Handlers and other places where outside data enters.",
    "Catalogue.sources": "Symbols that return untrusted data.",
    "Catalogue.sinks": "Symbols that are dangerous with untrusted data.",
    "Catalogue.sanitisers": "Symbols that neutralise data, with the contexts they cover.",
    "Catalogue.entries": "Flat list of entries that each give their own `kind`.",
    "CatalogueEntry.id": "Entry id, referenced from rules and taint specs.",
    "CatalogueEntry.kind": "`entry_point`, `source`, `sink` or `sanitiser`; set by the section the entry is listed in.",
    "CatalogueEntry.type": "What kind of source or entry point, such as `http_param`.",
    "CatalogueEntry.symbol": "Fully qualified dotted name, matched against the imports of the file.",
    "CatalogueEntry.pattern": "Code pattern that identifies the entry; use instead of `symbol`.",
    "CatalogueEntry.arg": "Index of the dangerous argument of a sink.",
    "CatalogueEntry.context": "Output context of a sink: html, html_attr, js, css, url, sql, shell, path, ldap, xpath, xml, header, log, template or deserialisation.",
    "CatalogueEntry.covers": "Contexts a sanitiser is adequate for; a sanitiser covers a sink only when the sink context is listed.",
    "CatalogueEntry.description": "What the entry is.",
}


def schema_text(name: str, model: type[BaseModel]) -> str:
    """The JSON Schema of one model as stable, sorted text."""
    document: dict[str, Any] = model.model_json_schema(mode="validation")
    document["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    document["$id"] = f"urn:codekavach:schema:rules-{name}:1"
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _type_name(annotation: object) -> str:
    """A stable, readable name for a field type (no memory addresses)."""
    origin = get_origin(annotation)
    if origin is Annotated:
        return _type_name(get_args(annotation)[0])
    if origin in (Union, UnionType):
        return " | ".join(_type_name(item) for item in get_args(annotation))
    if origin is not None:
        arguments = ", ".join(
            "..." if item is Ellipsis else _type_name(item) for item in get_args(annotation)
        )
        return f"{getattr(origin, '__name__', str(origin))}[{arguments}]"
    if annotation is type(None):
        return "None"
    return getattr(annotation, "__name__", str(annotation))


def reference_text() -> str:
    """The Markdown field reference, one table per model."""
    lines = [
        "# Rule metadata",
        "",
        "Generated from the rule models by `python -m codekavach.analysis.rules.schema`; do not edit.",
        "A rule file is YAML. Validate it with `codekavach rules validate`. The JSON Schemas are in",
        "`docs/schemas/rules/`.",
        "",
    ]
    for model in REFERENCE_MODELS:
        lines += [
            f"## {model.__name__}",
            "",
            chr(10).join(line.rstrip() for line in (model.__doc__ or "").splitlines()),
            "",
            "| Field | Type | Required | Meaning |",
            "|---|---|---|---|",
        ]
        for name, field in model.model_fields.items():
            note = FIELD_NOTES.get(f"{model.__name__}.{name}", "")
            required = "yes" if field.is_required() else "no"
            lines.append(f"| `{name}` | `{_type_name(field.annotation)}` | {required} | {note} |")
        lines.append("")
    lines += [
        "## Example",
        "",
        "```yaml",
        EXAMPLE.rstrip(),
        "```",
        "",
    ]
    return "\n".join(lines)


EXAMPLE: Final = """id: python.sqli.cursor-execute-concat
languages: [python]
message: SQL query built by string concatenation
severity: high
confidence: medium
metadata:
  cwe: [89]
  owasp: ["A03:2021"]
  asvs: ["5.3.4"]
  capec: [66]
  licence: MIT
  remediation: Use a parameterised query and pass values as parameters.
  references: ["https://cwe.mitre.org/data/definitions/89.html"]
  added_in: "1.0.0"
match:
  any:
    - pattern: $CUR.execute($Q)
      where:
        - metavariable: $Q
          kind: concatenation
  none:
    - pattern: $CUR.execute($Q, $PARAMS)
"""


def expected_files() -> dict[Path, str]:
    """Every generated file and its current text."""
    files = {
        SCHEMA_DIR / f"{name}.schema.json": schema_text(name, model)
        for name, model in SCHEMAS.items()
    }
    files[REFERENCE] = reference_text()
    return files


def check() -> list[str]:
    """One message per missing or stale generated file."""
    problems = []
    for path, text in expected_files().items():
        if not path.is_file():
            problems.append(f"missing: {path.relative_to(ROOT).as_posix()}")
        elif path.read_bytes().decode("utf-8").replace("\r\n", "\n") != text:
            problems.append(f"stale: {path.relative_to(ROOT).as_posix()}")
    return problems


def write() -> None:
    """Write every generated file (LF endings)."""
    for path, text in expected_files().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Write the files, or with ``--check`` report drift and exit 1."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report stale files, change nothing")
    arguments = parser.parse_args(argv)
    if arguments.check:
        problems = check()
        for line in problems:
            sys.stderr.write(line + chr(10))
        return 1 if problems else 0
    write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
