"""Export JSON Schemas of the core models into docs/schemas.

Owning epic: E02. ADR decision D8: the export is a module entry point, not a CLI command.

Usage:
    python -m codekavach.core.models.export [--out DIR] [--check] [--check-migrations]

Each file stands alone (``$defs`` inlined per file) and is written deterministically: sorted keys,
two-space indent, UTF-8, LF line endings and no timestamps, tool versions or absolute paths.
``--check`` compares the files on disk with a fresh build byte for byte and never writes.
``--check-migrations`` reports migratable models with a missing upgrade step (E02-21). Both
checks exit 1 on a problem; under GitHub Actions they also print ``::error`` annotations. CI and
the ``codekavach-schema-drift`` pre-commit hook run them (E02-23).
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codekavach.core.models.base import KavachModel, VersionedModel
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import Finding
from codekavach.core.models.location import CodeRegion, Location
from codekavach.core.models.migrate import check_migration_completeness
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.scan import Project, Scan
from codekavach.core.models.slice import CodeSlice
from codekavach.core.models.summary import ScanSummary
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.verdict import LLMVerdict

EXPORTED_MODELS: tuple[type[KavachModel], ...] = (
    Location,
    CodeRegion,
    TaintPath,
    Candidate,
    CodeSlice,
    SanitisedPayload,
    LLMVerdict,
    Evidence,
    Finding,
    EgressRecord,
    Project,
    Scan,
    ScanSummary,
)
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
INDEX_FILE = "index.json"
OUTPUT_SCHEMA_FILE = "llm_verdict.output.schema.json"
OUTPUT_SCHEMA_NAME = "LLMVerdictOutput"
HINT = "run: uv run python -m codekavach.core.models.export"
MIGRATION_HINT = "register the missing steps; see docs/reference/model-versioning.md"


def snake_name(class_name: str) -> str:
    """Convert a class name to snake case: ``LLMVerdict`` to ``llm_verdict``."""
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", class_name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", spaced).lower()


def schema_version(model: type[KavachModel]) -> int:
    """The model's ``SCHEMA_VERSION``, or 0 for models that are not versioned documents."""
    return model.SCHEMA_VERSION if issubclass(model, VersionedModel) else 0


def _render(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _model_schema(model: type[KavachModel]) -> dict[str, Any]:
    schema = model.model_json_schema(mode="serialization", ref_template="#/$defs/{model}")
    schema["$schema"] = JSON_SCHEMA_DIALECT
    schema["$id"] = f"urn:codekavach:schema:{snake_name(model.__name__)}:{schema_version(model)}"
    schema["x-data-classification"] = model.DATA_CLASSIFICATION.value
    return schema


def build_schemas() -> dict[str, str]:
    """Return file name to file content for every exported schema and the index."""
    files: dict[str, str] = {}
    index: list[dict[str, Any]] = []
    for model in EXPORTED_MODELS:
        name = f"{snake_name(model.__name__)}.schema.json"
        files[name] = _render(_model_schema(model))
        index.append(
            {"name": model.__name__, "file": name, "schema_version": schema_version(model)}
        )
    output = LLMVerdict.llm_output_schema()
    output["$schema"] = JSON_SCHEMA_DIALECT
    output["$id"] = f"urn:codekavach:schema:llm_verdict_output:{LLMVerdict.SCHEMA_VERSION}"
    output["x-data-classification"] = LLMVerdict.DATA_CLASSIFICATION.value
    files[OUTPUT_SCHEMA_FILE] = _render(output)
    index.append(
        {
            "name": OUTPUT_SCHEMA_NAME,
            "file": OUTPUT_SCHEMA_FILE,
            "schema_version": LLMVerdict.SCHEMA_VERSION,
        }
    )
    for entry in index:
        entry["sha256"] = hashlib.sha256(files[entry["file"]].encode("utf-8")).hexdigest()
    files[INDEX_FILE] = _render({"models": sorted(index, key=lambda entry: entry["name"])})
    return files


def export_schemas(out_dir: Path) -> list[Path]:
    """Write every schema file and the index into ``out_dir``; return the written paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, content in build_schemas().items():
        path = out_dir / name
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        written.append(path)
    return written


def check_schemas(out_dir: Path) -> list[str]:
    """Return one message per missing, stale or unexpected schema file; never writes."""
    expected = build_schemas()
    problems: list[str] = []
    for name, content in sorted(expected.items()):
        path = out_dir / name
        if not path.exists():
            problems.append(f"missing: {name}")
        elif path.read_bytes() != content.encode("utf-8"):
            problems.append(f"stale: {name}")
    if out_dir.is_dir():
        problems.extend(
            f"unexpected: {path.name}"
            for path in sorted(out_dir.glob("*.schema.json"))
            if path.name not in expected
        )
    return problems


def _annotate(message: str, file: str | None = None) -> None:
    """Print a GitHub Actions error annotation when running under GitHub Actions."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        where = f" file={file}" if file else ""
        sys.stdout.write(f"::error{where}::{message}\n")


def _drift(out_dir: Path) -> bool:
    problems = check_schemas(out_dir)
    for problem in problems:
        sys.stdout.write(problem + "\n")
        kind, name = problem.split(": ", 1)
        _annotate(f"schema is {kind}, run the export", (out_dir / name).as_posix())
    if problems:
        sys.stdout.write(HINT + "\n")
    return bool(problems)


def _missing_migrations() -> bool:
    versioned = [model for model in EXPORTED_MODELS if issubclass(model, VersionedModel)]
    problems = check_migration_completeness(versioned)
    for problem in problems:
        sys.stdout.write(problem + "\n")
        _annotate(problem)
    if problems:
        sys.stdout.write(MIGRATION_HINT + "\n")
    return bool(problems)


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description="Export the JSON Schemas of the core models.")
    parser.add_argument("--out", type=Path, default=Path("docs/schemas"), help="target directory")
    parser.add_argument("--check", action="store_true", help="report drift and exit 1; no writes")
    parser.add_argument(
        "--check-migrations",
        action="store_true",
        help="report missing migration steps and exit 1; no writes",
    )
    args = parser.parse_args(argv)
    if args.check or args.check_migrations:
        failed = _drift(args.out) if args.check else False
        if args.check_migrations:
            failed = _missing_migrations() or failed
        return 1 if failed else 0
    for path in export_schemas(args.out):
        sys.stdout.write(f"{path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
