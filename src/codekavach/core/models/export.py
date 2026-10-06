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
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from codekavach.core.models.base import KavachModel, VersionedModel
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.compat import classify_change
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


# --- compatibility gate against a git revision (E02-24) ---------------------------------------

GIT_TIMEOUT_SECONDS = 10
REMOVE_MARKER = "[schema-remove]"
_REF = re.compile(r"^[A-Za-z0-9._/~^-]{1,100}$")


class _GitTimeoutError(Exception):
    """A git call took longer than ``GIT_TIMEOUT_SECONDS``."""


def _git(args: Sequence[str], cwd: Path | None) -> "subprocess.CompletedProcess[str]":
    """Run git without a shell; ``FileNotFoundError`` when git is missing."""
    try:
        return subprocess.run(
            ["git", *args],  # noqa: S607 - git from PATH is the intent
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        raise _GitTimeoutError from None


def _versions(index_text: str) -> dict[str, int]:
    return {entry["file"]: entry["schema_version"] for entry in json.loads(index_text)["models"]}


def _git_path(out_dir: Path, name: str, cwd: Path | None) -> str:
    target = out_dir / name
    if target.is_absolute():
        target = target.relative_to((cwd or Path.cwd()).resolve())
    return "./" + target.as_posix()


def compat_check(
    base: str,
    out_dir: Path,
    *,
    build: Callable[[], dict[str, str]] = build_schemas,
    cwd: Path | None = None,
) -> tuple[int, list[str]]:
    """Compare the built schemas with those of revision ``base``: ``(exit code, lines)``.

    Exit 1 when a file changes in a breaking way and keeps its schema version, or is deleted
    without a ``[schema-remove]`` commit message; 0 otherwise. A missing git executable or base
    revision skips the check with a notice (exit 0), an invalid reference is a usage error
    (exit 2), and a git call that times out exits 2.
    """
    if not _REF.match(base) or base.startswith("-"):
        return 2, ["invalid --compat-base reference"]
    try:
        verified = _git(["rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"], cwd)
        if verified.returncode != 0:
            return 0, [f"notice: base revision {base} is not in this clone; check skipped"]
        old_index = _git(["show", f"{base}:{_git_path(out_dir, INDEX_FILE, cwd)}"], cwd)
        if old_index.returncode != 0:
            return 0, [f"notice: {base} has no {INDEX_FILE}; nothing to compare"]
        old_versions = _versions(old_index.stdout)
        built = build()
        new_versions = _versions(built[INDEX_FILE])
        lines: list[str] = []
        failed = False
        for name in sorted(set(built) - {INDEX_FILE}):
            shown = _git(["show", f"{base}:{_git_path(out_dir, name, cwd)}"], cwd)
            if shown.returncode != 0:
                lines.append(f"{name}: additive (new file)")
                continue
            report = classify_change(json.loads(shown.stdout), json.loads(built[name]))
            bumped = new_versions.get(name) != old_versions.get(name)
            lines.append(f"{name}: {report.level}" + (" (schema version raised)" if bumped else ""))
            if report.level == "breaking" and not bumped:
                failed = True
                lines.extend(f"  - {reason}" for reason in report.reasons)
                _annotate(
                    f"breaking schema change without a version bump: {report.reasons[0]}",
                    _git_path(out_dir, name, cwd)[2:],
                )
        removed = sorted(set(old_versions) - set(new_versions))
        if removed:
            log = _git(["log", "--format=%B", f"{base}..HEAD"], cwd)
            allowed = log.returncode == 0 and REMOVE_MARKER in log.stdout
            for name in removed:
                lines.append(f"{name}: breaking (file removed)")
                if not allowed:
                    failed = True
                    lines.append(f"  - add {REMOVE_MARKER} to a commit message to remove a schema")
    except FileNotFoundError:
        return 0, ["notice: git is not available; compatibility check skipped"]
    except _GitTimeoutError:
        return 2, [f"git did not answer within {GIT_TIMEOUT_SECONDS} seconds"]
    if failed:
        lines.append(
            "a breaking change needs SCHEMA_VERSION raised and a migration step; "
            "see docs/reference/model-versioning.md"
        )
    return (1 if failed else 0), lines


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
    parser.add_argument(
        "--compat-base",
        metavar="REF",
        help="classify changes against git revision REF; exit 1 on an unversioned break",
    )
    args = parser.parse_args(argv)
    if args.compat_base is not None:
        code, lines = compat_check(args.compat_base, args.out)
        for line in lines:
            sys.stdout.write(line + "\n")
        return code
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
