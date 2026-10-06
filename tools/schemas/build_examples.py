"""Generate (or check) one example document per exported schema (E02-29).

Usage::

    uv run python tools/schemas/build_examples.py [--out DIR] [--check]

Writes ``<snake_name>.example.json`` for every model in ``EXPORTED_MODELS``, plus
``llm_verdict.output.example.json`` (the provider-facing verdict, without ``schema_version``) and
``ledger_chain.example.jsonl`` (three sealed entries), into ``docs/schemas/examples``. All examples
come from the deterministic factories in ``tests/support/factories.py`` and tell one story: the
synthetic SQL injection in ``src/bank/accounts.py``. Nothing is produced by running the tool on
real code. ``--check`` compares byte for byte, reports missing, stale and unexpected files, and
never writes.

The script lives under ``tools/`` because it imports the test factories, which the package under
``src/`` must not do.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # run as a script from any directory
    sys.path.insert(0, str(REPO_ROOT))

from tests.support import factories  # noqa: E402

from codekavach.core.models.base import KavachModel  # noqa: E402
from codekavach.core.models.export import EXPORTED_MODELS, snake_name  # noqa: E402

DEFAULT_OUT = REPO_ROOT / "docs" / "schemas" / "examples"
OUTPUT_EXAMPLE = "llm_verdict.output.example.json"
LEDGER_EXAMPLE = "ledger_chain.example.jsonl"
LEDGER_LENGTH = 3
HINT = "run: uv run python tools/schemas/build_examples.py"

FACTORIES: dict[str, Callable[[], KavachModel]] = {
    "Location": factories.make_location,
    "CodeRegion": factories.make_region,
    "TaintPath": factories.make_taint_path,
    "Candidate": factories.make_candidate,
    "CodeSlice": factories.make_slice,
    "SanitisedPayload": factories.make_payload,
    "LLMVerdict": factories.make_verdict,
    "Evidence": factories.make_evidence,
    "Finding": factories.make_finding,
    "EgressRecord": lambda: factories.make_egress_chain(1)[0],
    "Project": factories.make_project,
    "Scan": factories.make_scan,
    "ScanSummary": factories.make_summary,
}


def example_name(model: type[KavachModel]) -> str:
    """The example file name of ``model``, next to its ``<snake_name>.schema.json``."""
    return f"{snake_name(model.__name__)}.example.json"


def build_examples() -> dict[str, str]:
    """File name to content of every example document."""
    missing = [model.__name__ for model in EXPORTED_MODELS if model.__name__ not in FACTORIES]
    if missing:
        raise KeyError(f"no example factory for: {', '.join(missing)}")
    files = {
        example_name(model): FACTORIES[model.__name__]().model_dump_json(indent=2) + "\n"
        for model in EXPORTED_MODELS
    }
    verdict = factories.make_verdict()
    files[OUTPUT_EXAMPLE] = verdict.model_dump_json(indent=2, exclude={"schema_version"}) + "\n"
    chain = factories.make_egress_chain(LEDGER_LENGTH)
    files[LEDGER_EXAMPLE] = "".join(record.model_dump_json() + "\n" for record in chain)
    return dict(sorted(files.items()))


def write_examples(out_dir: Path) -> list[Path]:
    """Write every example into ``out_dir``; return the written paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in build_examples().items():
        path = out_dir / name
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        written.append(path)
    return written


def check_examples(out_dir: Path) -> list[str]:
    """One message per missing, stale or unexpected example file; never writes."""
    expected = build_examples()
    problems = []
    for name, content in expected.items():
        path = out_dir / name
        if not path.exists():
            problems.append(f"missing: {name}")
        elif path.read_bytes() != content.encode("utf-8"):
            problems.append(f"stale: {name}")
    if out_dir.is_dir():
        problems.extend(
            f"unexpected: {path.name}"
            for path in sorted(out_dir.glob("*.example.json*"))
            if path.name not in expected
        )
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description="Generate the schema example documents.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="target directory")
    parser.add_argument("--check", action="store_true", help="report drift and exit 1; no writes")
    args = parser.parse_args(argv)
    if args.check:
        problems = check_examples(args.out)
        for problem in problems:
            sys.stdout.write(problem + "\n")
        if problems:
            sys.stdout.write(HINT + "\n")
            return 1
        return 0
    for path in write_examples(args.out):
        sys.stdout.write(
            f"{path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
