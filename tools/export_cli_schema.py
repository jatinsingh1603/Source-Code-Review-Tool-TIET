"""Write (or check) the JSON Schema of the CLI envelope: ``docs/schemas/cli/envelope.schema.json``.

The schema lives in its own sub-directory so that the domain-model exporter of E02-22, which owns
``docs/schemas/*.schema.json``, does not report it as unexpected.

Usage: ``uv run python tools/export_cli_schema.py [--check]``.
"""

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from codekavach.cli.envelope import Envelope

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "cli" / "envelope.schema.json"


def render() -> str:
    """The schema text, stable byte for byte."""
    schema = Envelope.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:codekavach:schema:cli_envelope:1"
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Write the schema, or with ``--check`` report whether it is up to date."""
    args = list(sys.argv[1:] if argv is None else argv)
    content = render()
    if "--check" in args:
        current = SCHEMA_PATH.read_text(encoding="utf-8") if SCHEMA_PATH.exists() else ""
        if current != content:
            sys.stderr.write(f"stale: {SCHEMA_PATH.relative_to(ROOT)}\n")
            return 1
        return 0
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SCHEMA_PATH.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
