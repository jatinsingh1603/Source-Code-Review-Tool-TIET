"""Every golden wire file loads, validates and re-serialises to identical bytes (E02-27).

This is the single place that loads all of them, so a change that silently alters
serialisation fails here with a byte-level diff. When a schema version is bumped, the old
golden file stays (it must still load through ``load_versioned``) and the new one is added next
to it with a row in ``LOADERS``. The ``*.txt`` files are rendering goldens owned by the
evidence renderer tests (E02-15) and are not wire formats.
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from codekavach.core.models.candidate import Candidate
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.finding import Finding
from codekavach.core.models.migrate import load_versioned
from codekavach.core.models.scan import Scan

GOLDEN = Path(__file__).parent / "golden"


def _document(model: type[Candidate | Finding | Scan]) -> Callable[[str], str]:
    def reserialise(text: str) -> str:
        return load_versioned(model, text).model_dump_json(indent=2) + "\n"

    return reserialise


def _ledger(text: str) -> str:
    records = [load_versioned(EgressRecord, line) for line in text.splitlines()]
    for previous, record in zip([None, *records], records, strict=False):
        record.verify_link(previous)
    return "".join(record.model_dump_json() + "\n" for record in records)


def _plain_json(text: str) -> str:
    return json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


LOADERS: dict[str, Callable[[str], str]] = {
    "candidate_v1.json": _document(Candidate),
    "finding_v1.json": _document(Finding),
    "scan_v1.json": _document(Scan),
    "ledger_chain_v1.jsonl": _ledger,
    "llm_verdict_output_schema.json": _plain_json,
}


def wire_files() -> list[str]:
    return sorted(path.name for path in GOLDEN.iterdir() if path.suffix in {".json", ".jsonl"})


def test_every_wire_file_has_a_loader() -> None:
    files = set(wire_files())
    assert files == set(LOADERS), (
        f"unlisted: {sorted(files - set(LOADERS))}, missing: {sorted(set(LOADERS) - files)}"
    )


@pytest.mark.parametrize("name", sorted(LOADERS))
def test_wire_file_round_trips_byte_for_byte(name: str) -> None:
    raw = (GOLDEN / name).read_bytes()
    assert b"\r" not in raw, f"{name} has CRLF line endings; golden files are LF only"
    text = raw.decode("utf-8")
    assert LOADERS[name](text) == text
