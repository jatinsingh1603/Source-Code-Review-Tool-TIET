"""Deterministic rule bundles for offline installs (E16-01).

Owning epic: E16. A ``.ckrules`` file is gzip-compressed canonical JSON with no timestamp, so two
runs from the same tree produce the same bytes. It holds a manifest (pack ids, versions,
checksums and the CodeKavach version) and the packs. Reading checks every checksum again, caps
the decompressed size and needs no network.
"""

import gzip
import io
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from codekavach.analysis.rules.errors import RuleFileTooLargeError, RuleShapeError, RuleYamlError
from codekavach.analysis.rules.pack import RulePack, pack_checksum
from codekavach.core.models.canonical import canonical_json

FORMAT: Final = "ckrules/1"
MAX_BUNDLE_BYTES: Final = 64 * 1024 * 1024
MAX_COMPRESSED_BYTES: Final = 64 * 1024 * 1024


def bundle_bytes(packs: Sequence[RulePack], *, codekavach_version: str) -> bytes:
    """The bundle of ``packs`` as bytes; the same packs always give the same bytes."""
    ordered = sorted(packs, key=lambda pack: pack.id)
    document = {
        "format": FORMAT,
        "codekavach_version": codekavach_version,
        "manifest": [
            {"id": pack.id, "version": pack.version, "checksum": pack.checksum} for pack in ordered
        ],
        "packs": [pack.model_dump(mode="json") for pack in ordered],
    }
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0, compresslevel=6) as handle:
        handle.write(canonical_json(document))
    return buffer.getvalue()


def write_bundle(packs: Sequence[RulePack], out: Path, *, codekavach_version: str) -> str:
    """Write the bundle to ``out`` and return its SHA-256."""
    import hashlib  # noqa: PLC0415 - used once

    data = bundle_bytes(packs, codekavach_version=codekavach_version)
    out.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def read_bundle(path: Path) -> list[RulePack]:
    """The packs of a bundle, with their checksums verified."""
    try:
        with path.open("rb") as handle:
            compressed = handle.read(MAX_COMPRESSED_BYTES + 1)
        if len(compressed) > MAX_COMPRESSED_BYTES:
            raise RuleFileTooLargeError(path, "is larger than the bundle limit")
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as handle:
            raw = handle.read(MAX_BUNDLE_BYTES + 1)
    except (OSError, EOFError):
        raise RuleYamlError(path, "is not a readable bundle") from None
    if len(raw) > MAX_BUNDLE_BYTES:
        raise RuleFileTooLargeError(path, "expands beyond the bundle limit")
    try:
        document = json.loads(raw)
        if document["format"] != FORMAT:
            raise RuleShapeError(path, "has an unknown bundle format")
        packs = [RulePack.model_validate(item) for item in document["packs"]]
        listed = {(m["id"], m["version"], m["checksum"]) for m in document["manifest"]}
    except (ValueError, KeyError, TypeError, ValidationError):
        raise RuleShapeError(path, "is not a valid bundle") from None
    for pack in packs:
        if pack_checksum(pack.rules) != pack.checksum:
            raise RuleShapeError(path, f"pack {pack.id} does not match its checksum")
    if listed != {(pack.id, pack.version, pack.checksum) for pack in packs}:
        raise RuleShapeError(path, "the manifest does not match the packs")
    return packs
