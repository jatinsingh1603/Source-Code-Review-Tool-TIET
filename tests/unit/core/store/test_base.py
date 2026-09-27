import hashlib
import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from codekavach.core.store.base import (
    ArtefactCorruptError,
    ArtefactForbiddenError,
    ArtefactSerialisationError,
    ArtefactTypeError,
    EncodedArtefact,
    decode_json,
    decode_list,
    decode_model,
    encode_artefact,
    parts_digest,
    type_tag,
)

MARKER = "PLANTEDVALUE"


class FileRecord(BaseModel):
    path: str
    size: int
    score: float = 0.0


class Other(BaseModel):
    path: str


class Salt:
    __ck_never_persist__ = True


def test_canonical_encoding_is_order_independent() -> None:
    first = encode_artefact({"b": 1, "a": {"y": [1, 2.5], "x": None}})
    second = encode_artefact({"a": {"x": None, "y": [1, 2.5]}, "b": 1})
    assert first.data == second.data
    assert first.digest == second.digest == hashlib.sha256(first.data).hexdigest()
    assert json.loads(first.data) == {
        "ck_artefact": 1,
        "shape": "json",
        "type": "",
        "data": {"a": {"x": None, "y": [1, 2.5]}, "b": 1},
    }


def test_model_and_list_envelopes() -> None:
    record = FileRecord(path="app/main.py", size=120, score=7.5)
    encoded = encode_artefact(record)
    assert (encoded.shape, encoded.type_tag) == ("model", type_tag(FileRecord))
    assert decode_model("files", encoded, FileRecord) == record
    listed = encode_artefact((record, record))
    assert listed.shape == "list"
    assert decode_list("files", listed, FileRecord) == [record, record]
    empty = encode_artefact([])
    assert (empty.shape, empty.type_tag) == ("list", "")
    assert decode_list("files", empty, Other) == []
    assert decode_json("files", encoded) == record.model_dump(mode="json")


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        {"x": float("inf")},
        {1: MARKER},
        {MARKER: object()},
        [FileRecord(path=MARKER, size=1), Other(path=MARKER)],
        Path(MARKER),
        {MARKER.encode()},
    ],
)
def test_rejected_values_do_not_echo(value: object) -> None:
    with pytest.raises(ArtefactSerialisationError) as error:
        encode_artefact(value)
    assert MARKER not in str(error.value)


@pytest.mark.parametrize("value", [Salt(), [Salt()], (FileRecord(path="a", size=1), Salt())])
def test_never_persist_marker(value: object) -> None:
    with pytest.raises(ArtefactForbiddenError):
        encode_artefact(value)


def test_type_and_shape_mismatches() -> None:
    encoded = encode_artefact(FileRecord(path="a", size=1))
    with pytest.raises(ArtefactTypeError, match="requested"):
        decode_model("files", encoded, Other)
    with pytest.raises(ArtefactTypeError, match="not a list"):
        decode_list("files", encoded, FileRecord)
    listed = encode_artefact([FileRecord(path="a", size=1)])
    with pytest.raises(ArtefactTypeError, match="not a model"):
        decode_model("files", listed, FileRecord)
    with pytest.raises(ArtefactTypeError):
        decode_list("files", listed, Other)


def test_corrupt_data_does_not_echo() -> None:
    envelope = {"ck_artefact": 1, "shape": "model", "type": type_tag(FileRecord),
                "data": {"path": MARKER, "size": MARKER}}  # fmt: skip
    raw = json.dumps(envelope).encode()
    bad = EncodedArtefact("model", type_tag(FileRecord), raw, hashlib.sha256(raw).hexdigest())
    with pytest.raises(ArtefactCorruptError) as error:
        decode_model("files", bad, FileRecord)
    assert MARKER not in str(error.value)
    garbage = EncodedArtefact("json", "", b"\xff not json", "0" * 64)
    with pytest.raises(ArtefactCorruptError):
        decode_json("files", garbage)
    wrong_version = EncodedArtefact("json", "", b'{"ck_artefact":2,"data":1}', "0" * 64)
    with pytest.raises(ArtefactCorruptError):
        decode_json("files", wrong_version)


def test_parts_digest_is_order_independent() -> None:
    parts = [("analyse-taint", "b" * 64), ("analyse-rules", "a" * 64)]
    expected = hashlib.sha256(
        f"analyse-rules:{'a' * 64}\nanalyse-taint:{'b' * 64}".encode()
    ).hexdigest()
    assert parts_digest(parts) == parts_digest(list(reversed(parts))) == expected


def test_no_executable_deserialisation() -> None:
    source = Path(__file__).resolve().parents[4] / "src" / "codekavach" / "core" / "store"
    for module in source.rglob("*.py"):
        text = module.read_text(encoding="utf-8")
        for word in ("pickle", "marshal", "shelve"):
            assert word not in text, module
