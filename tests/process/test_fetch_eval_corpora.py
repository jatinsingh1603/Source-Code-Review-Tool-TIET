"""``tools/fetch_eval_corpora.py``: pins are required and checked before anything is written."""

import hashlib
import importlib.util
import io
import sys
import tarfile
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
PIN_FILE = REPO / "tools" / "eval_corpora.toml"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "fetch_eval_corpora", REPO / "tools/fetch_eval_corpora.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["fetch_eval_corpora"] = module
    spec.loader.exec_module(module)
    return module


tool = _load()
COMMIT = "a" * 40


def archive(member: str = "repo-1/readme.txt") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"hello"
        info = tarfile.TarInfo(member)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def pins(digest: str, commit: str = COMMIT) -> str:
    return f'[corpus.demo]\nrepository = "owner/name"\ncommit = "{commit}"\nsha256 = "{digest}"\n'


def test_the_shipped_pins_are_unfilled_so_nothing_can_be_fetched_by_accident() -> None:
    text = PIN_FILE.read_text(encoding="utf-8")
    names = tomllib.loads(text)["corpus"]
    assert names
    for name in names:
        with pytest.raises(tool.PinError):
            tool.read_pin(name, text)


def test_a_matching_checksum_extracts_and_asks_for_the_pinned_commit(tmp_path: Path) -> None:
    body = archive()
    asked: list[str] = []

    def opener(url: str) -> bytes:
        asked.append(url)
        return body

    target = tool.fetch(
        "demo", tmp_path, pins=pins(hashlib.sha256(body).hexdigest()), opener=opener
    )
    assert asked == [f"repos/owner/name/tarball/{COMMIT}"]
    assert (target / "repo-1" / "readme.txt").read_bytes() == b"hello"


def test_a_checksum_mismatch_writes_nothing(tmp_path: Path) -> None:
    with pytest.raises(tool.PinError, match="checksum mismatch"):
        tool.fetch("demo", tmp_path, pins=pins("0" * 64), opener=lambda url: archive())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("commit", ["", "main", "abc", "G" * 40])
def test_an_unpinned_or_malformed_commit_is_refused_before_any_download(commit: str) -> None:
    def never(url: str) -> bytes:
        raise AssertionError("downloaded")

    with pytest.raises(tool.PinError):
        tool.fetch("demo", Path(), pins=pins("0" * 64, commit), opener=never)


def test_an_unknown_corpus_is_refused() -> None:
    with pytest.raises(tool.PinError, match="no corpus named"):
        tool.read_pin("nope", pins("0" * 64))


def test_a_member_that_escapes_the_destination_is_refused(tmp_path: Path) -> None:
    body = archive("../escape.txt")
    digest = hashlib.sha256(body).hexdigest()
    with pytest.raises(tarfile.TarError):
        tool.fetch("demo", tmp_path / "d", pins=pins(digest), opener=lambda url: body)
    assert not (tmp_path / "escape.txt").exists()
