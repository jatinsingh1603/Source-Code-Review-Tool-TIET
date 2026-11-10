"""``Source``, ``LocalPathSource`` and ``select_source`` (E06-02)."""

import socket
from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources.base import Source, UnsupportedSource
from codekavach.ingest.sources.local import LocalPathSource
from codekavach.ingest.sources.selection import select_source


def _limits(**overrides: object) -> IngestLimits:
    return IngestLimits.from_settings(IngestSettings(**overrides))  # type: ignore[arg-type]


def test_a_directory_is_returned_in_place_without_copying(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    scratch = tmp_path.parent / f"{tmp_path.name}-scratch"
    root = LocalPathSource().materialise(str(tmp_path), limits=_limits(), into=scratch)
    assert root == tmp_path
    assert not scratch.exists()


def test_a_single_file_is_copied_into_the_scratch_directory(tmp_path: Path) -> None:
    original = tmp_path / "one.py"
    original.write_text("x = 1\n", encoding="utf-8")
    scratch = tmp_path / "scratch"
    root = LocalPathSource().materialise(str(original), limits=_limits(), into=scratch)
    assert root == scratch
    assert (scratch / "one.py").read_text(encoding="utf-8") == "x = 1\n"
    assert original.read_text(encoding="utf-8") == "x = 1\n"


def test_a_file_over_the_size_limit_is_refused_before_copying(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * 100, encoding="utf-8")
    scratch = tmp_path / "scratch"
    with pytest.raises(LimitExceededError) as raised:
        LocalPathSource().materialise(
            str(big), limits=_limits(max_file_size_bytes=10), into=scratch
        )
    assert raised.value.kind is LimitKind.FILE_SIZE
    assert not scratch.exists()


def test_a_missing_path_is_unsupported_and_the_message_hides_the_target(tmp_path: Path) -> None:
    target = str(tmp_path / "secret-client-name")
    with pytest.raises(UnsupportedSource) as raised:
        LocalPathSource().materialise(target, limits=_limits(), into=tmp_path / "s")
    assert "secret-client-name" not in str(raised.value)


def test_select_source_returns_the_local_source_for_directories_and_files(tmp_path: Path) -> None:
    file = tmp_path / "a.py"
    file.write_text("x = 1\n", encoding="utf-8")
    assert isinstance(select_source(str(tmp_path)), LocalPathSource)
    assert isinstance(select_source(str(file)), LocalPathSource)


def test_local_source_satisfies_the_source_protocol() -> None:
    source: Source = LocalPathSource()
    assert callable(source.materialise)


@pytest.mark.parametrize(
    "target",
    [
        "archive.zip.does-not-exist",
        "no-such-directory",
        "",
        "bad\x00path",
        "ftp://example.invalid/x",
    ],
)
def test_select_source_rejects_everything_else_without_network(
    target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a network call was attempted")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    with pytest.raises(UnsupportedSource) as raised:
        select_source(target)
    assert "example.invalid" not in str(raised.value)
