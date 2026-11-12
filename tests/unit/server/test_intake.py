"""Safe intake: hostile archives and git URLs are refused with distinct codes."""

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from codekavach.server.jobs.workspace import (
    ArchiveLimits,
    IntakeError,
    assert_safe_clone_url,
    extract_archive,
)

pytest.importorskip("fastapi")


def _zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data in entries.items():
            bundle.writestr(name, data)
    return path


def _symlink_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as bundle:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        bundle.writestr(info, "/etc/passwd")
    return path


def _symlink_tar(path: Path) -> Path:
    with tarfile.open(path, "w:gz") as bundle:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        bundle.addfile(info)
    return path


def test_a_normal_archive_is_extracted_and_unwrapped(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "a.zip", {"proj/app.py": b"print(1)\n", "proj/lib/x.py": b"y = 2\n"})
    root = extract_archive(archive, tmp_path / "out")
    assert (root / "app.py").read_text() == "print(1)\n"
    assert (root / "lib" / "x.py").is_file()


@pytest.mark.parametrize(
    ("build", "code"),
    [
        (lambda p: _zip(p / "s.zip", {"../../etc/passwd": b"x"}), "archive_path_traversal"),
        (lambda p: _zip(p / "a.zip", {"/abs/path": b"x"}), "archive_absolute_path"),
        (lambda p: _zip(p / "b.zip", {"bomb.txt": b"0" * 20_000_000}), "archive_compression_ratio"),
        (lambda p: _symlink_zip(p / "l.zip"), "archive_link"),
        (lambda p: _symlink_tar(p / "l.tgz"), "archive_link"),
        (
            lambda p: _zip(p / "f.zip", {f"f{i}.txt": b"" for i in range(60)}),
            "archive_too_many_entries",
        ),
        (lambda p: _zip(p / "d.zip", {"/".join(["d"] * 80) + "/x": b"x"}), "archive_too_deep"),
    ],
)
def test_hostile_archives_are_refused(tmp_path: Path, build: object, code: str) -> None:
    archive = build(tmp_path)  # type: ignore[operator]
    out = tmp_path / "out"
    with pytest.raises(IntakeError) as caught:
        extract_archive(archive, out, ArchiveLimits(max_entries=50, max_ratio=100))
    assert caught.value.code == code
    assert not out.exists()
    assert not (tmp_path.parent / "etc").exists()


def test_a_non_archive_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "x.zip"
    path.write_bytes(b"not an archive")
    with pytest.raises(IntakeError) as caught:
        extract_archive(path, tmp_path / "out")
    assert caught.value.code == "archive_unsupported"


def test_a_tar_with_traversal_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "t.tar"
    with tarfile.open(path, "w") as bundle:
        data = b"x"
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))
    with pytest.raises(IntakeError) as caught:
        extract_archive(path, tmp_path / "out")
    assert caught.value.code == "archive_path_traversal"


def _resolver(*addresses: str):  # type: ignore[no-untyped-def]
    return lambda _host: list(addresses)


ALLOWED = ("github.com",)


@pytest.mark.parametrize(
    ("url", "addresses", "code"),
    [
        ("http://github.com/a/b.git", ("140.82.112.3",), "git_url_scheme"),
        ("git@github.com:a/b.git", ("140.82.112.3",), "git_url_scheme"),
        ("https://user:pw@github.com/a/b.git", ("140.82.112.3",), "git_url_credentials"),
        ("https://evil.example/a/b.git", ("140.82.112.3",), "git_host_not_allowed"),
        ("https://github.com/a/b.git", ("127.0.0.1",), "git_host_private"),
        ("https://github.com/a/b.git", ("10.0.0.5",), "git_host_private"),
        ("https://github.com/a/b.git", ("169.254.169.254",), "git_host_private"),
        ("https://github.com/a/b.git", ("::ffff:127.0.0.1",), "git_host_private"),
        ("https://github.com/a/b.git", ("fd00::1",), "git_host_private"),
    ],
)
def test_unsafe_clone_urls_are_refused(url: str, addresses: tuple[str, ...], code: str) -> None:
    with pytest.raises(IntakeError) as caught:
        assert_safe_clone_url(url, ALLOWED, _resolver(*addresses))
    assert caught.value.code == code


def test_a_public_allow_listed_url_passes() -> None:
    url = "https://github.com/OWASP/NodeGoat.git"
    assert assert_safe_clone_url(url, ALLOWED, _resolver("140.82.112.3")) == url
