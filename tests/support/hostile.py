"""Builders for the hostile archives and repositories of the ingest tests (E06-03).

Nothing here is committed as a binary: every archive is built at test time into ``tmp_path`` so
that no secret scanner, virus scanner or checkout ever meets a decompression bomb on disk in the
repository. The cases follow ``tests/fixtures/hostile/README.md``.
"""

import io
import os
import subprocess
import tarfile
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

CHUNK = 1024 * 1024


class Zeros(io.RawIOBase):
    """A readable stream of ``size`` zero bytes that is never held in memory."""

    def __init__(self, size: int) -> None:
        self._left = size

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        count = self._left if size < 0 else min(size, self._left)
        self._left -= count
        return bytes(count)

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        count = min(len(buffer), self._left)
        buffer[:count] = bytes(count)
        self._left -= count
        return count


def zip_of(path: Path, files: Mapping[str, bytes | str]) -> Path:
    """A zip of ``files`` (name to content), deflated."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
    return path


def tar_of(path: Path, files: Mapping[str, bytes | str], mode: str = "w") -> Path:
    """A tar of ``files`` (name to content), compressed as ``mode`` says (``w``, ``w:gz`` ...)."""
    with tarfile.open(path, mode) as bundle:  # type: ignore[call-overload]
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
    return path


def tar_with_members(path: Path, members: Iterable[tarfile.TarInfo], mode: str = "w") -> Path:
    """A tar of the given members; regular files get empty content of their declared size."""
    with tarfile.open(path, mode) as bundle:  # type: ignore[call-overload]
        for info in members:
            if info.isreg():
                bundle.addfile(info, io.BytesIO(bytes(info.size)))
            else:
                bundle.addfile(info)
    return path


def member(
    name: str, kind: bytes = tarfile.REGTYPE, *, size: int = 0, link: str = ""
) -> tarfile.TarInfo:
    """A tar member of the given type."""
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = size if kind == tarfile.REGTYPE else 0
    info.linkname = link
    return info


def zip_bomb(path: Path, *, uncompressed: int = 64 * CHUNK) -> Path:
    """A zip whose one entry inflates ``uncompressed`` bytes from a few dozen kilobytes."""
    with (
        zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle,
        bundle.open("zeros.txt", "w", force_zip64=True) as entry,
    ):
        remaining = uncompressed
        block = bytes(CHUNK)
        while remaining > 0:
            step = min(remaining, CHUNK)
            entry.write(block[:step])
            remaining -= step
    return path


def tar_gz_bomb(path: Path, *, uncompressed: int = 64 * CHUNK) -> Path:
    """A gzip-compressed tar with one entry of ``uncompressed`` zero bytes."""
    info = tarfile.TarInfo("zeros.txt")
    info.size = uncompressed
    with tarfile.open(path, "w:gz", compresslevel=9) as bundle:
        bundle.addfile(info, Zeros(uncompressed))
    return path


def zip_with_symlink(path: Path, name: str, target: str) -> Path:
    """A zip holding one symbolic-link entry ``name`` -> ``target`` (as a Unix mode)."""
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr(info, target)
    return path


def many_entries_tar(path: Path, count: int) -> Path:
    """A tar of ``count`` empty files."""
    with tarfile.open(path, "w") as bundle:
        for index in range(count):
            bundle.addfile(tarfile.TarInfo(f"d/f{index}.txt"))
    return path


def tree_size(root: Path) -> int:
    """Total size in bytes of every file below ``root``."""
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def all_files(root: Path) -> list[str]:
    """Posix paths (relative to ``root``) of every file below it, sorted."""
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


# --- git fixtures -------------------------------------------------------------------------------

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(cwd: Path, *arguments: str) -> str:
    """Run a trusted git command in a test repository and return its standard output."""
    completed = subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", *arguments],  # noqa: S607
        cwd=cwd,
        env={**os.environ, **GIT_ENV},
        capture_output=True,
        check=True,
        text=True,
    )
    return completed.stdout.strip()


def make_repo(root: Path, files: dict[str, str]) -> Path:
    """A repository at ``root`` with one commit of ``files``; returns the root."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q")
    return commit_files(root, files, "initial")


def commit_files(root: Path, files: dict[str, str], message: str) -> Path:
    """Write ``files`` into the repository and commit them."""
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return root


def add_gitlink(root: Path, path: str, url: str) -> None:
    """Record a submodule at ``path`` pointing at ``url`` without fetching anything."""
    (root / ".gitmodules").write_text(f'[submodule "{path}"]\n\tpath = {path}\n\turl = {url}\n')
    git(
        root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{git(root, 'rev-parse', 'HEAD')},{path}",
    )
    git(root, "add", ".gitmodules")
    git(root, "commit", "-q", "-m", "add submodule")


def has_git() -> bool:
    """Whether a usable ``git`` is on the path."""
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)  # noqa: S607
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def names_of(paths: Sequence[Path]) -> list[str]:
    """File names of ``paths``, sorted."""
    return sorted(p.name for p in paths)
