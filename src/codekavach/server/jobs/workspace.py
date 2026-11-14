"""Safe intake of untrusted project sources into a scan workspace.

Owning epic: E32.

Three routes bring code into ``<workspace>/src``: a copy of a local directory (or the bundled
sample), the extraction of an uploaded zip or tar archive, and a shallow ``git clone`` of an
allow-listed https URL. The archive route rejects, each with its own error code, an entry that
escapes the extraction root (``../`` or an absolute name), a symbolic or hard link, a device or
FIFO, too many entries, too many extracted bytes and a compression ratio that marks a
decompression bomb. The clone route refuses credentials in the URL, plain http, hosts outside the
allow-list and hosts that resolve to loopback, private, link-local or reserved addresses, and runs
git without submodules, hooks, symlinks or interactive prompts.
"""

import ipaddress
import os
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import urlsplit

COPY_IGNORE: Final = (".git", ".codekavach", "node_modules", ".venv", "__pycache__", "ground-truth")
SAMPLE_IGNORE: Final = (*COPY_IGNORE, "cassettes")
GIT_TIMEOUT_SECONDS: Final = 300
ARCHIVE_SUFFIXES: Final = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz")
MAX_COPY_BYTES: Final = 1024 * 1024 * 1024


class IntakeError(Exception):
    """The source was refused; ``code`` says why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ArchiveLimits:
    """Bounds of one archive extraction."""

    max_entries: int = 50_000
    max_bytes: int = 1024 * 1024 * 1024
    max_ratio: int = 200
    max_depth: int = 64


def _ignore(names: Iterable[str]) -> Callable[[str, list[str]], set[str]]:
    blocked = set(names)

    def ignore(_directory: str, entries: list[str]) -> set[str]:
        return {entry for entry in entries if entry in blocked}

    return ignore


def copy_tree(source: Path, destination: Path, *, ignore: Iterable[str] = COPY_IGNORE) -> Path:
    """Copy ``source`` into ``destination`` without VCS metadata, dependencies or symlinks."""
    if not source.is_dir():
        raise IntakeError("source_not_found", f"the source directory does not exist: {source}")
    shutil.copytree(source, destination, ignore=_ignore(ignore), symlinks=True)
    total = 0
    for path in destination.rglob("*"):
        if path.is_symlink():
            path.unlink()
        elif path.is_file():
            total += path.stat().st_size
            if total > MAX_COPY_BYTES:
                raise IntakeError("source_too_large", "the source is larger than 1 GiB")
    return destination


def _safe_name(name: str, depth_limit: int) -> PurePosixPath:
    normalised = name.replace("\\", "/")
    path = PurePosixPath(normalised)
    if normalised.startswith("/") or path.is_absolute() or (path.parts and ":" in path.parts[0]):
        raise IntakeError("archive_absolute_path", f"archive entry has an absolute path: {name}")
    if any(part == ".." for part in path.parts):
        raise IntakeError("archive_path_traversal", f"archive entry escapes the root: {name}")
    if len(path.parts) > depth_limit:
        raise IntakeError("archive_too_deep", f"archive entry is nested too deeply: {name}")
    return path


def _inside(root: Path, relative: PurePosixPath) -> Path:
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise IntakeError("archive_path_traversal", f"archive entry escapes the root: {relative}")
    return target


def _write(handle: object, target: Path, budget: list[int], limits: ArchiveLimits) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    reader = handle
    with target.open("wb") as out:
        while True:
            chunk = reader.read(1024 * 1024)  # type: ignore[attr-defined]
            if not chunk:
                break
            budget[0] += len(chunk)
            if budget[0] > limits.max_bytes:
                raise IntakeError("archive_too_large", "the archive expands beyond the size limit")
            out.write(chunk)


def _check_ratio(compressed: int, expanded: int, limits: ArchiveLimits) -> None:
    if expanded > 1024 * 1024 and expanded > max(compressed, 1) * limits.max_ratio:
        raise IntakeError(
            "archive_compression_ratio",
            "the archive's compression ratio marks it as a decompression bomb",
        )


def _extract_zip(archive: Path, root: Path, limits: ArchiveLimits) -> None:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > limits.max_entries:
            raise IntakeError("archive_too_many_entries", "the archive has too many entries")
        declared = sum(member.file_size for member in members)
        if declared > limits.max_bytes:
            raise IntakeError("archive_too_large", "the archive expands beyond the size limit")
        _check_ratio(archive.stat().st_size, declared, limits)
        budget = [0]
        for member in members:
            relative = _safe_name(member.filename, limits.max_depth)
            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise IntakeError("archive_link", f"archive entry is a link: {member.filename}")
            target = _inside(root, relative)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            with bundle.open(member) as handle:
                _write(handle, target, budget, limits)


def _extract_tar(archive: Path, root: Path, limits: ArchiveLimits) -> None:
    with tarfile.open(archive) as bundle:
        budget = [0]
        count = 0
        for member in bundle:
            count += 1
            if count > limits.max_entries:
                raise IntakeError("archive_too_many_entries", "the archive has too many entries")
            relative = _safe_name(member.name, limits.max_depth)
            if member.issym() or member.islnk():
                raise IntakeError("archive_link", f"archive entry is a link: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise IntakeError(
                    "archive_special_file", f"archive entry is special: {member.name}"
                )
            target = _inside(root, relative)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            _check_ratio(archive.stat().st_size, budget[0] + member.size, limits)
            handle = bundle.extractfile(member)
            if handle is None:
                continue
            with handle:
                _write(handle, target, budget, limits)


def extract_archive(archive: Path, destination: Path, limits: ArchiveLimits | None = None) -> Path:
    """Extract ``archive`` (zip or tar, optionally compressed) into ``destination`` safely.

    A single top-level directory is unwrapped, so ``project.zip`` holding ``project/...`` scans
    as the project itself. On refusal the partial output is removed.

    Raises:
        IntakeError: with one of the ``archive_*`` codes.
    """
    limits = limits or ArchiveLimits()
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    try:
        if zipfile.is_zipfile(archive):
            _extract_zip(archive, root, limits)
        elif tarfile.is_tarfile(archive):
            _extract_tar(archive, root, limits)
        else:
            raise IntakeError("archive_unsupported", "the upload is not a zip or tar archive")
    except IntakeError:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError) as error:
        shutil.rmtree(destination, ignore_errors=True)
        raise IntakeError(
            "archive_corrupt", f"the archive cannot be read: {type(error).__name__}"
        ) from None
    if not any(item.is_file() for item in destination.rglob("*")):
        shutil.rmtree(destination, ignore_errors=True)
        raise IntakeError("archive_empty", "the archive holds no files; there is nothing to scan")
    entries = [entry for entry in destination.iterdir() if entry.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        staging = destination.with_name(destination.name + ".unwrap")
        inner.rename(staging)
        shutil.rmtree(destination)
        staging.rename(destination)
    return destination


def _blocked_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


Resolver = Callable[[str], list[str]]


def _system_resolver(host: str) -> list[str]:
    """The addresses of ``host`` from ``getent ahosts`` (no socket is opened in this process)."""
    getent = shutil.which("getent")
    if getent is None:
        raise OSError("getent is not available")
    try:
        result = subprocess.run(
            [getent, "ahosts", host], check=True, capture_output=True, text=True, timeout=10
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise OSError("name resolution failed") from error
    return sorted({line.split()[0] for line in result.stdout.splitlines() if line.strip()})


def assert_safe_clone_url(
    url: str, allowed_hosts: Iterable[str], resolver: Resolver | None = None
) -> str:
    """``url`` when it may be cloned; ``IntakeError`` otherwise.

    Rules: https only, no user information, host on the allow-list, every resolved address
    public. A host given as an IP literal (decimal, octal or mapped forms included) is judged by
    its address and must also be listed.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        raise IntakeError("git_url_invalid", "the git URL cannot be parsed") from None
    if parts.scheme != "https":
        raise IntakeError("git_url_scheme", "only https git URLs are accepted")
    if parts.username or parts.password or "@" in parts.netloc:
        raise IntakeError("git_url_credentials", "the git URL must not carry credentials")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise IntakeError("git_url_invalid", "the git URL has no host")
    allowed = {item.lower() for item in allowed_hosts}
    if host not in allowed:
        raise IntakeError("git_host_not_allowed", f"the git host {host} is not on the allow-list")
    try:
        addresses = (resolver or _system_resolver)(host)
    except OSError:
        raise IntakeError(
            "git_host_unresolvable", f"the git host {host} cannot be resolved"
        ) from None
    for address in addresses:
        try:
            if _blocked_address(address):
                raise IntakeError(
                    "git_host_private", f"the git host {host} resolves to a non-public address"
                )
        except ValueError:
            raise IntakeError("git_host_unresolvable", "the git host resolved to junk") from None
    return url


def _git_reason(stderr: bytes | str | None) -> str:
    """Git's own ``fatal:`` line, without a URL (which could carry a token), cut to 160 chars."""
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else stderr or ""
    for line in text.splitlines():
        if line.startswith("fatal:") and "could not read Username" in line:
            return "the repository is private or does not exist (no credentials are sent)"
        if line.startswith("fatal:"):
            reason = re.sub(r"\s*(?:'[^']*'|\S+://\S+)", "", line[6:].strip())
            return reason[:160]
    return ""


def clone_git(url: str, destination: Path, *, ref: str | None = None) -> Path:
    """Shallow-clone ``url`` (already checked) into ``destination`` with hardened options."""
    git = shutil.which("git")
    if git is None:
        raise IntakeError("git_unavailable", "git is not installed on the server")
    command = [
        git,
        "-c", "core.symlinks=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "http.followRedirects=false",
        "-c", "submodule.recurse=false",
        "clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules",
    ]  # fmt: skip
    if ref:
        if ref.startswith("-") or any(char.isspace() for char in ref):
            raise IntakeError("git_ref_invalid", "the git ref is not valid")
        command += ["--branch", ref]
    command += ["--", url, str(destination)]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(destination.parent),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ASKPASS": "/bin/false",
    }
    try:
        subprocess.run(
            command, check=True, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, env=env
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(destination, ignore_errors=True)
        raise IntakeError("git_timeout", "the git clone took too long") from None
    except subprocess.CalledProcessError as error:
        shutil.rmtree(destination, ignore_errors=True)
        reason = _git_reason(error.stderr)
        message = f"the git clone failed: {reason}" if reason else "the git clone failed"
        raise IntakeError("git_clone_failed", message) from None
    shutil.rmtree(destination / ".git", ignore_errors=True)
    for path in destination.rglob("*"):
        if path.is_symlink():
            path.unlink()
    return destination
