"""Sub-project detection and selection for monorepos (E06-03).

Owning epic: E06.

A sub-project is a directory that holds a build manifest. Detection is by manifest file name only
(this module reads no manifest content; dependency data is E19): ``pyproject.toml`` and
``setup.py`` (python), ``package.json`` (node), ``pom.xml`` (java-maven), ``build.gradle`` and
``build.gradle.kts`` (java-gradle), ``go.mod`` (go), ``composer.json`` (php), ``*.csproj``
(dotnet), ``Gemfile`` (ruby). A directory with several manifests is one sub-project, of the kind
of the first manifest in that order. Vendored files are ignored, so the thousands of
``package.json`` files under ``node_modules`` are not sub-projects.

``subproject_of`` gives the *nearest* enclosing sub-project of a path. ``select_subprojects``
keeps the files under the requested directories and refuses a request that matches nothing, so a
typo cannot produce an empty, reassuring scan.
"""

import posixpath
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.core.models import RepoPath
from codekavach.ingest.models import SourceFile

# Order matters: the first manifest found in a directory decides its kind.
_MANIFESTS: Final[tuple[tuple[str, str], ...]] = (
    ("pyproject.toml", "python"),
    ("setup.py", "python"),
    ("package.json", "node"),
    ("pom.xml", "java-maven"),
    ("build.gradle", "java-gradle"),
    ("build.gradle.kts", "java-gradle"),
    ("go.mod", "go"),
    ("composer.json", "php"),
    ("Gemfile", "ruby"),
)
_CSPROJ: Final = ".csproj"


class SubprojectSelectionError(ValueError):
    """A requested sub-project path is malformed or matches no file."""


@dataclass(frozen=True, slots=True)
class SubProject:
    """One detected sub-project: its directory (``.`` for the root), kind and manifest path."""

    path: RepoPath
    kind: str
    manifest: RepoPath


def _kind_of(name: str) -> str | None:
    for manifest, kind in _MANIFESTS:
        if name == manifest:
            return kind
    return "dotnet" if name.endswith(_CSPROJ) and len(name) > len(_CSPROJ) else None


def _priority(name: str) -> int:
    for index, (manifest, _) in enumerate(_MANIFESTS):
        if name == manifest:
            return index
    return len(_MANIFESTS)


def detect_subprojects(
    root: Path,
    files: Iterable[SourceFile],
) -> tuple[SubProject, ...]:
    """The sub-projects among ``files`` (found under ``root``), sorted by directory.

    Only files that discovery accepted can be manifests, so a manifest over the size limit or a
    vendored one is not seen.
    """
    best: dict[str, tuple[int, str, str]] = {}
    for file in files:
        if file.is_vendored:
            continue
        directory, name = posixpath.split(file.path)
        kind = _kind_of(name)
        if kind is None:
            continue
        key = directory or "."
        rank = _priority(name)
        if key not in best or rank < best[key][0]:
            best[key] = (rank, kind, file.path)
    return tuple(
        SubProject(path=directory, kind=kind, manifest=manifest)
        for directory, (_, kind, manifest) in sorted(best.items())
    )


def subproject_of(path: RepoPath, subprojects: Sequence[SubProject]) -> SubProject | None:
    """The nearest sub-project whose directory contains ``path``, or ``None``."""
    chosen: SubProject | None = None
    for subproject in subprojects:
        root = subproject.path
        inside = root in {".", path} or path.startswith(root + "/")
        if inside and (chosen is None or _depth(root) > _depth(chosen.path)):
            chosen = subproject
    return chosen


def _depth(directory: str) -> int:
    return 0 if directory == "." else directory.count("/") + 1


def normalise_selection(raw: str) -> str:
    """A requested path as a repository-relative POSIX directory (``.`` for the root).

    Raises:
        SubprojectSelectionError: the path is absolute, has a ``..`` segment, a backslash or a NUL.
    """
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/"):
        raise SubprojectSelectionError("a --subproject path must be relative to the scan root")
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    if ".." in parts:
        raise SubprojectSelectionError("a --subproject path must not contain '..'")
    return "/".join(parts) or "."


def select_subprojects(files: Sequence[SourceFile], requested: Sequence[str]) -> list[SourceFile]:
    """The files under any requested directory.

    Raises:
        SubprojectSelectionError: a request is malformed or no file lies under it.
    """
    wanted = [normalise_selection(item) for item in requested]
    kept: list[SourceFile] = []
    matched: set[str] = set()
    for file in files:
        hits = [w for w in wanted if w in {".", file.path} or file.path.startswith(w + "/")]
        if hits:
            kept.append(file)
            matched.update(hits)
    if set(wanted) - matched:
        raise SubprojectSelectionError("a --subproject path matches no scanned file")
    return kept
