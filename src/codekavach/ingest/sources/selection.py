"""``select_source``: pick the source for a scan target (E06-02, E06-03).

Owning epic: E06.

The order is fixed and never touches the network to decide:

1. the literal ``-`` is standard input (:class:`StdinSource`);
2. an existing path: an archive file (by extension) is an :class:`ArchiveSource`, a bare
   repository directory (``*.git`` holding ``HEAD`` and ``objects``) is cloned by
   :class:`GitSource`, anything else is a :class:`LocalPathSource`;
3. a target that is not on the disk and looks like a git URL (``https://``, ``ssh://``,
   ``git@host:path``, ``file://`` or ``*.git``) is a :class:`GitSource`;
4. anything else is refused with :class:`UnsupportedSource`, whose message never repeats the
   target (a URL may carry a token or name the client).
"""

from pathlib import Path

from codekavach.ingest.options import IngestOptions
from codekavach.ingest.sources.archive import ArchiveSource, is_archive_name
from codekavach.ingest.sources.base import Source, UnsupportedSource
from codekavach.ingest.sources.git import GitSource, looks_like_git_target
from codekavach.ingest.sources.local import LocalPathSource
from codekavach.ingest.sources.stdin import STDIN_TARGET, StdinSource


def _git(options: IngestOptions) -> GitSource:
    return GitSource(
        ref=options.ref,
        depth=options.depth,
        credential=options.git_credential,
        fetch_base=options.diff_since,
    )


def _is_bare_repository(path: Path) -> bool:
    return path.name.endswith(".git") and (path / "HEAD").is_file() and (path / "objects").is_dir()


def select_source(target: str, options: IngestOptions | None = None) -> Source:
    """The source that can serve ``target``.

    Raises:
        UnsupportedSource: ``target`` is not standard input, an existing path, an archive or a
            git URL; or an option of the chosen source is not acceptable.
    """
    chosen = options or IngestOptions()
    if target == STDIN_TARGET:
        return StdinSource(filename=chosen.stdin_filename)
    try:
        # An empty string is Path("."): the working directory must never be scanned by accident.
        path = Path(target) if target else None
        exists = path is not None and path.exists()
    except (OSError, ValueError):
        path, exists = None, False
    if exists and path is not None:
        if path.is_file() and is_archive_name(path.name):
            return ArchiveSource()
        if path.is_dir() and _is_bare_repository(path):
            return _git(chosen)
        return LocalPathSource()
    if looks_like_git_target(target):
        return _git(chosen)
    raise UnsupportedSource(
        "the target is not an existing local directory, file or archive, a git URL, or '-'"
    )
