"""``select_source``: pick the source for a scan target (E06-02).

Owning epic: E06.

Only the local source exists here. Anything that is not an existing directory or file, a git URL
included, raises ``UnsupportedSource`` without any network access, so E06-03 can register the
remaining sources by extending this function and nothing else.
"""

from pathlib import Path

from codekavach.ingest.sources.base import Source, UnsupportedSource
from codekavach.ingest.sources.local import LocalPathSource


def select_source(target: str) -> Source:
    """The source that can serve ``target``.

    Raises:
        UnsupportedSource: ``target`` is not an existing local directory or file; git, archive and
            stdin targets are added by E06-03.
    """
    try:
        # An empty string is Path("."): the working directory must never be scanned by accident.
        exists = bool(target) and Path(target).exists()
    except (OSError, ValueError):
        exists = False
    if exists:
        return LocalPathSource()
    raise UnsupportedSource(
        "the target is not an existing local directory or file; "
        "git, archive and stdin sources are added by E06-03"
    )
