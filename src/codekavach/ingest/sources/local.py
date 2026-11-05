"""``LocalPathSource``: a directory or a single file on the local disk (E06-02).

Owning epic: E06.

A directory is walked in place; nothing is copied. A single file is copied into the scratch
directory so that discovery, which walks a directory, treats it like any other tree and the
original is never touched. The copy is refused above ``ingest.max_file_size_bytes`` before any
byte is read.
"""

import shutil
from pathlib import Path

from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources.base import UnsupportedSource


class LocalPathSource:
    """Serves an existing directory or file path."""

    def materialise(self, target: str, *, limits: IngestLimits, into: Path) -> Path:
        """Return ``target`` itself when it is a directory, else ``into`` holding a copy of it."""
        try:
            path = Path(target)
            if path.is_dir():
                return path
            if not path.is_file():
                raise UnsupportedSource("the target is not an existing directory or file")
            if path.stat().st_size > limits.max_file_size_bytes:
                raise LimitExceededError(LimitKind.FILE_SIZE, limits.max_file_size_bytes)
            into.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, into / path.name)
        except (OSError, ValueError) as error:
            if isinstance(error, UnsupportedSource):
                raise
            raise UnsupportedSource("the target cannot be read as a local path") from None
        return into
