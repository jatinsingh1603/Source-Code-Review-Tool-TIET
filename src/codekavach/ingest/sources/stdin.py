"""``StdinSource``: one file read from standard input (E06-03).

Owning epic: E06.

The input is written to a single file named by ``--stdin-filename``, so the language can be
detected from its extension; there is no guessing from content. The name is a bare file name: a
path separator, a ``..``, a NUL, a drive-letter colon or an empty name is refused, so the file can
only land directly inside the working root. At most ``ingest.max_file_size_bytes`` are read; one
byte more is an error, and nothing is written.
"""

import sys
from pathlib import Path
from typing import IO, ClassVar, Final

from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources.base import UnsupportedSource
from codekavach.ingest.sources.workdir import private_directory

STDIN_TARGET: Final = "-"
MAX_NAME_LENGTH: Final = 255
_FORBIDDEN: Final = ("/", "\\", "\x00", ":")


def check_stdin_filename(name: str | None) -> str:
    """The validated bare file name for standard input.

    Raises:
        UnsupportedSource: the name is missing, or is not a bare file name.
    """
    if not name:
        raise UnsupportedSource("reading standard input needs --stdin-filename")
    if (
        any(mark in name for mark in _FORBIDDEN)
        or name == "."
        or ".." in name
        or len(name) > MAX_NAME_LENGTH
        or name != name.strip()
    ):
        raise UnsupportedSource("--stdin-filename must be a bare file name")
    return name


class StdinSource:
    """Serves the bytes of standard input as one file."""

    owns_root: ClassVar[bool] = True

    def __init__(self, *, filename: str | None, stream: IO[bytes] | None = None) -> None:
        self._filename = filename
        self._stream = stream

    def materialise(self, target: str, *, limits: IngestLimits, into: Path) -> Path:
        """Write standard input to ``into/<filename>`` and return ``into``."""
        if target != STDIN_TARGET:
            raise UnsupportedSource("standard input is selected with the target '-'")
        name = check_stdin_filename(self._filename)
        stream = self._stream if self._stream is not None else sys.stdin.buffer
        data = stream.read(limits.max_file_size_bytes + 1)
        if len(data) > limits.max_file_size_bytes:
            raise LimitExceededError(LimitKind.FILE_SIZE, limits.max_file_size_bytes)
        private_directory(into)
        (into / name).write_bytes(data)
        return into
