"""The ``Source`` protocol and the error for a target no source can handle (E06-02).

Owning epic: E06.

A source turns the scan target into a directory discovery can walk. ``materialise`` receives the
safety limits and a scratch directory it may fill (``into``), and returns the directory to walk,
which is ``into`` or, for a source that needs no copy, the target itself. Keeping this seam fixed
lets E06-03 add git, archive and stdin sources without touching ``IngestStage``.
"""

from pathlib import Path
from typing import ClassVar, Protocol

from codekavach.ingest.limits import IngestLimits


class UnsupportedSource(ValueError):  # noqa: N818 - the name is fixed by the M1 interface contract
    """No available source can handle the target.

    The message never repeats the target: a URL may carry a token or name the client.
    """


class UnsafeArchiveEntry(ValueError):  # noqa: N818 - named for what it rejects, like UnsupportedSource
    """An archive entry breaks a safety rule (a path that escapes, a link, a device member).

    ``reason`` is a short rule name; the message never repeats the entry name, which the author of
    the archive chose and which may reach a log.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"unsafe archive entry ({reason})")


class Source(Protocol):
    """Makes a scan target available as a local directory.

    ``owns_root`` is true when ``materialise`` fills ``into`` with a copy that later stages must
    read from (a clone, an extracted archive, standard input) and false when it returns the
    target itself.
    """

    owns_root: ClassVar[bool]

    def materialise(self, target: str, *, limits: IngestLimits, into: Path) -> Path:
        """Return the directory to walk for ``target``, using ``into`` as scratch space.

        Raises:
            LimitExceededError: the target breaks one of ``limits``.
            UnsupportedSource: this source cannot handle ``target``.
        """
        ...
