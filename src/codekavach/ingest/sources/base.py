"""The ``Source`` protocol and the error for a target no source can handle (E06-02).

Owning epic: E06.

A source turns the scan target into a directory discovery can walk. ``materialise`` receives the
safety limits and a scratch directory it may fill (``into``), and returns the directory to walk,
which is ``into`` or, for a source that needs no copy, the target itself. Keeping this seam fixed
lets E06-03 add git, archive and stdin sources without touching ``IngestStage``.
"""

from pathlib import Path
from typing import Protocol

from codekavach.ingest.limits import IngestLimits


class UnsupportedSource(ValueError):  # noqa: N818 - the name is fixed by the M1 interface contract
    """No available source can handle the target.

    The message never repeats the target: a URL may carry a token or name the client.
    """


class Source(Protocol):
    """Makes a scan target available as a local directory."""

    def materialise(self, target: str, *, limits: IngestLimits, into: Path) -> Path:
        """Return the directory to walk for ``target``, using ``into`` as scratch space.

        Raises:
            LimitExceededError: the target breaks one of ``limits``.
            UnsupportedSource: this source cannot handle ``target``.
        """
        ...
