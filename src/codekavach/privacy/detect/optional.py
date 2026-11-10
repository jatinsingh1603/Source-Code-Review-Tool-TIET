"""Optional extras: probing for them and warning once when one is missing (E08-04).

Owning epic: E08.

Everything in E08-04 sits behind an extra and behind an ``available()`` probe, and the native
detectors never call into it. A missing extra is not an error: the capability is simply absent,
and the process says so **once**, naming what to install, so a log does not repeat the same line
for every file. :func:`warn_unavailable` keeps that memory; tests clear it with
:func:`reset_warnings`.
"""

import importlib.resources
import importlib.util
import tomllib
from dataclasses import dataclass
from typing import Final

from codekavach.core.log import get_logger

_log = get_logger("codekavach.privacy.detect")

_warned: set[str] = set()

NER_EXTRA: Final = "codekavach[pii]"
MANIFEST_FILE: Final = "optional_engines.toml"
DISTRIBUTION_MODES: Final = frozenset({"bundled", "client-installed", "evaluation-only"})
ENTRY_KINDS: Final = frozenset({"engine", "library", "model", "data", "dataset"})


def module_present(name: str) -> bool:
    """Whether the top-level module ``name`` can be found, without importing it."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def warn_unavailable(feature: str, extra: str, *, reason: str) -> bool:
    """Log one warning per ``feature`` per process; return whether this call logged it."""
    if feature in _warned:
        return False
    _warned.add(feature)
    _log.warning("optional_extra_unavailable", feature=feature, extra=extra, reason=reason)
    return True


def reset_warnings() -> None:
    """Forget which warnings were given (for tests)."""
    _warned.clear()


@dataclass(frozen=True)
class ManifestEntry:
    """One optional engine, model or dataset: its licence and how it is distributed."""

    id: str
    kind: str
    spdx: str
    distribution: str
    hosted: bool
    note: str


def parse_manifest(text: str) -> tuple[ManifestEntry, ...]:
    """The entries of a licence manifest.

    Raises:
        ValueError: an entry lacks a field, repeats an id, uses an unknown kind or distribution
            mode, or is shipped (``bundled``) while marked ``hosted = false``.
    """
    entries: list[ManifestEntry] = []
    for raw in tomllib.loads(text).get("entry", []):
        try:
            entry = ManifestEntry(
                id=str(raw["id"]),
                kind=str(raw["kind"]),
                spdx=str(raw["spdx"]),
                distribution=str(raw["distribution"]),
                hosted=raw["hosted"] is True,
                note=str(raw.get("note", "")),
            )
        except KeyError as error:
            raise ValueError(f"manifest entry lacks {error.args[0]}") from None
        if not isinstance(raw["hosted"], bool):
            raise ValueError(f"manifest entry {entry.id}: hosted must be true or false")
        if entry.kind not in ENTRY_KINDS or entry.distribution not in DISTRIBUTION_MODES:
            raise ValueError(f"manifest entry {entry.id}: unknown kind or distribution mode")
        if entry.distribution == "bundled" and not entry.hosted:
            raise ValueError(f"manifest entry {entry.id}: a bundled item must allow hosted use")
        if any(other.id == entry.id for other in entries):
            raise ValueError(f"manifest entry {entry.id} is repeated")
        entries.append(entry)
    return tuple(entries)


def engine_manifest() -> tuple[ManifestEntry, ...]:
    """The licence manifest shipped with CodeKavach."""
    package = "codekavach.privacy.detect.data"
    text = (importlib.resources.files(package) / MANIFEST_FILE).read_text(encoding="utf-8")
    return parse_manifest(text)
