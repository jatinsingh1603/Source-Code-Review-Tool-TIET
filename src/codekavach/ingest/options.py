"""``IngestOptions``: the per-run choices that are flags, not settings (E06-03).

Owning epic: E06.

``--ref``, ``--depth``, ``--git-credential``, ``--stdin-filename``, ``--diff-since``,
``--include-deleted`` and ``--subproject`` change what one scan reads, not how the product is
configured, so they travel with the run (in the ``scan.target`` artefact) and not through the
layered settings. The core pipeline carries them as a plain mapping and does not interpret it;
this module is the only place that turns the mapping into a typed value and checks it.

``--git-credential`` is a secret *reference* (``env:NAME``), never a secret.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

MAX_SUBPROJECTS: Final = 256
MAX_TEXT: Final = 4096


class OptionsError(ValueError):
    """The mapping holds an option of the wrong type or an out-of-range value."""


@dataclass(frozen=True, slots=True)
class IngestOptions:
    """Typed per-run ingest options; the defaults mean "nothing was asked"."""

    ref: str | None = None
    depth: int = 1
    git_credential: str | None = None
    stdin_filename: str | None = None
    diff_since: str | None = None
    include_deleted: bool = False
    subprojects: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, object]:
        """The JSON-able form, holding only what differs from the defaults."""
        default = IngestOptions()
        out: dict[str, object] = {}
        for name in (
            "ref",
            "depth",
            "git_credential",
            "stdin_filename",
            "diff_since",
            "include_deleted",
        ):
            if getattr(self, name) != getattr(default, name):
                out[name] = getattr(self, name)
        if self.subprojects:
            out["subprojects"] = list(self.subprojects)
        return out

    @classmethod
    def from_mapping(cls, raw: object) -> "IngestOptions":
        """Build from the mapping stored with the target; ``None`` or ``{}`` gives the defaults.

        Raises:
            OptionsError: a value has the wrong type or is out of range. Values are not echoed.
        """
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise OptionsError("the ingest options are not a mapping")
        unknown = set(raw) - set(cls.__slots__)
        if unknown:
            raise OptionsError("the ingest options hold an unknown key")
        return cls(
            ref=_text(raw, "ref"),
            depth=_depth(raw),
            git_credential=_text(raw, "git_credential"),
            stdin_filename=_text(raw, "stdin_filename"),
            diff_since=_text(raw, "diff_since"),
            include_deleted=_flag(raw, "include_deleted"),
            subprojects=_texts(raw, "subprojects"),
        )


def _text(raw: Mapping[str, object], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise OptionsError(f"the ingest option {key!r} is not a short string")
    return value


def _texts(raw: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = raw.get(key)
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or len(value) > MAX_SUBPROJECTS:
        raise OptionsError(f"the ingest option {key!r} is not a short list")
    if not all(isinstance(item, str) and len(item) <= MAX_TEXT for item in value):
        raise OptionsError(f"the ingest option {key!r} holds a non-string")
    return tuple(str(item) for item in value)


def _flag(raw: Mapping[str, object], key: str) -> bool:
    value = raw.get(key, False)
    if not isinstance(value, bool):
        raise OptionsError(f"the ingest option {key!r} is not a boolean")
    return value


def _depth(raw: Mapping[str, object]) -> int:
    value = raw.get("depth", 1)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1_000_000:
        raise OptionsError("the ingest option 'depth' is not an integer from 1 to 1000000")
    return value
