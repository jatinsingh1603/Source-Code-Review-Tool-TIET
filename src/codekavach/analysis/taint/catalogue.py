"""Binding of catalogue entries to the calls and places of a lowered function (E17-02).

Owning epic: E17. The catalogues of E16-03 say which symbols are sources, sinks and sanitisers.
This module resolves them against what the lowering saw: a call's resolved dotted symbol (through
the imports of the file), its text when nothing resolved, and the aliases of the file for places
such as ``request.args``.

Matching, from strongest to weakest:

1. *Resolved*: the call's symbol equals the entry's symbol (a source also matches any member of
   it, so ``flask.request.args`` matches ``flask.request.args.get``).
2. *Global*: an entry in ``builtins.`` or ``globalThis.`` matches the bare name (``open``).
3. *Method*: an entry whose second-to-last segment is a class (``sqlite3.Cursor.execute``)
   matches a call of that method name on a receiver whose type is not known. This is the weakest
   match and the candidate says so (``taint.sink_match=method``), because ``sock.send`` and
   ``res.send`` are indistinguishable without types.

Only a catalogue entry can sanitise (``docs/research/INSIGHTS.md`` section 2.2), and it sanitises
only the contexts it declares in ``covers``; the function name is never read for meaning.
"""

from dataclasses import dataclass
from typing import Final

from codekavach.analysis.rules.pack import Catalogue, CatalogueEntry
from codekavach.analysis.taint.ir import Call, Place
from codekavach.analysis.taint.strings import last_segment
from codekavach.core.models import Severity

GLOBAL_PREFIXES: Final = ("builtins.", "globalThis.")
LANGUAGE_FAMILY: Final = {"typescript": "javascript"}
UNKNOWN_SOURCE: Final = "unknown"


@dataclass(frozen=True, slots=True)
class SinkClass:
    """What a sink kind means as a weakness: CWE ids and the severity of an exploitable flow."""

    cwe: tuple[int, ...]
    severity: Severity


SINK_CLASSES: Final[dict[str, SinkClass]] = {
    "sql": SinkClass((89,), Severity.HIGH),
    "shell": SinkClass((78,), Severity.HIGH),
    "code": SinkClass((95,), Severity.HIGH),
    "deserialise": SinkClass((502,), Severity.HIGH),
    "deserialisation": SinkClass((502,), Severity.HIGH),
    "template": SinkClass((1336,), Severity.HIGH),
    "path": SinkClass((22,), Severity.MEDIUM),
    "http": SinkClass((918,), Severity.MEDIUM),
    "url": SinkClass((918,), Severity.MEDIUM),
    "redirect": SinkClass((601,), Severity.MEDIUM),
    "xml": SinkClass((611,), Severity.MEDIUM),
    "html": SinkClass((79,), Severity.MEDIUM),
    "js": SinkClass((79,), Severity.MEDIUM),
    "ldap": SinkClass((90,), Severity.MEDIUM),
    "xpath": SinkClass((643,), Severity.MEDIUM),
    "header": SinkClass((113,), Severity.LOW),
    "log": SinkClass((117,), Severity.LOW),
}
"""Sink kind (the third segment of a sink id, else its context) to the weakness it implies. A kind
absent here, such as ``weakhash``, is not a data-flow weakness and is never reported by taint."""


@dataclass(frozen=True, slots=True)
class SinkMatch:
    """A call recognised as a sink."""

    entry: CatalogueEntry
    kind: str
    context: str | None
    arg: int | None
    exact: bool

    @property
    def weakness(self) -> SinkClass:
        """The weakness class of this sink."""
        return SINK_CLASSES[self.kind]


def sink_kind(entry: CatalogueEntry) -> str | None:
    """The kind of a sink entry: ``python.sink.sql.cursor`` is ``sql``; else its context."""
    parts = entry.id.split(".")
    if len(parts) >= 4 and parts[1] == "sink" and parts[2] in SINK_CLASSES:
        return parts[2]
    if entry.context in SINK_CLASSES:
        return entry.context
    return None


def _simple_path(pattern: str) -> str | None:
    """A pattern that is just a dotted access path (``req.query``, ``request.json()``)."""
    text = pattern.strip().removesuffix("()")
    if not text or any(char in text for char in "$(){}[]<> ,;:\"'\n") or ".." in text:
        return None
    return text


class Binding:
    """Catalogue entries of one language, ready to match calls and places."""

    def __init__(
        self,
        catalogues: tuple[Catalogue, ...] | list[Catalogue],
        aliases: tuple[tuple[str, str], ...] = (),
        language: str = "python",
    ) -> None:
        family = LANGUAGE_FAMILY.get(language, language)
        self.aliases = dict(aliases)
        self.sources: list[tuple[CatalogueEntry, str]] = []
        self._sources_by_head: dict[str, list[tuple[CatalogueEntry, str]]] = {}
        self.sinks: dict[str, list[tuple[CatalogueEntry, str, str]]] = {}
        self.sanitisers: dict[str, list[tuple[CatalogueEntry, str]]] = {}
        for catalogue in catalogues:
            if catalogue.language != family:
                continue
            for entry in catalogue.items():
                self._add(entry)

    def _add(self, entry: CatalogueEntry) -> None:
        name = entry.symbol if entry.symbol is not None else _simple_path(entry.pattern or "")
        kind = entry.kind.value if entry.kind is not None else ""
        if name is None:
            return
        if kind == "source":
            self.sources.append((entry, name))
            for head in dict.fromkeys((_head(name), _head(_bare(name)))):
                self._sources_by_head.setdefault(head, []).append((entry, name))
        elif kind == "sink":
            sink = sink_kind(entry)
            if sink is not None:
                self.sinks.setdefault(last_segment(name), []).append((entry, name, sink))
        elif kind == "sanitiser":
            self.sanitisers.setdefault(last_segment(name), []).append((entry, name))

    # --- places and calls --------------------------------------------------------------------

    def qualified(self, place: Place) -> str:
        """The place text with its base replaced by what the file imported under that name."""
        target = self.aliases.get(place.base)
        return (target if target is not None else place.base) + "".join(place.steps)

    def source_for_place(self, place: Place) -> CatalogueEntry | None:
        """The source entry a read of ``place`` matches, if any."""
        if not self.sources:
            return None
        qualified = self.qualified(place)
        for entry, name in self._sources_by_head.get(_head(qualified), ()):
            if _within(qualified, name) or _within(place.text, name):
                return entry
        for entry, name in self._sources_by_head.get(place.base, ()):
            if _within(place.text, name):
                return entry
        return None

    def source_for_call(self, call: Call) -> CatalogueEntry | None:
        """The source entry a call of ``call.callee`` matches, if any."""
        callee = call.callee
        text = callee.text.removeprefix("new ")
        head = _head(callee.symbol if callee.symbol is not None else text)
        for entry, name in self._sources_by_head.get(head, ()):
            if callee.symbol is not None:
                if _within(callee.symbol, name):
                    return entry
            elif _within(text, name) or _global(name, text) or _within(text, _bare(name)):
                return entry
        return None

    def sink_for(self, call: Call) -> SinkMatch | None:
        """The sink entry the call matches, if any."""
        callee = call.callee
        text = callee.text.removeprefix("new ")
        for entry, name, kind in self._by_name(self.sinks, callee.symbol, text):
            exact = self._call_matches(name, callee.symbol, text, call.receiver is not None)
            if exact is not None:
                return SinkMatch(entry, kind, entry.context, entry.arg, exact)
        return None

    def sanitiser_for(self, call: Call) -> CatalogueEntry | None:
        """The sanitiser entry the call matches, if any (resolved and global matches only)."""
        callee = call.callee
        text = callee.text.removeprefix("new ")
        for entry, name in self._by_name(self.sanitisers, callee.symbol, text):
            if self._call_matches(name, callee.symbol, text, call.receiver is not None) is True:
                return entry
        return None

    @staticmethod
    def _by_name[T](index: dict[str, list[T]], symbol: str | None, text: str) -> list[T]:
        """Entries indexed under the last segment of the resolved symbol or of the text."""
        names = dict.fromkeys(
            (last_segment(symbol) if symbol is not None else last_segment(text), last_segment(text))
        )
        return [item for name in names for item in index.get(name, ())]

    @staticmethod
    def _call_matches(name: str, symbol: str | None, text: str, has_receiver: bool) -> bool | None:
        """True for a resolved or global match, False for a method-name match, None for none."""
        if symbol is not None:
            return True if symbol == name else None
        if _global(name, text):
            return True
        parts = name.split(".")
        class_method = len(parts) >= 3 and parts[-2][:1].isupper()
        if class_method and has_receiver and last_segment(text) == parts[-1]:
            return False
        return None


def _head(text: str) -> str:
    """The first segment of a dotted or indexed name."""
    for index, char in enumerate(text):
        if char in ".[":
            return text[:index]
    return text


def _within(text: str, name: str) -> bool:
    """Whether ``text`` is ``name`` or a member or element of it."""
    return text == name or text.startswith((name + ".", name + "["))


def _global(name: str, text: str) -> bool:
    """Whether ``name`` is ``builtins.X`` or ``globalThis.X`` and ``text`` is the bare ``X``."""
    return any(name == prefix + text for prefix in GLOBAL_PREFIXES)


def _bare(name: str) -> str:
    """A catalogue name without a ``builtins.`` or ``globalThis.`` prefix."""
    for prefix in GLOBAL_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name
