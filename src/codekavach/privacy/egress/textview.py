"""How the leak scanners look at a request body: decoded once, unescaped, normalised.

Owning epic: E12.

A scanner that matched raw bytes would be beaten by the ordinary behaviour of a JSON serialiser
(two escape sequences spell ``fn``) and by trivial obfuscation (a zero-width character in the
middle of a name, a Cyrillic letter that looks Latin, a changed case). This module builds the
views the scanners share, so that the body is decoded and normalised once and not once per
scanner:

* ``BodyView.raw``: the body decoded as UTF-8 with replacement;
* ``BodyView.strings``: when the body is JSON, the text of every string value and key joined by
  newlines, with any unicode escape that survived decoded; otherwise the raw text with the same
  escapes decoded;
* ``normalise``: Unicode compatibility folding (NFKC), removal of zero-width, bidirectional and
  other format characters, case folding, a fold of the Cyrillic and Greek letters that look like
  Latin ones, and runs of whitespace collapsed to one space.

**Best effort.** This catches the realistic failures (escaping) and the trivial obfuscations. It
does not catch a paraphrase, a transliteration, a homoglyph outside the table, or a name rebuilt by
a model from context; the leakage harness measures what survives (``docs/research/INSIGHTS.md``
section 4.4). Offsets reported against a normalised or unescaped view are offsets into that view,
not into the body.

Nothing here keeps or logs text beyond the cache entry of the body being scanned.
"""

import json
import re
import threading
import unicodedata
from dataclasses import dataclass
from typing import Any, Final

# Format characters (category Cf: zero-width space and joiners, bidi marks and overrides, word
# joiner, byte order mark, soft hyphen) are removed. These few others render as nothing.
_INVISIBLE_CODES: Final = (
    0x034F,
    0x115F,
    0x1160,
    0x17B4,
    0x17B5,
    0x3164,
    0xFFA0,
    *range(0xFE00, 0xFE10),
)
_WHITESPACE: Final = re.compile(r"\s+")
_ESCAPE: Final = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_SURROGATE_PAIR: Final = re.compile("[\ud800-\udbff][\udc00-\udfff]")

# Letters that look like an ASCII letter, by code point. Applied after case folding.
_LOOKALIKES: Final = {
    "a": (0x0430, 0x03B1),  # Cyrillic a, Greek alpha
    "c": (0x0441, 0x03F2),  # Cyrillic es, Greek lunate sigma
    "d": (0x0501,),
    "e": (0x0435, 0x03B5),  # Cyrillic ie, Greek epsilon
    "h": (0x04BB,),
    "i": (0x0456, 0x03B9, 0x0457),  # Cyrillic i, Greek iota, Cyrillic yi
    "j": (0x0458, 0x03F3),
    "k": (0x043A, 0x03BA),
    "l": (0x04CF,),
    "o": (0x043E, 0x03BF),  # Cyrillic o, Greek omicron
    "p": (0x0440, 0x03C1),  # Cyrillic er, Greek rho
    "q": (0x051B,),
    "s": (0x0455,),
    "u": (0x03C5,),
    "v": (0x03BD, 0x0475),
    "w": (0x0461,),
    "x": (0x0445, 0x03C7),  # Cyrillic ha, Greek chi
    "y": (0x0443, 0x03B3),
    "z": (0x1D22,),
}
_CONFUSABLES: Final = {
    code: ascii_letter for ascii_letter, codes in _LOOKALIKES.items() for code in codes
}
_DROP: Final = frozenset(_INVISIBLE_CODES)


def _strip_format(text: str) -> str:
    if text.isascii():
        return text
    return "".join(
        char for char in text if unicodedata.category(char) != "Cf" and ord(char) not in _DROP
    )


def normalise(text: str) -> str:
    """``text`` folded for matching; see the module docstring for what it does and does not do."""
    if text.isascii():
        return _WHITESPACE.sub(" ", text.casefold())
    folded = _strip_format(unicodedata.normalize("NFKC", text)).casefold()
    return _WHITESPACE.sub(" ", folded.translate(_CONFUSABLES))


def _unescape(text: str) -> str:
    """Decode the unicode and hex escapes that are still in ``text``."""
    if "\\" not in text:
        return text

    def one(match: re.Match[str]) -> str:
        return chr(int(match.group(1) or match.group(2), 16))

    decoded = _ESCAPE.sub(one, text)
    return _SURROGATE_PAIR.sub(
        lambda pair: pair.group().encode("utf-16", "surrogatepass").decode("utf-16"), decoded
    )


def _collect(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            _collect(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect(item, out)


def json_strings(raw: str) -> str | None:
    """Every string value and key of ``raw`` as JSON, joined by newlines; ``None`` if not JSON."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError):  # not JSON, or nested too deep: it is just raw text
        return None
    out: list[str] = []
    _collect(document, out)
    return "\n".join(out)


@dataclass(slots=True)
class BodyView:
    """The views of one body. Built once; scanners read the properties they need."""

    raw: str
    _strings: str | None = None
    _normal_raw: str | None = None
    _normal_strings: str | None = None
    _built: bool = False

    def _ensure(self) -> None:
        if self._built:
            return
        decoded = json_strings(self.raw)
        self._strings = _unescape(decoded if decoded is not None else self.raw)
        self._built = True

    @property
    def strings(self) -> str:
        """The unescaped view (JSON string values, or the raw text with escapes decoded)."""
        self._ensure()
        assert self._strings is not None  # noqa: S101 - _ensure sets it
        return self._strings

    @property
    def normal_raw(self) -> str:
        """``normalise`` of the raw text."""
        if self._normal_raw is None:
            self._normal_raw = normalise(self.raw)
        return self._normal_raw

    @property
    def normal_strings(self) -> str:
        """``normalise`` of the unescaped view."""
        if self._normal_strings is None:
            self._normal_strings = normalise(self.strings)
        return self._normal_strings

    def matching_texts(self) -> tuple[str, ...]:
        """The distinct normalised texts a verbatim matcher runs over."""
        first, second = self.normal_raw, self.normal_strings
        return (first,) if first == second else (first, second)


_LOCK = threading.Lock()
_CACHE: list[tuple[bytes, BodyView]] = []


def view_of(body: bytes) -> BodyView:
    """The (cached) view of ``body``: one entry, replaced when a different body is scanned.

    The guard runs its scanners one after another on the same ``bytes`` object, so the body is
    decoded once. The entry is keyed by object identity and kept alive by the cache itself.
    """
    with _LOCK:
        if _CACHE and _CACHE[0][0] is body:
            return _CACHE[0][1]
    view = BodyView(body.decode("utf-8", errors="replace"))
    with _LOCK:
        _CACHE[:] = [(body, view)]
    return view


def forget() -> None:
    """Drop the cached view (a scan that ends does not leave a body in memory)."""
    with _LOCK:
        _CACHE.clear()
