"""Per-ecosystem version comparison (E19-02).

Comparison table (documented behaviour):

==============  =============================================================================
Ecosystem       Rule
==============  =============================================================================
PyPI            PEP 440: epoch, release segments, then ``dev < a < b < rc < final < post``;
                local versions (``+x``) are ignored for ordering.
npm, crates.io  Semantic versioning 2.0: a pre-release sorts below its release; pre-release
                identifiers compare numerically when numeric, else lexically; numeric first.
Maven           Segment-wise; qualifiers ``alpha < beta < milestone < rc < snapshot < "" < sp``;
                unknown qualifiers sort after the known ones, lexically.
Go              ``v`` prefix stripped; semver, with pseudo-versions ordered by their timestamp.
other           Dotted numeric segments, then a lexical tie-break.
==============  =============================================================================
"""

import re
from collections.abc import Callable
from functools import cmp_to_key
from typing import Any, Final

_PEP = re.compile(
    r"^v?(?:(?P<epoch>\d+)!)?(?P<rel>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pren>\d+)?)?"
    r"(?:(?:-(?P<postn1>\d+))|(?:[-_.]?(?P<post>post|rev|r)[-_.]?(?P<postn2>\d+)?))?"
    r"(?:[-_.]?(?P<dev>dev)[-_.]?(?P<devn>\d+)?)?(?:\+.*)?$",
    re.IGNORECASE,
)
_PRE_RANK: Final = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_INF: Final = 10**9


def _cmp(a: Any, b: Any) -> int:
    return int(a > b) - int(a < b)


def _release(text: str) -> tuple[int, ...]:
    parts = [int(p) for p in text.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _loose_key(version: str) -> tuple[Any, ...]:
    parts = re.split(r"[.\-_+]", version.strip().lstrip("vV"))
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in parts if p)


def _pep_key(version: str) -> tuple[Any, ...]:
    m = _PEP.match(version.strip())
    if m is None:
        return (0, _loose_key(version), (_INF, 0), -1, _INF)
    pre: tuple[int, int] = (_INF, 0)
    if m["pre"]:
        pre = (_PRE_RANK[m["pre"].lower()], int(m["pren"] or 0))
    elif m["dev"] and not (m["post"] or m["postn1"]):
        pre = (-1, 0)  # a bare .devN sorts before any pre-release
    post = -1
    if m["postn1"] or m["post"]:
        post = int(m["postn1"] or m["postn2"] or 0)
    dev = int(m["devn"] or 0) if m["dev"] else _INF
    return (int(m["epoch"] or 0), _release(m["rel"]), pre, post, dev)


def _semver_key(version: str) -> tuple[Any, ...]:
    v = version.strip().lstrip("vV").split("+", 1)[0]
    core, _, pre = v.partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in core.split(".")[:3])
    nums += (0,) * (3 - len(nums))
    if not pre:
        return (nums, 1, ())
    ids = tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in pre.split("."))
    return (nums, 0, ids)


_MAVEN_Q: Final = {
    "alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3,
    "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6,
}  # fmt: skip


def _maven_key(version: str) -> tuple[Any, ...]:
    out: list[tuple[int, int, str]] = []
    for part in re.findall(r"\d+|[A-Za-z]+", version.lower()):
        if part.isdigit():
            out.append((1, int(part), ""))
        else:
            rank = _MAVEN_Q.get(part, 7)
            # qualifiers below the release sort before a missing segment, those above after it
            out.append((0, rank, "") if rank < 5 else (1, 0, f"~{rank}{part}"))
    while out and out[-1] in {(1, 0, ""), (1, 0, "~5ga"), (1, 0, "~5final"), (1, 0, "~5release")}:
        out.pop()
    return tuple(out)


def _pad(key: tuple[Any, ...], other: tuple[Any, ...]) -> tuple[Any, ...]:
    return key + ((1, 0, ""),) * max(0, len(other) - len(key))


_PSEUDO = re.compile(r"^(?P<base>.*?)-?(?:0\.)?(?P<ts>\d{14})-(?P<sha>[0-9a-f]{12})$")


def _go_key(version: str) -> tuple[Any, ...]:
    m = _PSEUDO.match(version)
    if m:
        return (_semver_key(m["base"] or "v0.0.0"), m["ts"])
    return (_semver_key(version), "")


_KEYS: Final[dict[str, Callable[[str], tuple[Any, ...]]]] = {
    "PyPI": _pep_key,
    "npm": _semver_key,
    "crates.io": _semver_key,
    "Maven": _maven_key,
    "Go": _go_key,
}


def compare(ecosystem: str, a: str, b: str) -> int:
    """-1, 0 or 1 as ``a`` sorts before, equal to or after ``b`` in ``ecosystem``."""
    key = _KEYS.get(ecosystem, _loose_key)
    ka, kb = key(a), key(b)
    if ecosystem == "Maven":
        ka, kb = _pad(ka, kb), _pad(kb, ka)
    return _cmp(ka, kb)


def sort_key(ecosystem: str) -> Callable[[str], Any]:
    """A ``key=`` function sorting versions of ``ecosystem`` ascending."""
    return cmp_to_key(lambda a, b: compare(ecosystem, a, b))
