"""False-positive filters for the secret detectors, each individually testable and disableable.

Owning epic: E08.

A filter looks at one candidate value in its context and says "this is not a secret" (``DROP``)
or "this is probably boilerplate" (``DOWNGRADE``). Downgrading keeps the span, marked
``downgraded``, so the recall-first posture holds: the value is still redacted at the default
floor and the downgrade is counted in ``DetectionReport``. Every rule has a name; a detector takes
``disabled_filters`` so a test (or an operator with measurements) can turn one off and see the
value come back.

Rules:

* ``hash_in_manifest``: a hexadecimal string of 32, 40, 64 or 128 characters in a lockfile,
  manifest, or an ``integrity``/``hash``/``checksum`` field is a digest.
* ``uuid``: a canonical UUID is an identifier.
* ``base64_text``: base64 that decodes to printable words is data.
* ``placeholder_value``: the whole literal is in ``data/placeholder_values.txt`` or has the shape
  of a placeholder (``xxxx``, a repeated character, ``<redacted>``, ``${NAME}``).
* ``example_marker``: in a test, fixture, example or docs path, a value (or its line) that says
  it is an example.
* ``repeated_value`` (``DOWNGRADE``): the same value more than ``REPEAT_THRESHOLD`` times in one
  scan is boilerplate.

This module performs no network operation.
"""

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from importlib import resources
from pathlib import PurePosixPath
from typing import Final

REPEAT_THRESHOLD: Final = 20
_DATA_PACKAGE: Final = "codekavach.privacy.detect.secrets.data"
_DATA_FILE: Final = "placeholder_values.txt"
_HASH_LENGTHS: Final = frozenset({32, 40, 64, 128})
_LOCKFILE_NAMES: Final = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
        "go.sum",
        "composer.lock",
        "gemfile.lock",
        "uv.lock",
        "npm-shrinkwrap.json",
        "packages.lock.json",
        "manifest.json",
        "manifest.yaml",
        "manifest.yml",
    }
)
_HASH_FIELDS: Final = frozenset(
    {"integrity", "hash", "checksum", "sha", "sha1", "sha256", "sha512", "md5", "digest", "etag"}
)
_EXAMPLE_DIRECTORIES: Final = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "testdata", "examples"}
    | {"example", "samples", "sample", "docs", "doc"}
)
_EXAMPLE_WORDS: Final = ("example", "sample", "dummy", "fake", "not-a-real", "not_a_real")
_HEX: Final = re.compile(r"[0-9a-fA-F]+")
_SRI: Final = re.compile(r"(?:sha1|sha256|sha384|sha512|md5)-[A-Za-z0-9+/]{20,}={0,2}$")
_UUID: Final = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_BASE64: Final = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_PLACEHOLDER_SHAPES: Final = (
    re.compile(r"(.)\1{3,}"),  # a repeated single character
    re.compile(r"[xX*#.\-_]{4,}"),  # xxxx, ****, ----
    re.compile(r"<[^<>]{1,40}>"),  # <your-key>
    re.compile(r"\$\{[^}]{1,64}\}"),  # ${NAME}
    re.compile(r"\{\{[^}]{1,64}\}\}"),  # {{ name }}
    re.compile(r"%\([^)]{1,64}\)s"),  # %(name)s
    re.compile(r"your[-_ ]?[\w-]{0,30}[-_ ]?here", re.IGNORECASE),
)


class Verdict(StrEnum):
    """What a matching filter does to the candidate."""

    DROP = "drop"
    DOWNGRADE = "downgrade"


@dataclass(frozen=True)
class FilterContext:
    """What a filter may look at besides the value: where it is and how often it occurs."""

    path: str
    line: str = ""
    field: str | None = None
    occurrences: int = 1


@dataclass(frozen=True)
class FalsePositiveFilter:
    """One named rule."""

    name: str
    description: str
    verdict: Verdict
    applies: Callable[[str, FilterContext], bool]


@cache
def placeholder_values() -> frozenset[str]:
    """The lower-cased whole-literal placeholder denylist from ``placeholder_values.txt``."""
    text = resources.files(_DATA_PACKAGE).joinpath(_DATA_FILE).read_text(encoding="utf-8")
    values: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value, separator, reason = line.partition(" # ")
        if not separator or not reason.strip():
            raise ValueError(f"{_DATA_FILE}: every entry needs a reason after ' # ': {line[:30]!r}")
        values.add(value.strip().lower())
    return frozenset(values)


def is_placeholder(value: str) -> bool:
    """True when the whole literal is a known placeholder or has the shape of one."""
    if value.lower() in placeholder_values():
        return True
    return any(shape.fullmatch(value) for shape in _PLACEHOLDER_SHAPES)


def _hash_in_manifest(value: str, context: FilterContext) -> bool:
    is_hex_digest = len(value) in _HASH_LENGTHS and _HEX.fullmatch(value) is not None
    is_sri_digest = _SRI.match(value) is not None  # sha512-<base64>, as in package-lock.json
    if not (is_hex_digest or is_sri_digest):
        return False
    name = PurePosixPath(context.path).name.lower()
    field = (context.field or "").lower()
    return name in _LOCKFILE_NAMES or name.endswith(".lock") or field in _HASH_FIELDS


def _uuid(value: str, _: FilterContext) -> bool:
    return _UUID.fullmatch(value) is not None


def _base64_text(value: str, _: FilterContext) -> bool:
    if len(value) < 16 or not _BASE64.fullmatch(value):
        return False
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("ascii")
    except (binascii.Error, ValueError):
        return False
    if not decoded.isprintable():
        return False
    words = re.findall(r"[A-Za-z]{3,}", decoded)
    letters = sum(char.isalpha() or char.isspace() for char in decoded)
    return len(words) >= 2 and letters / len(decoded) >= 0.85


def _placeholder_value(value: str, _: FilterContext) -> bool:
    return is_placeholder(value)


def _example_marker(value: str, context: FilterContext) -> bool:
    directories = {part.lower() for part in PurePosixPath(context.path).parts[:-1]}
    if not directories & _EXAMPLE_DIRECTORIES:
        return False
    haystack = f"{value} {context.line}".lower()
    return any(word in haystack for word in _EXAMPLE_WORDS)


def _repeated_value(_: str, context: FilterContext) -> bool:
    return context.occurrences > REPEAT_THRESHOLD


FILTERS: Final[tuple[FalsePositiveFilter, ...]] = (
    FalsePositiveFilter(
        "hash_in_manifest",
        "Hex of 32, 40, 64 or 128 characters, or a sha512-<base64> digest, in a lockfile, "
        "manifest or integrity field.",
        Verdict.DROP,
        _hash_in_manifest,
    ),
    FalsePositiveFilter("uuid", "A canonical UUID.", Verdict.DROP, _uuid),
    FalsePositiveFilter(
        "base64_text", "Base64 of printable ASCII words.", Verdict.DROP, _base64_text
    ),
    FalsePositiveFilter(
        "placeholder_value",
        "A whole-literal placeholder such as changeme, xxxx or <redacted>.",
        Verdict.DROP,
        _placeholder_value,
    ),
    FalsePositiveFilter(
        "example_marker",
        "An 'example' value in a test, fixture, example or docs path.",
        Verdict.DROP,
        _example_marker,
    ),
    FalsePositiveFilter(
        "repeated_value",
        f"The same value more than {REPEAT_THRESHOLD} times in one scan.",
        Verdict.DOWNGRADE,
        _repeated_value,
    ),
)
FILTER_NAMES: Final = frozenset(rule.name for rule in FILTERS)


def first_match(
    value: str, context: FilterContext, disabled: frozenset[str] = frozenset()
) -> FalsePositiveFilter | None:
    """The first enabled filter that applies to ``value``, or ``None``.

    Raises:
        ValueError: ``disabled`` names a filter that does not exist (a typo would silently keep
            the filter on).
    """
    unknown = disabled - FILTER_NAMES
    if unknown:
        raise ValueError(f"unknown filter names: {sorted(unknown)}")
    for rule in FILTERS:
        if rule.name not in disabled and rule.applies(value, context):
            return rule
    return None
