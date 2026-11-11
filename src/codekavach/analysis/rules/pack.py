"""Rule packs: the manifest, the catalogues and the loaded pack with its checksum (E16-01).

Owning epic: E16. Layout under a licence directory (``rules/mit/`` is bundled; any other top-level
directory is user-installed and never shipped)::

    rules/<licence>/packs/<pack-id>/pack.yaml
    rules/<licence>/packs/<pack-id>/<class>/<rule-id>.yaml
    rules/<licence>/catalogues/<language>/<framework>.yaml

The checksum is the SHA-256 of the canonical JSON of the rules sorted by id, so it is the same on
every operating system and for any file order or line ending.
"""

import re
from enum import StrEnum
from typing import ClassVar, Final, Self

from pydantic import Field, model_validator

from codekavach.analysis.rules.dsl import RULE_ID_PATTERN, SEMVER_PATTERN, RuleDef, _RuleModel
from codekavach.core.models.canonical import canonical_json, sha256_hex

PACK_ID_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"


class CatalogueKind(StrEnum):
    """What a catalogue entry describes."""

    ENTRY_POINT = "entry_point"
    SOURCE = "source"
    SINK = "sink"
    SANITISER = "sanitiser"


CONTEXTS: Final = (
    "html",
    "html_attr",
    "js",
    "css",
    "url",
    "sql",
    "shell",
    "path",
    "ldap",
    "xpath",
    "xml",
    "header",
    "log",
    "template",
    "deserialisation",
)
_SYMBOL: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_$-]*(\.[A-Za-z_][A-Za-z0-9_$-]*)*$")


class CatalogueEntry(_RuleModel):
    """One entry point, source, sink or sanitiser, referred to by id from rules and taint specs.

    An entry names code either by ``symbol`` (a fully qualified dotted name, matched against the
    imports of the file) or by a ``pattern`` (a rule pattern). ``context`` is the output context
    of a sink and ``covers`` the contexts a sanitiser is adequate for; both draw on ``CONTEXTS``.
    ``kind`` is taken from the section of the catalogue file the entry is listed in.
    """

    id: str = Field(pattern=RULE_ID_PATTERN, max_length=128)
    kind: CatalogueKind | None = None
    type: str = Field(default="", max_length=32)
    symbol: str | None = Field(default=None, max_length=256)
    pattern: str | None = Field(default=None, max_length=4000)
    arg: int | None = Field(default=None, ge=0, le=32)
    context: str | None = Field(default=None, max_length=32)
    covers: tuple[str, ...] = Field(default=(), max_length=len(CONTEXTS))
    description: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if (self.symbol is None) == (self.pattern is None):
            raise ValueError("an entry names its code with exactly one of symbol and pattern")
        if self.symbol is not None and not _SYMBOL.fullmatch(self.symbol):
            raise ValueError("a symbol is a dotted name such as os.path.join")
        if self.context is not None and self.context not in CONTEXTS:
            raise ValueError("context is outside the closed vocabulary")
        if any(item not in CONTEXTS for item in self.covers):
            raise ValueError("covers names a context outside the closed vocabulary")
        return self


class Catalogue(_RuleModel):
    """A ``catalogues/<language>/<framework>.yaml`` file.

    Entries are listed under ``entry_points``, ``sources``, ``sinks`` and ``sanitisers``; the
    older flat ``entries`` list with an explicit ``kind`` is accepted too. :meth:`items` returns
    every entry with its ``kind`` filled in.
    """

    id: str | None = Field(default=None, pattern=RULE_ID_PATTERN, max_length=128)
    language: str = Field(max_length=32)
    framework: str = Field(max_length=64)
    entry_points: tuple[CatalogueEntry, ...] = Field(default=(), max_length=500)
    sources: tuple[CatalogueEntry, ...] = Field(default=(), max_length=1000)
    sinks: tuple[CatalogueEntry, ...] = Field(default=(), max_length=1000)
    sanitisers: tuple[CatalogueEntry, ...] = Field(default=(), max_length=1000)
    entries: tuple[CatalogueEntry, ...] = Field(default=(), max_length=2000)

    def items(self) -> tuple[CatalogueEntry, ...]:
        """Every entry, with ``kind`` taken from its section when the entry gives none."""
        sections = (
            (self.entry_points, CatalogueKind.ENTRY_POINT),
            (self.sources, CatalogueKind.SOURCE),
            (self.sinks, CatalogueKind.SINK),
            (self.sanitisers, CatalogueKind.SANITISER),
            (self.entries, None),
        )
        return tuple(
            entry if kind is None else entry.model_copy(update={"kind": kind})
            for entries, kind in sections
            for entry in entries
        )


class PackManifest(_RuleModel):
    """The ``pack.yaml`` file of a pack."""

    id: str = Field(pattern=PACK_ID_PATTERN)
    version: str = Field(pattern=SEMVER_PATTERN)
    licence: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=500)
    languages: tuple[str, ...] = Field(default=(), max_length=32)


class RulePack(_RuleModel):
    """A loaded pack: manifest facts, its rules, the catalogues of its licence directory."""

    SCHEMA_NOTE: ClassVar[str] = "checksum covers the rules only"

    id: str
    version: str
    licence: str
    description: str = ""
    languages: tuple[str, ...] = ()
    rules: tuple[RuleDef, ...] = ()
    catalogues: tuple[Catalogue, ...] = ()
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")


def pack_checksum(rules: tuple[RuleDef, ...] | list[RuleDef]) -> str:
    """SHA-256 over the canonical JSON of the rules sorted by id."""
    ordered = sorted(rules, key=lambda rule: rule.id)
    return sha256_hex(canonical_json([rule.model_dump(mode="json") for rule in ordered]))


def catalogue_ids(catalogues: tuple[Catalogue, ...] | list[Catalogue]) -> frozenset[str]:
    """Every entry id of the catalogues."""
    return frozenset(entry.id for catalogue in catalogues for entry in catalogue.items())


def public_names(catalogues: tuple[Catalogue, ...] | list[Catalogue]) -> tuple[str, ...]:
    """Every ``symbol`` of every source, sink and sanitiser, sorted and without duplicates.

    These are the names the pseudonymiser's public allow-list keeps in clear (ARCHITECTURE
    section 6.2 step 4), so that sources, sinks and sanitisers stay recognisable in a sanitised
    payload. An operator who adds a private catalogue adds the same names through
    ``privacy.public_allowlist_extra``.
    """
    wanted = {CatalogueKind.SOURCE, CatalogueKind.SINK, CatalogueKind.SANITISER}
    return tuple(
        sorted(
            {
                entry.symbol
                for catalogue in catalogues
                for entry in catalogue.items()
                if entry.symbol is not None and entry.kind in wanted
            }
        )
    )
