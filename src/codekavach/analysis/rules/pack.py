"""Rule packs: the manifest, the catalogues and the loaded pack with its checksum (E16-01).

Owning epic: E16. Layout under a licence directory (``rules/mit/`` is bundled; any other top-level
directory is user-installed and never shipped)::

    rules/<licence>/packs/<pack-id>/pack.yaml
    rules/<licence>/packs/<pack-id>/<class>/<rule-id>.yaml
    rules/<licence>/catalogues/<language>/<framework>.yaml

The checksum is the SHA-256 of the canonical JSON of the rules sorted by id, so it is the same on
every operating system and for any file order or line ending.
"""

from enum import StrEnum
from typing import ClassVar

from pydantic import Field

from codekavach.analysis.rules.dsl import RULE_ID_PATTERN, SEMVER_PATTERN, RuleDef, _RuleModel
from codekavach.core.models.canonical import canonical_json, sha256_hex

PACK_ID_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"


class CatalogueKind(StrEnum):
    """What a catalogue entry describes."""

    SOURCE = "source"
    SINK = "sink"
    SANITISER = "sanitiser"


class CatalogueEntry(_RuleModel):
    """One source, sink or sanitiser, referred to by id from rules and taint specs."""

    id: str = Field(pattern=RULE_ID_PATTERN, max_length=128)
    kind: CatalogueKind
    pattern: str = Field(max_length=4000)
    description: str = Field(default="", max_length=500)


class Catalogue(_RuleModel):
    """A ``catalogues/<language>/<framework>.yaml`` file."""

    language: str = Field(max_length=32)
    framework: str = Field(max_length=64)
    entries: tuple[CatalogueEntry, ...] = Field(default=(), max_length=2000)


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
    return frozenset(entry.id for catalogue in catalogues for entry in catalogue.entries)
