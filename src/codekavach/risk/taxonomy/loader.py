"""Load and validate the CWE knowledge base and the compliance tables under ``data/``.

Owning epic: E29. The tables are plain YAML with their sources recorded in ``data/SOURCES.yaml``.
The directory is found at ``$CODEKAVACH_DATA_DIR`` or next to the source checkout (which is also
the Docker image layout). Loading is strict: an unknown key, an unknown family or control group,
or an invalid CVSS vector fails the load, so a broken table is caught by the tests rather than at
scan time. ``load_knowledge_base()`` is cached per directory.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar, Final, Literal

import yaml
from pydantic import Field, model_validator

from codekavach.core.log import get_logger
from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.taxonomy import CweId, Reference
from codekavach.risk.cvss.v4 import Cvss4Vector
from codekavach.risk.cvss.v31 import Cvss31Vector

_log = get_logger(__name__)

DATA_DIR_ENV: Final = "CODEKAVACH_DATA_DIR"
BASELINE_GROUP: Final = "baseline"
FALLBACK_FAMILY: Final = "input-validation"

Abstraction = Literal["pillar", "class", "base", "variant", "compound"]
Basis = Literal["official", "derived"]


class KnowledgeBaseError(ValueError):
    """A data table is missing or invalid."""


class _Data(KavachModel):
    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA


class ThreatFactors(_Data):
    """OWASP Risk Rating likelihood factors (0 to 9) typical of a weakness family."""

    skill: int = Field(ge=0, le=9)
    motive: int = Field(ge=0, le=9)
    opportunity: int = Field(ge=0, le=9)
    size: int = Field(ge=0, le=9)
    ease_of_discovery: int = Field(ge=0, le=9)
    ease_of_exploit: int = Field(ge=0, le=9)
    awareness: int = Field(ge=0, le=9)
    intrusion_detection: int = Field(ge=0, le=9)


class Family(_Data):
    """A weakness family: default vectors, threat factors, remediation and control groups."""

    key: str
    title: str
    cvss4: str
    cvss31: str
    threat: ThreatFactors
    remediation: str
    references: tuple[Reference, ...] = ()
    compliance: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_vectors(self) -> "Family":
        Cvss4Vector.parse(self.cvss4)
        Cvss31Vector.parse(self.cvss31)
        return self


class CweEntry(_Data):
    """One weakness of the knowledge base."""

    id: CweId
    name: str = Field(min_length=1, max_length=300)
    abstraction: Abstraction
    family: str
    summary: str = ""
    top25: int | None = Field(default=None, ge=1, le=25)
    owasp: str | None = Field(default=None, pattern=r"^A(0[1-9]|10)$")
    owasp_basis: Basis = "derived"
    asvs: tuple[str, ...] = ()
    capec: tuple[int, ...] = ()
    remediation: str | None = None

    @property
    def url(self) -> str:
        """The MITRE definition page."""
        return f"https://cwe.mitre.org/data/definitions/{self.id}.html"


class OwaspCategory(_Data):
    """An OWASP Top 10 2021 category."""

    id: str
    title: str
    url: str


class Framework(_Data):
    """A compliance framework and the source it is cited from."""

    id: str
    title: str
    version: str
    source: str


class Control(_Data):
    """One clause of a framework that a control group maps to."""

    framework: str
    id: str
    title: str
    basis: Basis = "derived"


class Source(_Data):
    """A document a table draws on."""

    id: str
    title: str
    publisher: str
    url: str
    version: str | None = None
    used_for: str = ""


class KnowledgeBase(_Data):
    """Every table, validated and cross-checked."""

    catalogue_version: str
    weaknesses: dict[int, CweEntry]
    families: dict[str, Family]
    owasp: dict[str, OwaspCategory]
    owasp_version: str
    frameworks: dict[str, Framework]
    groups: dict[str, tuple[Control, ...]]
    sources: dict[str, Source]
    directory: str

    @model_validator(mode="after")
    def _cross_check(self) -> "KnowledgeBase":
        if FALLBACK_FAMILY not in self.families:
            raise ValueError(f"family {FALLBACK_FAMILY!r} is required as the fallback")
        for entry in self.weaknesses.values():
            if entry.family not in self.families:
                raise ValueError(f"CWE-{entry.id} names unknown family {entry.family!r}")
            if entry.owasp is not None and entry.owasp not in self.owasp:
                raise ValueError(f"CWE-{entry.id} names unknown OWASP category {entry.owasp}")
        for family in self.families.values():
            for group in family.compliance:
                if group not in self.groups:
                    raise ValueError(f"family {family.key!r} names unknown group {group!r}")
        for controls in self.groups.values():
            for control in controls:
                if control.framework not in self.frameworks:
                    raise ValueError(f"unknown framework {control.framework!r}")
        for framework in self.frameworks.values():
            if framework.source not in self.sources:
                raise ValueError(f"framework {framework.id!r} cites unknown source")
        return self

    def entry(self, cwe: int) -> CweEntry | None:
        """The knowledge-base entry of ``cwe``, or None."""
        return self.weaknesses.get(cwe)

    def primary(self, cwes: tuple[int, ...]) -> CweEntry | None:
        """The first of ``cwes`` the knowledge base knows."""
        for cwe in cwes:
            entry = self.weaknesses.get(cwe)
            if entry is not None:
                return entry
        return None

    def family_for(self, cwes: tuple[int, ...]) -> Family:
        """The weakness family of the first known CWE, else the generic fallback family."""
        entry = self.primary(cwes)
        return self.families[entry.family if entry is not None else FALLBACK_FAMILY]

    def controls_for(self, family: Family) -> tuple[Control, ...]:
        """Baseline controls plus the family's control groups, de-duplicated, in table order."""
        seen: set[tuple[str, str]] = set()
        result: list[Control] = []
        for group in (BASELINE_GROUP, *family.compliance):
            for control in self.groups.get(group, ()):
                key = (control.framework, control.id)
                if key not in seen:
                    seen.add(key)
                    result.append(control)
        return tuple(result)


def default_data_dir() -> Path:
    """``$CODEKAVACH_DATA_DIR`` when set, else ``data/`` of the checkout or image."""
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "data" / "cwe" / "catalogue.yaml"
        if candidate.is_file():
            return parent / "data"
    return here.parents[4] / "data"


def _read(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise KnowledgeBaseError(f"cannot read {path.name}: {error}") from error
    if not isinstance(loaded, dict):
        raise KnowledgeBaseError(f"{path.name} must hold a mapping")
    return loaded


def _controls(raw: dict[str, Any]) -> dict[str, tuple[Control, ...]]:
    groups: dict[str, tuple[Control, ...]] = {}
    for name, frameworks in raw.items():
        rows: list[Control] = []
        for framework, controls in (frameworks or {}).items():
            rows.extend(Control(framework=framework, **row) for row in controls or ())
        groups[name] = tuple(rows)
    return groups


def parse_knowledge_base(directory: Path) -> KnowledgeBase:
    """Read every table under ``directory``; raises KnowledgeBaseError when one is invalid."""
    try:
        catalogue = _read(directory / "cwe" / "catalogue.yaml")
        families = _read(directory / "cwe" / "families.yaml")
        owasp = _read(directory / "taxonomy" / "owasp-top10-2021.yaml")
        compliance = _read(directory / "compliance" / "controls.yaml")
        sources = _read(directory / "SOURCES.yaml")
        return KnowledgeBase(
            catalogue_version=str(catalogue["catalogue_version"]),
            weaknesses={int(row["id"]): CweEntry(**row) for row in catalogue["weaknesses"]},
            families={key: Family(key=key, **value) for key, value in families["families"].items()},
            owasp={
                key: OwaspCategory(id=key, **value) for key, value in owasp["categories"].items()
            },
            owasp_version=str(owasp["version"]),
            frameworks={
                key: Framework(id=key, **value) for key, value in compliance["frameworks"].items()
            },
            groups=_controls(compliance["groups"]),
            sources={key: Source(id=key, **value) for key, value in sources["sources"].items()},
            directory=str(directory),
        )
    except KnowledgeBaseError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise KnowledgeBaseError(f"invalid knowledge base under {directory}: {error}") from error


@lru_cache(maxsize=4)
def _cached(directory: str) -> KnowledgeBase:
    return parse_knowledge_base(Path(directory))


def load_knowledge_base(directory: Path | None = None) -> KnowledgeBase | None:
    """The knowledge base, or None (with one warning) when the data files are unavailable."""
    path = (directory or default_data_dir()).resolve()
    try:
        return _cached(str(path))
    except KnowledgeBaseError as error:
        _log.warning("risk_knowledge_base_unavailable", reason=str(error)[:300])
        return None
