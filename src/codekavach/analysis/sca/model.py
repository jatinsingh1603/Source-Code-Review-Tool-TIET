"""Dependency inventory models (E19-01).

``Dependency`` is one resolved component; ``DependencyGraph`` the inventory with its edges. Both
carry raw client data (a private package name describes the architecture), so they are never
sent to a model and travel only through raw-data artefacts.
"""

from typing import ClassVar
from urllib.parse import quote

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel

ECOSYSTEMS = ("PyPI", "npm", "Maven", "Go", "RubyGems", "Packagist", "crates.io")
_PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Maven": "maven",
    "Go": "golang",
    "RubyGems": "gem",
    "Packagist": "composer",
    "crates.io": "cargo",
}


def make_purl(ecosystem: str, name: str, version: str) -> str:
    """The package URL of a component (https://github.com/package-url/purl-spec)."""
    kind = _PURL_TYPE.get(ecosystem, "generic")
    if ecosystem == "Maven" and ":" in name:
        group, artefact = name.split(":", 1)
        base = f"pkg:maven/{quote(group)}/{quote(artefact)}"
    elif ecosystem == "npm" and name.startswith("@"):
        scope, _, rest = name.partition("/")
        base = f"pkg:npm/{quote(scope)}/{quote(rest)}"
    elif ecosystem == "PyPI":
        base = f"pkg:pypi/{quote(name.lower().replace('_', '-'))}"
    else:
        base = f"pkg:{kind}/{quote(name, safe='/')}"
    return f"{base}@{quote(version)}" if version else base


class Dependency(KavachModel):
    """One component of the application at a resolved (or declared) version."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    purl: str
    name: str
    version: str
    ecosystem: str
    direct: bool = False
    scope: str = "runtime"
    declared_range: str | None = None
    resolved_from: str
    line: int = Field(default=1, ge=1)
    locations: tuple[str, ...] = ()
    licence_ids: tuple[str, ...] = ()
    is_internal: bool = False
    integrity: str | None = None
    requires: tuple[str, ...] = ()


class DependencyGraph(KavachModel):
    """The inventory of a scan: components and the edges between them."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    dependencies: tuple[Dependency, ...] = ()
    edges: tuple[tuple[str, str], ...] = ()
    manifests: tuple[str, ...] = ()

    @property
    def by_purl(self) -> dict[str, Dependency]:
        """Components keyed by package URL."""
        return {d.purl: d for d in self.dependencies}
