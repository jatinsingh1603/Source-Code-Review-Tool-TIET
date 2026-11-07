"""Loader for the KavachBank ground-truth manifest (E13-01).

The manifest says what is planted in ``fixtures/kavachbank`` and where. It never contains a
credential: a secret or an identifier is named by a ``value_ref`` that resolves, through this
module, to a constant of ``tests/support/synthetic.py``, so each synthetic value lives in exactly
one place (AGENTS.md section 3) and ``tools/gen_terms.py`` derives the terms file from the same
references.

``value_ref`` is either the name of a module-level string constant of ``synthetic.py``
(``AWS_EXAMPLE_ACCESS_KEY_ID``) or ``<kind>:<subtype>[:<index>]`` with ``kind`` one of ``secret``,
``pii`` or ``term``: the ``index``-th entry of that table with that subtype (default 0).

This module belongs to the test support tree and is not part of the shipped package.
"""

from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError

from tests.support import synthetic

SCHEMA_VERSION: Final = 1
FIXTURE_ROOT: Final = Path(__file__).resolve().parents[2] / "fixtures" / "kavachbank"
MANIFEST_PATH: Final = FIXTURE_ROOT / "ground-truth" / "manifest.yaml"
NEGATIVE_CONTROLS_PATH: Final = FIXTURE_ROOT / "ground-truth" / "negative_controls.yaml"
TERMS_PATH: Final = FIXTURE_ROOT / "ground-truth" / "terms.txt"

_KINDS: Final = ("secret", "pii", "term")


class ManifestError(ValueError):
    """The manifest is malformed or does not match the fixture tree."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Application(_Strict):
    """What the fixture application is."""

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    services: tuple[str, ...] = Field(min_length=1)


class PlantedVulnerability(_Strict):
    """One planted weakness. ``line`` is 1-based and names the line a finding should point at."""

    id: str = Field(pattern=r"^KB-VULN-\d{3}$")
    cwe: StrictInt = Field(ge=1)
    vuln_class: str = Field(alias="class", min_length=1)
    file: str = Field(min_length=1)
    line: StrictInt = Field(ge=1)
    demo_1: StrictBool


class PlantedSecret(_Strict):
    """One planted secret, named by the synthetic constant that holds its value."""

    id: str = Field(pattern=r"^KB-SEC-\d{3}$")
    subtype: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: StrictInt = Field(ge=1)
    value_ref: str = Field(min_length=1)


class PlantedPii(_Strict):
    """One planted personal-data value, named by the synthetic constant that holds it."""

    id: str = Field(pattern=r"^KB-PII-\d{3}$")
    subtype: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: StrictInt = Field(ge=1)
    value_ref: str = Field(min_length=1)


class NegativeControl(_Strict):
    """The safe counterpart of a planted weakness: nothing may be reported at ``line``."""

    id: str = Field(pattern=r"^KB-SAFE-\d{3}$")
    vuln_class: str = Field(alias="class", min_length=1)
    file: str = Field(min_length=1)
    line: StrictInt = Field(ge=1)


class Manifest(_Strict):
    """The ground truth of the fixture."""

    schema_version: Literal[1]
    application: Application
    planted_vulnerabilities: tuple[PlantedVulnerability, ...]
    planted_secrets: tuple[PlantedSecret, ...]
    planted_pii: tuple[PlantedPii, ...]
    business_domain_dictionary: tuple[str, ...]

    def demo_1_vulnerabilities(self) -> tuple[PlantedVulnerability, ...]:
        """The weaknesses the Demo 1 candidate pass must find."""
        return tuple(item for item in self.planted_vulnerabilities if item.demo_1)


def resolve_value_ref(value_ref: str) -> str:
    """The synthetic value that ``value_ref`` names.

    Raises:
        ManifestError: the reference does not name a synthetic value.
    """
    kind, _, rest = value_ref.partition(":")
    if kind not in _KINDS or not rest:
        constant = getattr(synthetic, value_ref, None)
        if not isinstance(constant, str) or not value_ref.isidentifier():
            raise ManifestError(f"value_ref {value_ref!r} does not name a synthetic constant")
        return constant
    subtype, _, index_text = rest.partition(":")
    try:
        return synthetic.synthetic_value(kind, subtype, int(index_text) if index_text else 0)
    except (IndexError, KeyError, ValueError) as error:
        raise ManifestError(f"value_ref {value_ref!r} does not name a synthetic value") from error


def _read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ManifestError(f"{path.name} cannot be read: {error}") from error


def _lines_of(root: Path, relative: str) -> list[str]:
    path = (root / relative).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        raise ManifestError(f"{relative} is not a file of the fixture")
    return path.read_text(encoding="utf-8").split("\n")


def _check_position(root: Path, file: str, line: int, item: str) -> list[str]:
    lines = _lines_of(root, file)
    if line > len(lines):
        raise ManifestError(f"{item}: {file} has no line {line}")
    return lines


def _check_value_on_line(root: Path, item: PlantedSecret | PlantedPii) -> None:
    lines = _check_position(root, item.file, item.line, item.id)
    first_line = resolve_value_ref(item.value_ref).split("\n")[0]
    if first_line not in lines[item.line - 1]:
        raise ManifestError(f"{item.id}: {item.file} line {item.line} does not hold its value")


def _check_unique(manifest: Manifest) -> None:
    ids = [
        entry.id
        for group in (
            manifest.planted_vulnerabilities,
            manifest.planted_secrets,
            manifest.planted_pii,
        )
        for entry in group
    ]
    if len(set(ids)) != len(ids):
        raise ManifestError("manifest ids must be unique")


def load_manifest(path: Path = MANIFEST_PATH, *, root: Path = FIXTURE_ROOT) -> Manifest:
    """Read and validate the manifest.

    Every referenced file and line must exist under ``root``, and every ``value_ref`` must resolve
    to a synthetic value that is present on its line.

    Raises:
        ManifestError: the file is malformed, a reference does not resolve or a line is missing.
    """
    data = _read_yaml(path)
    if not isinstance(data, dict):
        raise ManifestError("the manifest must be a mapping")
    try:
        manifest = Manifest.model_validate(data)
    except ValidationError as error:
        raise ManifestError(f"the manifest does not match its schema: {error}") from error
    _check_unique(manifest)
    for vulnerability in manifest.planted_vulnerabilities:
        _check_position(root, vulnerability.file, vulnerability.line, vulnerability.id)
    valued: tuple[PlantedSecret | PlantedPii, ...] = (
        *manifest.planted_secrets,
        *manifest.planted_pii,
    )
    for item in valued:
        _check_value_on_line(root, item)
    return manifest


def load_negative_controls(
    path: Path = NEGATIVE_CONTROLS_PATH, *, root: Path = FIXTURE_ROOT
) -> tuple[NegativeControl, ...]:
    """Read and validate the negative controls (one safe counterpart per vulnerability class)."""
    data = _read_yaml(path)
    if not isinstance(data, dict) or set(data) != {"schema_version", "negative_controls"}:
        raise ManifestError("negative controls need schema_version and negative_controls")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ManifestError("unsupported negative controls schema_version")
    try:
        controls = tuple(NegativeControl.model_validate(item) for item in data["negative_controls"])
    except (ValidationError, TypeError) as error:
        raise ManifestError(f"the negative controls do not match their schema: {error}") from error
    for control in controls:
        _check_position(root, control.file, control.line, control.id)
    return controls


def terms_for(manifest: Manifest) -> list[str]:
    """The terms of ``terms.txt``: every line of each planted secret, then the dictionary.

    A multi-line secret (a private key block) contributes one term per line, because a terms
    file holds one term per line (E05-18).
    """
    terms: dict[str, None] = {}
    for secret in manifest.planted_secrets:
        for line in resolve_value_ref(secret.value_ref).split("\n"):
            terms.setdefault(line, None)
    for word in manifest.business_domain_dictionary:
        terms.setdefault(word, None)
    return list(terms)
