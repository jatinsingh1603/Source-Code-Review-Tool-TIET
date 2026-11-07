"""The bundled, versioned public-name allowlist that the identifier classifier reads (E09-02).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

``PublicAllowlist.bundled(language, extra=...)`` loads the versioned data file of the language
(``data/python.toml``; ``data/javascript.toml``, which TypeScript shares) and combines it with the
keywords and builtins of the language's ``LanguageSpec`` (E07-01) and with the names the user put
in ``privacy.public_allowlist_extra``. It is built once per scan into frozen sets and a
name-to-packages mapping, so the classifier answers every question with a set lookup and never
with a regular expression or a file read.

**Extra names only add.** ``extra`` adds names to the public set and nothing else. No operation
removes a bundled name, a keyword or a builtin, so no configuration can turn a bundled internal
default into a client-visible name by subtraction. Adding a name is a deliberate disclosure: it
is recorded by ``version()`` (the count of extra names, never the names) and the names it adds are
listed in ``kept_public_names()`` of the classification result for each payload.

**Versions.** ``version()`` returns the data file's version. When extra names are present it
appends ``+extra<count>``, so the payload provenance shows that the set was changed without the
changed names themselves entering the provenance.

Invariant I6 applies to this module's output: a bundled name is public because it is part of a
published interface (a keyword, a documented API, a framework contract), never because it was
seen in client code. The data files are the only source of such names.
"""

import importlib.resources
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Final, Self

from codekavach.core.models import Language
from codekavach.parsing.spec import REGISTRY

if TYPE_CHECKING:
    from codekavach.config import Settings

DATA_PACKAGE: Final = "codekavach.privacy.pseudonymise.data"
_DATA_FILES: Final[Mapping[Language, str]] = {
    Language.PYTHON: "python.toml",
    Language.JAVASCRIPT: "javascript.toml",
    Language.TYPESCRIPT: "javascript.toml",
}
_PACKAGE_KINDS: Final = frozenset({"stdlib", "third_party", "pseudo", "builtin"})
_MAGIC_MIN_LENGTH: Final = 5  # "__x__" is the shortest dunder name


class NoAllowlistError(LookupError):
    """No bundled allowlist exists for this language, so nothing can be classified as public."""

    def __init__(self, language: Language) -> None:
        self.language = language
        super().__init__(f"no public-name allowlist is bundled for {language.value!r}")


class AllowlistDataError(ValueError):
    """A bundled allowlist file is malformed. This is a build defect, never a client input."""


@dataclass(frozen=True, slots=True)
class PackageSurface:
    """The members of one package and what kind of package it is."""

    kind: str
    members: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Bundle:
    """The parsed content of one data file. Immutable, shared by every allowlist of a language."""

    version: str
    packages: Mapping[str, PackageSurface]
    contracts: frozenset[str]
    decorators: Mapping[str, str]
    well_known: frozenset[str]
    attribute_calls: frozenset[str]
    reflect_objects: Mapping[str, frozenset[str]]
    dynamic_code: frozenset[str]


def _strings(table: Mapping[str, object], key: str, where: str) -> tuple[str, ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AllowlistDataError(f"{where}.{key} must be a list of strings")
    return tuple(value)


def _parse_bundle(text: str, filename: str, language: Language) -> _Bundle:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise AllowlistDataError(f"{filename}: {error}") from None
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise AllowlistDataError(f"{filename}: version is missing")
    if data.get("language") != language.value and language is not Language.TYPESCRIPT:
        raise AllowlistDataError(f"{filename}: language does not match {language.value}")

    packages: dict[str, PackageSurface] = {}
    raw_packages = data.get("packages", {})
    if not isinstance(raw_packages, dict):
        raise AllowlistDataError(f"{filename}: [packages] must be a table")
    for name, table in raw_packages.items():
        if not isinstance(table, dict):
            raise AllowlistDataError(f"{filename}: [packages.{name}] must be a table")
        kind = table.get("kind")
        if kind not in _PACKAGE_KINDS:
            raise AllowlistDataError(f"{filename}: [packages.{name}] has an unknown kind")
        members = frozenset(_strings(table, "members", f"{filename}:packages.{name}"))
        packages[name] = PackageSurface(kind=str(kind), members=members)

    contracts = data.get("framework_contracts", {})
    decorators = data.get("framework_decorators", {})
    well_known = data.get("well_known", {})
    reflection = data.get("reflection", {})
    dynamic = data.get("dynamic_code", {})
    if not all(
        isinstance(t, dict) for t in (contracts, decorators, well_known, reflection, dynamic)
    ):
        raise AllowlistDataError(f"{filename}: a section is not a table")
    reflect_objects = reflection.get("reflect_objects", {})
    if not isinstance(reflect_objects, dict):
        raise AllowlistDataError(f"{filename}: reflection.reflect_objects must be a table")
    well_names: set[str] = set()
    for key in ("sources", "sinks", "sanitisers", "conventional_instances"):
        well_names.update(_strings(well_known, key, f"{filename}:well_known"))
    return _Bundle(
        version=version,
        packages=packages,
        contracts=frozenset(contracts),
        decorators=dict(decorators),
        well_known=frozenset(well_names),
        attribute_calls=frozenset(
            _strings(reflection, "attribute_calls", f"{filename}:reflection")
        ),
        reflect_objects={base: frozenset(names) for base, names in reflect_objects.items()},
        dynamic_code=frozenset(_strings(dynamic, "calls", f"{filename}:dynamic_code")),
    )


@cache
def _load(filename: str, language: Language) -> _Bundle:
    text = (importlib.resources.files(DATA_PACKAGE) / filename).read_text(encoding="utf-8")
    return _parse_bundle(text, filename, language)


def _is_magic(name: str) -> bool:
    return len(name) >= _MAGIC_MIN_LENGTH and name.startswith("__") and name.endswith("__")


class PublicAllowlist:
    """The public names of one language: bundled data, language keywords, and extra names.

    Construct it with ``bundled`` or ``from_settings``. A value of this class is immutable in
    everything a caller can observe, so one instance can serve every file of a scan.
    """

    __slots__ = ("_bundle", "_extra", "_keywords", "_language", "_listed_in", "_scoped")

    def __init__(self, language: Language, bundle: _Bundle, extra: frozenset[str]) -> None:
        self._language = language
        self._bundle = bundle
        self._extra = extra
        spec = REGISTRY.get(language)
        self._keywords: frozenset[str] = frozenset(spec.keywords) | frozenset(spec.builtins)
        listed: dict[str, set[str]] = {}
        for package, surface in bundle.packages.items():
            for member in surface.members:
                listed.setdefault(member, set()).add(package)
        self._listed_in: Mapping[str, tuple[str, ...]] = {
            member: tuple(sorted(packages)) for member, packages in listed.items()
        }
        self._scoped: dict[frozenset[str], Mapping[str, tuple[str, ...]]] = {}

    def listing_for(self, packages: frozenset[str]) -> Mapping[str, tuple[str, ...]]:
        """Member name to the sorted packages of ``packages`` that list it, computed once per set.

        A file's scope is the set of packages it imports, so the same few sets recur across the
        files of a scan and the mapping is built once for each.
        """
        cached = self._scoped.get(packages)
        if cached is None:
            listing: dict[str, set[str]] = {}
            for package in packages:
                for member in self.members_of(package):
                    listing.setdefault(member, set()).add(package)
            cached = {member: tuple(sorted(names)) for member, names in listing.items()}
            self._scoped[packages] = cached
        return cached

    @classmethod
    def bundled(cls, language: Language, *, extra: Iterable[str] = ()) -> Self:
        """The allowlist of ``language`` plus ``extra`` names.

        Raises:
            NoAllowlistError: no data file is bundled for ``language``.
        """
        filename = _DATA_FILES.get(language)
        if filename is None:
            raise NoAllowlistError(language)
        return cls(language, _load(filename, language), frozenset(extra))

    @classmethod
    def from_settings(cls, language: Language, settings: "Settings") -> Self:
        """The allowlist of ``language`` plus ``privacy.public_allowlist_extra`` from settings."""
        return cls.bundled(language, extra=settings.privacy.public_allowlist_extra)

    @property
    def language(self) -> Language:
        """The language this allowlist is for."""
        return self._language

    def version(self) -> str:
        """The bundled data version, with ``+extra<count>`` when extra names were added."""
        if not self._extra:
            return self._bundle.version
        return f"{self._bundle.version}+extra{len(self._extra)}"

    def is_keyword_or_builtin(self, name: str) -> bool:
        """Whether ``name`` is a reserved word, a soft keyword or a builtin of the language."""
        return name in self._keywords

    def is_magic(self, name: str) -> bool:
        """Whether ``name`` is a dunder (magic) name, such as ``__init__``."""
        return _is_magic(name)

    def is_extra(self, name: str) -> bool:
        """Whether ``name`` was added by the user's ``public_allowlist_extra``."""
        return name in self._extra

    def is_framework_contract(self, name: str) -> bool:
        """Whether ``name`` is a framework method name that a client class overrides."""
        return name in self._bundle.contracts

    def decorator_package(self, name: str) -> str | None:
        """The framework that owns the decorator ``name``, or ``None``."""
        return self._bundle.decorators.get(name)

    def is_well_known(self, name: str) -> bool:
        """Whether ``name`` is a well-known source, sink, sanitiser or instance name."""
        return name in self._bundle.well_known

    def is_public_module(self, top: str) -> bool:
        """Whether a third-party module, by its top-level name, is on the allowlist."""
        surface = self._bundle.packages.get(top)
        return surface is not None and surface.kind == "third_party"

    def package_names(self) -> frozenset[str]:
        """Every package name in the bundled data, of any kind."""
        return frozenset(self._bundle.packages)

    def kind_of(self, package: str) -> str | None:
        """The kind of ``package`` (stdlib, third_party, pseudo or builtin), or None."""
        surface = self._bundle.packages.get(package)
        return None if surface is None else surface.kind

    def members_of(self, package: str) -> frozenset[str]:
        """The member names listed for ``package``; empty when the package is not listed."""
        surface = self._bundle.packages.get(package)
        return frozenset() if surface is None else surface.members

    def packages_listing(self, name: str) -> tuple[str, ...]:
        """The packages whose member lists contain ``name``, sorted; empty when none does."""
        return self._listed_in.get(name, ())

    def is_listed_member(self, name: str) -> bool:
        """Whether ``name`` is a member of at least one listed package."""
        return name in self._listed_in

    def is_attribute_call(self, name: str) -> bool:
        """Whether ``name`` is a reflection call that takes an attribute name (``getattr``)."""
        return name in self._bundle.attribute_calls

    def is_reflection_method(self, base: str, name: str) -> bool:
        """Whether ``base.name`` is a reflection method that takes a property name second."""
        return name in self._bundle.reflect_objects.get(base, frozenset())

    def reflection_triggers(self) -> frozenset[str]:
        """The names that make a file's string arguments reflective.

        These are the attribute calls (``getattr``) and the bases of reflection objects
        (``Reflect``).
        """
        return self._bundle.attribute_calls | frozenset(self._bundle.reflect_objects)

    def is_dynamic_code_call(self, name: str) -> bool:
        """Whether ``name`` is a call that executes text, such as ``eval``."""
        return name in self._bundle.dynamic_code


__all__ = [
    "DATA_PACKAGE",
    "AllowlistDataError",
    "NoAllowlistError",
    "PackageSurface",
    "PublicAllowlist",
]
