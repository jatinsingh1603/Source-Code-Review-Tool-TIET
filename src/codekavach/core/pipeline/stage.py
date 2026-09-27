"""The Stage protocol of ARCHITECTURE section 4 and the metadata the pipeline reads from it.

Owning epic: E04.

A stage only has to declare ``name``, ``requires``, ``provides`` and ``run``. Everything else is
optional and read by ``describe_stage`` with defaults taken from ``CATEGORY_DEFAULTS``. The defaults
table is a privacy control: an untagged stage fails closed, is not cached and is treated as salt
dependent, and a privacy, LLM or restore stage cannot declare its way out of that (I4, I5).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from codekavach.core.pipeline.errors import StageDeclarationError

if TYPE_CHECKING:
    from codekavach.core.pipeline.context import RunContext

PLUGIN_API = 1
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
MAX_KEY_LENGTH = 64


@runtime_checkable
class Stage(Protocol):
    """One step of a scan. ``isinstance`` is only a cheap pre-check; use ``describe_stage``."""

    name: str
    requires: frozenset[str]
    provides: frozenset[str]

    def run(self, ctx: "RunContext") -> None:
        """Read ``requires`` from the context's store and write ``provides`` to it."""


class StageCategory(StrEnum):
    """What a stage does; values equal the default stage names of ARCHITECTURE section 4."""

    INGEST = "ingest"
    PARSE = "parse"
    ANALYSE = "analyse"
    AGGREGATE = "aggregate"
    PRIVACY = "privacy-prepare"
    LLM = "llm-review"
    RESTORE = "restore"
    RATE = "rate"
    REPORT = "report"
    SYNC = "sync"


class FailurePolicy(StrEnum):
    """What the orchestrator does when a stage fails (E04-15)."""

    ABORT_SCAN = "abort_scan"
    FAIL_CLOSED = "fail_closed"
    DEGRADE = "degrade"


# (failure_policy, cacheable, salt_dependent) per category; ``None`` is an untagged stage.
CATEGORY_DEFAULTS: Mapping[StageCategory | None, tuple[FailurePolicy, bool, bool]] = (
    MappingProxyType(
        {
            StageCategory.INGEST: (FailurePolicy.ABORT_SCAN, False, False),
            StageCategory.PARSE: (FailurePolicy.DEGRADE, True, False),
            StageCategory.ANALYSE: (FailurePolicy.DEGRADE, True, False),
            StageCategory.AGGREGATE: (FailurePolicy.ABORT_SCAN, True, False),
            StageCategory.PRIVACY: (FailurePolicy.FAIL_CLOSED, False, True),
            StageCategory.LLM: (FailurePolicy.FAIL_CLOSED, False, True),
            StageCategory.RESTORE: (FailurePolicy.FAIL_CLOSED, False, True),
            StageCategory.RATE: (FailurePolicy.DEGRADE, True, False),
            StageCategory.REPORT: (FailurePolicy.DEGRADE, False, False),
            StageCategory.SYNC: (FailurePolicy.DEGRADE, False, False),
            None: (FailurePolicy.FAIL_CLOSED, False, True),
        }
    )
)
_PROTECTED = frozenset({StageCategory.PRIVACY, StageCategory.LLM, StageCategory.RESTORE, None})
_NEVER_CACHED = frozenset({StageCategory.SYNC, StageCategory.INGEST})
_STRICT_POLICIES = frozenset({FailurePolicy.FAIL_CLOSED, FailurePolicy.ABORT_SCAN})


@dataclass(frozen=True, slots=True)
class StageInfo:
    """Everything the pipeline knows about one stage."""

    name: str
    requires: frozenset[str]
    provides: frozenset[str]
    version: str = "0"
    category: StageCategory | None = None
    optional_requires: frozenset[str] = frozenset()
    failure_policy: FailurePolicy = FailurePolicy.FAIL_CLOSED
    cacheable: bool = False
    salt_dependent: bool = True
    parallel_safe: bool = True
    timeout_seconds: int | None = None
    transient_provides: frozenset[str] = frozenset()
    config_sections: tuple[str, ...] | None = None
    plugin_api: int = PLUGIN_API
    origin: str | None = None


def _key_set(stage: str, attribute: str, value: object) -> frozenset[str]:
    if not isinstance(value, frozenset) or not all(isinstance(key, str) for key in value):
        raise StageDeclarationError(stage, f"{attribute} must be a frozenset of str")
    for key in value:
        if len(key) > MAX_KEY_LENGTH or not KEY_PATTERN.match(key):
            raise StageDeclarationError(stage, f"{attribute} contains an invalid key {key!r}")
    return frozenset(str(key) for key in value)


def _typed[T](stage: str, attribute: str, value: object, kind: type[T]) -> T | None:
    if value is None:
        return None
    if not isinstance(value, kind) or (kind is not bool and isinstance(value, bool)):
        raise StageDeclarationError(stage, f"{attribute} must be a {kind.__name__} or None")
    return value


def _check_weakening(
    name: str,
    category: StageCategory | None,
    policy: FailurePolicy | None,
    cacheable: bool | None,
    salt_dependent: bool | None,
) -> None:
    """Rule 4: protected categories keep fail-closed, uncached, salt-dependent defaults."""
    if category in _PROTECTED:
        if policy is not None and policy not in _STRICT_POLICIES:
            raise StageDeclarationError(
                name, f"failure_policy {policy} would weaken the fail-closed default"
            )
        if cacheable is True:
            raise StageDeclarationError(name, "cacheable = True would weaken the default")
        if salt_dependent is False:
            raise StageDeclarationError(name, "salt_dependent = False would weaken the default")
    if category in _NEVER_CACHED and cacheable is True:
        raise StageDeclarationError(name, f"cacheable = True is not allowed for {category}")


def _check_key_sets(
    name: str,
    requires: frozenset[str],
    provides: frozenset[str],
    optional: frozenset[str],
    transient: frozenset[str],
) -> None:
    """Rule 2: non-empty provides, disjoint sets, transient keys among provides."""
    if not provides:
        raise StageDeclarationError(name, "provides must not be empty")
    for left, right, label in (
        (requires, provides, "requires and provides"),
        (requires, optional, "requires and optional_requires"),
        (optional, provides, "optional_requires and provides"),
    ):
        if left & right:
            raise StageDeclarationError(name, f"{label} overlap")
    if not transient <= provides:
        raise StageDeclarationError(name, "transient_provides must be a subset of provides")


def describe_stage(stage: object, *, origin: str | None = None) -> StageInfo:
    """Validate ``stage`` and return its metadata with category defaults applied.

    Raises:
        StageDeclarationError: the declaration breaks a rule; the message names the stage and the
            attribute.
    """
    name = getattr(stage, "name", None)
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        raise StageDeclarationError(str(name), "name must match ^[a-z][a-z0-9-]{0,47}$")
    requires = _key_set(name, "requires", getattr(stage, "requires", None))
    provides = _key_set(name, "provides", getattr(stage, "provides", None))
    optional = _key_set(name, "optional_requires", getattr(stage, "optional_requires", frozenset()))
    transient = _key_set(
        name, "transient_provides", getattr(stage, "transient_provides", frozenset())
    )
    _check_key_sets(name, requires, provides, optional, transient)
    if not callable(getattr(stage, "run", None)):
        raise StageDeclarationError(name, "run must be callable")

    plugin_api = getattr(stage, "plugin_api", PLUGIN_API)
    if plugin_api != PLUGIN_API:
        raise StageDeclarationError(
            name, f"targets plugin API {plugin_api}; this CodeKavach supports {PLUGIN_API}"
        )
    version = getattr(stage, "version", "0")
    if not isinstance(version, str) or not VERSION_PATTERN.match(version):
        raise StageDeclarationError(name, "version must be 1 to 32 characters of [A-Za-z0-9._-]")
    category = _typed(name, "category", getattr(stage, "category", None), StageCategory)
    policy = _typed(name, "failure_policy", getattr(stage, "failure_policy", None), FailurePolicy)
    cacheable = _typed(name, "cacheable", getattr(stage, "cacheable", None), bool)
    salt_dependent = _typed(name, "salt_dependent", getattr(stage, "salt_dependent", None), bool)
    parallel_safe = _typed(name, "parallel_safe", getattr(stage, "parallel_safe", True), bool)
    timeout = _typed(name, "timeout_seconds", getattr(stage, "timeout_seconds", None), int)
    if timeout is not None and timeout <= 0:
        raise StageDeclarationError(name, "timeout_seconds must be positive")
    sections = _typed(name, "config_sections", getattr(stage, "config_sections", None), tuple)
    if sections is not None and not all(isinstance(item, str) for item in sections):
        raise StageDeclarationError(name, "config_sections must be a tuple of str")

    _check_weakening(name, category, policy, cacheable, salt_dependent)

    default_policy, default_cacheable, default_salt = CATEGORY_DEFAULTS[category]
    return StageInfo(
        name=name,
        requires=requires,
        provides=provides,
        version=version,
        category=category,
        optional_requires=optional,
        failure_policy=default_policy if policy is None else policy,
        cacheable=False if transient else (default_cacheable if cacheable is None else cacheable),
        salt_dependent=default_salt if salt_dependent is None else salt_dependent,
        parallel_safe=True if parallel_safe is None else parallel_safe,
        timeout_seconds=timeout,
        transient_provides=transient,
        config_sections=tuple(str(item) for item in sections) if sections is not None else None,
        plugin_api=PLUGIN_API,
        origin=origin,
    )
