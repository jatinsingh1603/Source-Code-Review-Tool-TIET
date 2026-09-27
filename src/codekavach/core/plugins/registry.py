"""The plugin registry: lazy, defensive, deterministic loading of discovered plugins.

Owning epic: E04.

The core never imports a concrete stage; it asks this registry. CodeKavach's own stages use the
same mechanism, one line per stage in ``pyproject.toml``::

    [project.entry-points."codekavach.stages"]
    ingest = "codekavach.ingest.stage:IngestStage"

Loading an entry point executes code from an installed distribution. Installed distributions are
trusted (CodeKavach installs nothing itself), but a broken plugin must not take the tool down: any
``Exception`` while importing, creating or validating a plugin becomes a ``PluginFailure`` that
records the exception class name only (import errors can contain local paths) and the plugin is
left out. ``BaseException`` subclasses such as ``KeyboardInterrupt`` and ``SystemExit`` propagate,
so a plugin that calls ``sys.exit()`` at import time is fatal by design.

Name collisions within a group are resolved deterministically: the ``codekavach`` distribution
wins, otherwise the alphabetically first distribution name; the others are reported as shadowed.
"""

import importlib.metadata
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Literal, cast

from codekavach.core.log import get_logger
from codekavach.core.pipeline.stage import Stage, StageInfo, describe_stage
from codekavach.core.plugins.discovery import GROUPS, PluginSpec, discover

STAGES_GROUP = "codekavach.stages"
CORE_DIST = "codekavach"
FailureStage = Literal["import", "create", "validate"]
Status = Literal["ok", "error", "shadowed", "disabled"]
GroupValidator = Callable[[object], None]

_log = get_logger("codekavach.plugins")
_GROUP_VALIDATORS: dict[str, GroupValidator] = {}


def register_group_validator(group: str, fn: GroupValidator) -> None:
    """Validate every plugin of ``group`` with ``fn`` (raise to reject); owning epics call this."""
    _GROUP_VALIDATORS[group] = fn


@dataclass(frozen=True, slots=True)
class PluginFailure:
    """Why one plugin was left out; ``error_type`` is an exception class name."""

    spec: PluginSpec
    stage: FailureStage
    error_type: str


@dataclass(frozen=True, slots=True)
class PluginRow:
    """One line of a plugin listing; every field is JSON-safe."""

    group: str
    kind: str
    name: str
    target: str
    dist: str
    version: str
    status: Status
    error_type: str | None = None
    category: str | None = None
    requires: list[str] = field(default_factory=list)
    optional_requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)


def kind_of(group: str) -> str:
    """``codekavach.stages`` gives ``stage``."""
    return group.removeprefix("codekavach.").removesuffix("s")


def _rank(spec: PluginSpec) -> tuple[bool, str, str]:
    return (spec.dist_name != CORE_DIST, spec.dist_name, spec.target)


class PluginRegistry:
    """Discovered plugins, loaded on first use and cached."""

    def __init__(
        self,
        specs: Iterable[PluginSpec],
        *,
        validators: dict[str, GroupValidator] | None = None,
    ) -> None:
        candidates: dict[tuple[str, str], list[PluginSpec]] = {}
        for spec in specs:
            candidates.setdefault((spec.group, spec.name), []).append(spec)
        self._winners: dict[tuple[str, str], PluginSpec] = {}
        shadowed: list[PluginSpec] = []
        for key, found in candidates.items():
            ordered = sorted(found, key=_rank)
            self._winners[key] = ordered[0]
            shadowed.extend(ordered[1:])
        self._shadowed = tuple(sorted(shadowed, key=lambda s: (s.group, s.name, s.dist_name)))
        self._validators = dict(_GROUP_VALIDATORS if validators is None else validators)
        self._lock = threading.RLock()
        self._instances: dict[tuple[str, str], object] = {}
        self._infos: dict[str, StageInfo] = {}
        self._failures: dict[tuple[str, str], PluginFailure] = {}

    def _fail(self, spec: PluginSpec, stage: FailureStage, error: Exception) -> None:
        self._failures[(spec.group, spec.name)] = PluginFailure(spec, stage, type(error).__name__)
        _log.debug(
            "plugin_load_failed",
            group=spec.group,
            plugin=spec.name,
            dist=spec.dist_name,
            failure_stage=stage,
            error_type=type(error).__name__,
            exc_info=True,
        )

    def _load(self, spec: PluginSpec) -> None:
        key = (spec.group, spec.name)
        entry_point = importlib.metadata.EntryPoint(
            name=spec.name, value=spec.target, group=spec.group
        )
        try:
            factory = entry_point.load()
        except Exception as error:  # noqa: BLE001 - a broken plugin must not stop the tool
            self._fail(spec, "import", error)
            return
        try:
            if not callable(factory):
                raise TypeError("entry point does not name a callable")
            instance = factory()
        except Exception as error:  # noqa: BLE001
            self._fail(spec, "create", error)
            return
        try:
            if spec.group == STAGES_GROUP:
                info = describe_stage(instance, origin=f"{spec.dist_name}=={spec.dist_version}")
                if info.name != spec.name:
                    raise ValueError("stage name differs from its entry-point name")
                self._infos[spec.name] = info
            elif spec.group in self._validators:
                self._validators[spec.group](instance)
        except Exception as error:  # noqa: BLE001
            self._fail(spec, "validate", error)
            return
        self._instances[key] = instance

    def _ensure(self, key: tuple[str, str]) -> None:
        with self._lock:
            if key in self._instances or key in self._failures:
                return
            spec = self._winners.get(key)
            if spec is not None:
                self._load(spec)

    def _ensure_all(self, group: str | None = None) -> None:
        for key in sorted(self._winners):
            if group is None or key[0] == group:
                self._ensure(key)

    def get(self, group: str, name: str) -> object:
        """The plugin instance; ``KeyError`` when unknown or failed."""
        self._ensure((group, name))
        with self._lock:
            return self._instances[(group, name)]

    def all(self, group: str) -> dict[str, object]:
        """Every loadable plugin of ``group``, by name."""
        self._ensure_all(group)
        with self._lock:
            return {
                name: instance
                for (plugin_group, name), instance in sorted(self._instances.items())
                if plugin_group == group
            }

    def stages(self) -> dict[str, Stage]:
        """Every valid stage, by name."""
        return cast("dict[str, Stage]", self.all(STAGES_GROUP))

    def languages(self) -> dict[str, object]:
        """Language plugins."""
        return self.all("codekavach.languages")

    def engines(self) -> dict[str, object]:
        """Engine plugins."""
        return self.all("codekavach.engines")

    def detectors(self) -> dict[str, object]:
        """Detector plugins."""
        return self.all("codekavach.detectors")

    def providers(self) -> dict[str, object]:
        """LLM provider plugins."""
        return self.all("codekavach.providers")

    def renderers(self) -> dict[str, object]:
        """Report renderer plugins."""
        return self.all("codekavach.renderers")

    def stage_infos(self) -> dict[str, StageInfo]:
        """Metadata of every valid stage, by name."""
        self._ensure_all(STAGES_GROUP)
        with self._lock:
            return dict(sorted(self._infos.items()))

    def failures(self) -> tuple[PluginFailure, ...]:
        """Plugins that failed to import, create or validate (loads every plugin)."""
        self._ensure_all()
        with self._lock:
            return tuple(self._failures[key] for key in sorted(self._failures))

    def shadowed(self) -> tuple[PluginSpec, ...]:
        """Entry points that lost a name collision."""
        return self._shadowed

    def _row(self, spec: PluginSpec, status: Status, error_type: str | None) -> PluginRow:
        info = self._infos.get(spec.name) if spec.group == STAGES_GROUP else None
        if status != "ok":
            info = None
        return PluginRow(
            group=spec.group,
            kind=kind_of(spec.group),
            name=spec.name,
            target=spec.target,
            dist=spec.dist_name,
            version=spec.dist_version,
            status=status,
            error_type=error_type,
            category=info.category.value if info and info.category else None,
            requires=sorted(info.requires) if info else [],
            optional_requires=sorted(info.optional_requires) if info else [],
            provides=sorted(info.provides) if info else [],
        )

    def rows(self) -> list[PluginRow]:
        """One row per entry point (winners and shadowed), sorted by (group, name, dist)."""
        self._ensure_all()
        rows: list[PluginRow] = []
        with self._lock:
            for key, spec in self._winners.items():
                failure = self._failures.get(key)
                if failure is None:
                    rows.append(self._row(spec, "ok", None))
                else:
                    rows.append(self._row(spec, "error", failure.error_type))
        rows.extend(self._row(spec, "shadowed", None) for spec in self._shadowed)
        return sorted(rows, key=lambda row: (row.group, row.name, row.dist))


def registry_from_environment() -> PluginRegistry:
    """A registry over every plugin installed in the running environment."""
    return PluginRegistry(discover(GROUPS))
