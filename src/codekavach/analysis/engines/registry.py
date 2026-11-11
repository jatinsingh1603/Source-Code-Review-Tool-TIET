"""The engine registry and the rules that decide which engines run (E14-01).

Owning epic: E14.

**Precedence** (E03-08, implemented verbatim): ``engines.options.<id>.enabled`` beats the
``enabled`` and ``disabled`` lists, and ``disabled`` beats ``enabled``. An empty ``engines.enabled``
means every installed engine applicable to the detected languages whose spec has
``default_enabled``. An id in the settings that no adapter has is reported as a warning, not an
error.

**Gates.** An engine whose licence does not clearly allow scanning proprietary code
(``scans_proprietary_code`` false in the manifest or spec) needs ``licence_attestation`` in its
options; enabling it explicitly without one raises :class:`EngineLicenceBlocked`, and the default
selection leaves it out. An engine with ``hosted_allowed`` false is refused in a hosted deployment,
which the environment marks with ``CODEKAVACH_DEPLOYMENT=hosted``; that refusal has its own reason.

These are the switches for *external* engines only. ``engines.native.*`` govern CodeKavach's own
analysers and are read nowhere here.

Third-party adapters are found through the ``codekavach.engines`` entry-point group with the
allow-list of the ``[plugins]`` section, so a plugin engine is never imported unless the operator
allowed its distribution.
"""

import os
import threading
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass
from typing import Final

from codekavach.analysis.engines.base import EngineAdapter, EngineProbe, EngineSpec
from codekavach.analysis.engines.errors import BlockReason, EngineLicenceBlocked
from codekavach.analysis.engines.manifest import EnginePolicy, ManifestEntry, effective_policy
from codekavach.config import Settings
from codekavach.config.models.engines import EngineOptions
from codekavach.core.log import get_logger
from codekavach.core.models import Language

HOSTED_VARIABLE: Final = "CODEKAVACH_DEPLOYMENT"
HOSTED_VALUE: Final = "hosted"
ATTESTATION_OPTION: Final = "licence_attestation"
_FALSE_WORDS: Final = frozenset({"", "0", "false", "no", "off"})
ENGINES_GROUP: Final = "codekavach.engines"

_log = get_logger("codekavach.analysis.engines.registry")


def is_hosted_deployment(environ: Mapping[str, str] | None = None) -> bool:
    """Whether the environment marks a hosted deployment."""
    source = os.environ if environ is None else environ
    return source.get(HOSTED_VARIABLE, "").strip().lower() == HOSTED_VALUE


def _attested(value: object) -> bool:
    if value is None or isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE_WORDS
    return bool(value)


def _selection(
    spec: EngineSpec, options: EngineOptions | None, enabled: set[str], disabled: set[str]
) -> tuple[bool, bool]:
    """``(selected, explicit)`` by the E03-08 precedence, before language and gate checks."""
    forced = None if options is None else options.enabled
    if forced is not None:
        return forced, forced
    if spec.id in disabled:
        return False, False
    if enabled:
        return spec.id in enabled, spec.id in enabled
    return spec.default_enabled, False


def _block_reason(
    policy: EnginePolicy, options: EngineOptions | None, hosted: bool
) -> BlockReason | None:
    """Why the gates refuse an engine, or ``None``."""
    if hosted and not policy.hosted_allowed:
        return "hosted"
    attestation = None if options is None else options.options.get(ATTESTATION_OPTION)
    if not policy.scans_proprietary_code and not _attested(attestation):
        return "licence_attestation"
    return None


@dataclass(frozen=True, slots=True)
class Resolution:
    """The engines selected for a scan, and what was left out and why."""

    adapters: tuple[EngineAdapter, ...]
    blocked: tuple[tuple[str, EngineLicenceBlocked], ...] = ()
    unknown_ids: tuple[str, ...] = ()


class EngineRegistry:
    """Adapters by engine id."""

    def __init__(self) -> None:
        self._adapters: dict[str, EngineAdapter] = {}
        self._lock = threading.RLock()

    def register(self, adapter: EngineAdapter) -> None:
        """Add ``adapter``; the id must be new."""
        spec = adapter.spec
        if not isinstance(spec, EngineSpec):
            raise TypeError("an engine adapter needs an EngineSpec")
        with self._lock:
            if spec.id in self._adapters:
                raise ValueError(f"engine {spec.id!r} is already registered")
            self._adapters[spec.id] = adapter

    def unregister(self, engine_id: str) -> None:
        """Remove an adapter (used by tests and by plugin reloads); unknown ids are ignored."""
        with self._lock:
            self._adapters.pop(engine_id, None)

    def clear(self) -> None:
        """Remove every adapter."""
        with self._lock:
            self._adapters.clear()

    def get(self, engine_id: str) -> EngineAdapter:
        """The adapter for ``engine_id``; ``KeyError`` when unknown."""
        with self._lock:
            return self._adapters[engine_id]

    def __iter__(self) -> Iterator[EngineAdapter]:
        with self._lock:
            items = [self._adapters[key] for key in sorted(self._adapters)]
        return iter(items)

    def __contains__(self, engine_id: object) -> bool:
        with self._lock:
            return engine_id in self._adapters

    def unknown_ids(self, settings: Settings) -> list[str]:
        """Ids named in ``engines.enabled``, ``disabled`` or ``options`` that have no adapter."""
        engines = settings.engines
        named = {*engines.enabled, *engines.disabled, *engines.options}
        with self._lock:
            return sorted(named - set(self._adapters))

    def resolve(
        self,
        settings: Settings,
        languages: Collection[Language],
        *,
        hosted: bool | None = None,
        probe: Callable[[EngineAdapter], EngineProbe] | None = None,
        manifest: Mapping[str, ManifestEntry] | None = None,
    ) -> Resolution:
        """Select the engines for a scan; blocked engines are listed, not raised."""
        engines = settings.engines
        is_hosted = is_hosted_deployment() if hosted is None else hosted
        wanted = frozenset(languages)
        enabled, disabled = set(engines.enabled), set(engines.disabled)
        unknown = self.unknown_ids(settings)
        for engine_id in unknown:
            _log.warning("engine_unknown_id", engine=engine_id)
        chosen: list[EngineAdapter] = []
        blocked: list[tuple[str, EngineLicenceBlocked]] = []
        for adapter in self:
            spec = adapter.spec
            options = engines.options.get(spec.id)
            selected, explicit = _selection(spec, options, enabled, disabled)
            if not selected or not spec.languages & wanted:
                continue
            reason = _block_reason(effective_policy(spec, manifest), options, is_hosted)
            if reason is not None:
                if explicit or reason == "hosted":
                    blocked.append((spec.id, EngineLicenceBlocked(spec.id, reason)))
                continue
            if not explicit and probe is not None and not probe(adapter).available:
                continue
            chosen.append(adapter)
        return Resolution(tuple(chosen), tuple(blocked), tuple(unknown))

    def resolve_enabled(
        self,
        settings: Settings,
        languages: Collection[Language],
        *,
        hosted: bool | None = None,
        probe: Callable[[EngineAdapter], EngineProbe] | None = None,
        manifest: Mapping[str, ManifestEntry] | None = None,
    ) -> list[EngineAdapter]:
        """The engines to run; raises :class:`EngineLicenceBlocked` for a blocked explicit one."""
        resolution = self.resolve(
            settings, languages, hosted=hosted, probe=probe, manifest=manifest
        )
        if resolution.blocked:
            raise resolution.blocked[0][1]
        return list(resolution.adapters)

    def load_plugins(self, settings: Settings) -> list[str]:
        """Register the allowed third-party adapters; returns the ids added.

        A plugin that fails to load, whose name differs from its spec id, or whose id is taken
        (built-ins win) is left out with a debug log; nothing here raises.
        """
        from codekavach.core.plugins.registry import registry_from_environment  # noqa: PLC0415

        added: list[str] = []
        loaded = registry_from_environment(settings).engines()
        for name, plugin in sorted(loaded.items()):
            spec = getattr(plugin, "spec", None)
            if (
                not isinstance(spec, EngineSpec)
                or spec.id != name
                or not isinstance(plugin, EngineAdapter)
            ):
                _log.debug("engine_plugin_rejected", plugin=name)
                continue
            if spec.id in self:
                continue
            self.register(plugin)
            added.append(spec.id)
        return added


_DEFAULT: Final = EngineRegistry()


def default_registry() -> EngineRegistry:
    """The process-wide registry."""
    return _DEFAULT


def register_engine(adapter: EngineAdapter) -> None:
    """Register ``adapter`` in the default registry."""
    _DEFAULT.register(adapter)


def iter_adapters() -> Iterator[EngineAdapter]:
    """Every registered adapter, sorted by engine id."""
    return iter(_DEFAULT)


def get_adapter(engine_id: str) -> EngineAdapter:
    """The registered adapter for ``engine_id``; ``KeyError`` when unknown."""
    return _DEFAULT.get(engine_id)


def resolve_enabled(
    settings: Settings,
    languages: Collection[Language],
    *,
    hosted: bool | None = None,
    probe: Callable[[EngineAdapter], EngineProbe] | None = None,
) -> list[EngineAdapter]:
    """:meth:`EngineRegistry.resolve_enabled` on the default registry."""
    return _DEFAULT.resolve_enabled(settings, languages, hosted=hosted, probe=probe)
