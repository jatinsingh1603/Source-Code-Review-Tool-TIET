"""The back end of the engine checks of ``codekavach doctor`` (E14-01, loaded by E05-21).

Owning epic: E14.

``engine_checks`` probes every registered adapter and returns the probe results; the ``doctor``
command turns them into rows. A probe only asks the engine for its version: no scan is run and no
network is used.
"""

from codekavach.analysis.engines.base import EngineProbe
from codekavach.analysis.engines.registry import default_registry
from codekavach.config import Settings
from codekavach.core.log import get_logger

_log = get_logger("codekavach.analysis.engines.doctor")


def engine_checks(settings: Settings | None = None) -> list[EngineProbe]:
    """One probe result per registered engine, sorted by engine id."""
    active = Settings() if settings is None else settings
    probes: list[EngineProbe] = []
    for adapter in default_registry():
        try:
            probes.append(adapter.probe(active))
        except Exception as error:  # noqa: BLE001 - a broken adapter must not break `doctor`
            _log.warning(
                "engine_probe_failed", engine=adapter.spec.id, error_type=type(error).__name__
            )
            probes.append(
                EngineProbe(adapter.spec.id, available=False, reason="the probe raised an error")
            )
    return probes
