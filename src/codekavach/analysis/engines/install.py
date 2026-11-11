"""Install hints and installed-version checks for engines (E14-01).

Owning epic: E14.

Neither function touches the network: a hint is text from the manifest or the adapter, and
``verify_installed`` compares a probe result with the manifest's minimum version. Installing an
engine is the user's act (ADR-0002 rule 1); CodeKavach only says how.
"""

from collections.abc import Mapping
from typing import Final

from codekavach.analysis.engines.base import EngineProbe
from codekavach.analysis.engines.manifest import ManifestEntry, load_manifest, version_tuple

GENERIC_HINT: Final = "install the engine and make sure it is on PATH; run `codekavach doctor`"


def install_hint(engine_id: str, manifest: Mapping[str, ManifestEntry] | None = None) -> str:
    """One line on how to install ``engine_id``: manifest, then adapter, then a generic line."""
    entries = load_manifest() if manifest is None else manifest
    row = entries.get(engine_id)
    if row is not None:
        return row.install
    from codekavach.analysis.engines.registry import get_adapter  # noqa: PLC0415 - cycle

    try:
        return get_adapter(engine_id).install_hint()
    except KeyError:
        return GENERIC_HINT


def verify_installed(
    engine_id: str, probe: EngineProbe, manifest: Mapping[str, ManifestEntry] | None = None
) -> list[str]:
    """Why ``probe`` is not usable, as fixed phrases; empty when the engine is usable."""
    if not probe.available:
        return [probe.reason or "the engine is not installed"]
    entries = load_manifest() if manifest is None else manifest
    row = entries.get(engine_id)
    if row is None or not probe.version:
        return []
    found, minimum = version_tuple(probe.version), version_tuple(row.min_version)
    if found and minimum and found < minimum:
        return [f"version {probe.version} is older than the minimum {row.min_version}"]
    return []
