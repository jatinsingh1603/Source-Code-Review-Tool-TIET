"""Entry-point discovery of plugins; nothing is imported here.

Owning epic: E04.

Six entry-point groups are recognised. Discovery reads distribution metadata only; the registry
(``codekavach.core.plugins.registry``) imports a plugin when it is first used.
"""

import importlib.metadata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final

GROUPS: Final = (
    "codekavach.stages",
    "codekavach.languages",
    "codekavach.engines",
    "codekavach.detectors",
    "codekavach.providers",
    "codekavach.renderers",
)
UNKNOWN_DIST: Final = "unknown"

EntryPointsFn = Callable[..., Iterable[Any]]


@dataclass(frozen=True, slots=True)
class PluginSpec:
    """One entry point: where it points and which distribution declares it."""

    group: str
    name: str
    target: str
    dist_name: str
    dist_version: str


def _spec(group: str, entry_point: Any) -> PluginSpec:
    dist = getattr(entry_point, "dist", None)
    return PluginSpec(
        group=group,
        name=str(entry_point.name),
        target=str(entry_point.value),
        dist_name=str(dist.name) if dist is not None else UNKNOWN_DIST,
        dist_version=str(dist.version) if dist is not None else "",
    )


def discover(
    groups: Sequence[str] = GROUPS,
    *,
    entry_points_fn: EntryPointsFn = importlib.metadata.entry_points,
) -> list[PluginSpec]:
    """Every entry point of ``groups``, sorted by (group, name, distribution); no imports."""
    specs = {
        _spec(group, entry_point)
        for group in groups
        for entry_point in entry_points_fn(group=group)
    }
    return sorted(specs, key=lambda spec: (spec.group, spec.name, spec.dist_name, spec.target))
