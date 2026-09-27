"""Execution order and waves derived from ``requires`` and ``provides``.

Owning epic: E04.

Stage S depends on every stage that provides a key in ``S.requires | S.optional_requires``. A hard
requirement that nothing provides (and that is not an initial key) is an error; an optional one
simply creates no edge, which is how ``rate`` follows ``aggregate`` directly when the LLM path is
not in the plan. Because ``llm-review`` requires ``payloads.sanitised``, which only a privacy stage
provides, no order exists in which the LLM stage runs before privacy preparation.

Everything here is pure and deterministic: ties are broken by ``(default_rank, name)``, so the same
set of stages gives the same order whatever the input order (supports I5).
"""

import heapq
import itertools
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from codekavach.core.pipeline.errors import (
    DuplicateProviderError,
    DuplicateStageError,
    GraphError,
    StageCycleError,
    UnsatisfiedRequirementError,
)
from codekavach.core.pipeline.keys import default_rank, is_multi_provider
from codekavach.core.pipeline.stage import StageInfo

INITIAL = "<initial>"


@dataclass(frozen=True, slots=True)
class StageGraph:
    """Stages by name, providers by key and dependencies by stage."""

    infos: Mapping[str, StageInfo]
    providers: Mapping[str, tuple[str, ...]]
    edges: Mapping[str, frozenset[str]]


@dataclass(frozen=True, slots=True)
class GraphProblem:
    """One problem found by ``diagnose``."""

    code: str
    stage: str | None
    key: str | None
    detail_names: tuple[str, ...] = ()


def _providers(infos: Mapping[str, StageInfo]) -> dict[str, tuple[str, ...]]:
    providers: dict[str, list[str]] = {}
    for name in sorted(infos):
        for key in infos[name].provides:
            providers.setdefault(key, []).append(name)
    return {key: tuple(names) for key, names in sorted(providers.items())}


def _index(infos: Collection[StageInfo]) -> dict[str, StageInfo]:
    by_name: dict[str, StageInfo] = {}
    for info in infos:
        if info.name in by_name:
            raise DuplicateStageError(info.name)
        assert not info.requires & info.provides, "rejected by describe_stage"  # noqa: S101
        by_name[info.name] = info
    return by_name


def build_graph(infos: Collection[StageInfo], initial_keys: Collection[str] = ()) -> StageGraph:
    """Check providers and requirements and compute the dependency edges.

    Raises:
        DuplicateStageError, DuplicateProviderError, UnsatisfiedRequirementError.
    """
    by_name = _index(infos)
    providers = _providers(by_name)
    initial = frozenset(initial_keys)
    for key in sorted(initial & providers.keys()):
        raise DuplicateProviderError(key, (INITIAL, *providers[key]))
    for key, names in providers.items():
        if len(names) > 1 and not is_multi_provider(key):
            raise DuplicateProviderError(key, names)
    edges: dict[str, frozenset[str]] = {}
    for name in sorted(by_name):
        info = by_name[name]
        for key in sorted(info.requires):
            if key not in providers and key not in initial:
                raise UnsatisfiedRequirementError(name, key)
        needed = info.requires | info.optional_requires
        edges[name] = frozenset(dep for key in needed for dep in providers.get(key, ()))
    return StageGraph(
        infos=MappingProxyType(by_name),
        providers=MappingProxyType(providers),
        edges=MappingProxyType(edges),
    )


def _priority(graph: StageGraph, name: str) -> tuple[int, str]:
    return (default_rank(graph.infos[name]), name)


def _dependents(edges: Mapping[str, frozenset[str]]) -> dict[str, list[str]]:
    dependents: dict[str, list[str]] = {name: [] for name in edges}
    for name, dependencies in edges.items():
        for dependency in dependencies:
            dependents[dependency].append(name)
    return dependents


def _kahn(graph: StageGraph) -> tuple[list[str], set[str]]:
    """The order of every stage that can be ordered, and the stages left in or behind cycles."""
    remaining = {name: len(deps) for name, deps in graph.edges.items()}
    dependents = _dependents(graph.edges)
    ready = [_priority(graph, name) for name, count in remaining.items() if count == 0]
    heapq.heapify(ready)
    order: list[str] = []
    while ready:
        _, name = heapq.heappop(ready)
        order.append(name)
        for dependent in dependents[name]:
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                heapq.heappush(ready, _priority(graph, dependent))
    return order, set(graph.edges) - set(order)


def _walk_cycle(
    edges: Mapping[str, frozenset[str]], stuck: set[str], node: str, path: list[str], seen: set[str]
) -> list[str] | None:
    """Depth-first search along dependencies; the first cycle closed by ``path``, if any."""
    path.append(node)
    seen.add(node)
    for dependency in sorted(edges[node] & stuck):
        if dependency in path:
            return path[path.index(dependency) :]
        if dependency not in seen and (found := _walk_cycle(edges, stuck, dependency, path, seen)):
            return found
    path.pop()
    return None


def _find_cycle(edges: Mapping[str, frozenset[str]], stuck: set[str]) -> tuple[str, ...]:
    """One concrete cycle among ``stuck``, rotated to start (and end) with its smallest name."""
    seen: set[str] = set()
    for start in sorted(stuck):
        if start in seen:
            continue
        cycle = _walk_cycle(edges, stuck, start, [], seen)
        if cycle:
            first = cycle.index(min(cycle))
            rotated = cycle[first:] + cycle[:first]
            return (*rotated, rotated[0])
    raise GraphError("no cycle found among the unordered stages")  # pragma: no cover


def _cycle_detail(graph: StageGraph, cycle: tuple[str, ...]) -> str:
    parts = []
    for stage, dependency in itertools.pairwise(cycle):
        info = graph.infos[stage]
        keys = sorted((info.requires | info.optional_requires) & graph.infos[dependency].provides)
        parts.append(f"{stage} requires {keys[0]!r} from {dependency}")
    return "; ".join(parts)


def resolve_order(graph: StageGraph) -> tuple[str, ...]:
    """A topological order with the ``(default_rank, name)`` tie-break.

    Raises:
        StageCycleError: the stages cannot be ordered.
    """
    order, stuck = _kahn(graph)
    if stuck:
        cycle = _find_cycle(graph.edges, stuck)
        raise StageCycleError(cycle, _cycle_detail(graph, cycle))
    return tuple(order)


def resolve_waves(graph: StageGraph) -> tuple[tuple[str, ...], ...]:
    """Groups of stages without dependencies between them, in execution order.

    A stage with ``parallel_safe=False`` gets a wave of its own right after the wave it would
    otherwise have joined.
    """
    order = resolve_order(graph)
    level: dict[str, int] = {}
    for name in order:
        level[name] = 1 + max((level[dep] for dep in graph.edges[name]), default=-1)
    waves: list[tuple[str, ...]] = []
    for current in range(max(level.values(), default=-1) + 1):
        members = sorted(
            (name for name in order if level[name] == current),
            key=lambda name: _priority(graph, name),
        )
        shared = tuple(name for name in members if graph.infos[name].parallel_safe)
        if shared:
            waves.append(shared)
        waves.extend((name,) for name in members if not graph.infos[name].parallel_safe)
    return tuple(waves)


def diagnose(
    infos: Collection[StageInfo], initial_keys: Collection[str] = ()
) -> list[GraphProblem]:
    """Every duplicate, unsatisfied requirement and cycle of a set of stages; never raises."""
    problems: list[GraphProblem] = []
    by_name: dict[str, StageInfo] = {}
    for info in sorted(infos, key=lambda item: item.name):
        if info.name in by_name:
            problems.append(GraphProblem("duplicate_stage", info.name, None))
        by_name[info.name] = info
    providers = _providers(by_name)
    initial = frozenset(initial_keys)
    for key, names in providers.items():
        if key in initial:
            problems.append(GraphProblem("duplicate_provider", None, key, (INITIAL, *names)))
        elif len(names) > 1 and not is_multi_provider(key):
            problems.append(GraphProblem("duplicate_provider", None, key, names))
    problems.extend(
        GraphProblem("unsatisfied_requirement", name, key)
        for name, info in sorted(by_name.items())
        for key in sorted(info.requires)
        if key not in providers and key not in initial
    )
    edges = {
        name: frozenset(
            dep
            for key in info.requires | info.optional_requires
            for dep in providers.get(key, ())
            if dep != name
        )
        for name, info in by_name.items()
    }
    graph = StageGraph(by_name, providers, edges)
    _, stuck = _kahn(graph)
    for component in _cyclic_components(edges, stuck):
        cycle = _find_cycle(edges, component)
        problems.append(GraphProblem("cycle", cycle[0], None, cycle))
    return problems


def _reachable(edges: Mapping[str, frozenset[str]], start: str, within: set[str]) -> set[str]:
    seen: set[str] = set()
    frontier = [start]
    while frontier:
        node = frontier.pop()
        for dependency in edges[node]:
            if dependency in within and dependency not in seen:
                seen.add(dependency)
                frontier.append(dependency)
    return seen


def _cyclic_components(edges: Mapping[str, frozenset[str]], stuck: set[str]) -> list[set[str]]:
    """Strongly connected components of ``stuck`` that contain a cycle, by smallest name."""
    reach = {name: _reachable(edges, name, stuck) for name in stuck}
    components: list[set[str]] = []
    assigned: set[str] = set()
    for name in sorted(stuck):
        if name in assigned or name not in reach[name]:
            continue
        component = {other for other in reach[name] if name in reach[other]} | {name}
        assigned |= component
        components.append(component)
    return components
