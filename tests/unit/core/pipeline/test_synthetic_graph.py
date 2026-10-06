"""The synthetic graph and the timing helpers of the pipeline budget tests (E04-32)."""

import itertools
import re
import time

import pytest

from codekavach.core.pipeline.errors import UnsatisfiedRequirementError
from codekavach.core.pipeline.graph import build_graph, resolve_order, resolve_waves
from codekavach.core.pipeline.keys import TARGET
from codekavach.core.pipeline.stage import KEY_PATTERN, NAME_PATTERN, StageInfo
from tests.support.perf import measurement_line, median_seconds
from tests.support.pipeline import layered_stage_infos


def test_500_valid_stage_infos() -> None:
    infos = layered_stage_infos(10, 50)
    assert len(infos) == 500
    assert all(isinstance(info, StageInfo) for info in infos)
    assert len({info.name for info in infos}) == 500
    provided = [key for info in infos for key in info.provides]
    assert len(set(provided)) == 500
    assert all(NAME_PATTERN.match(info.name) for info in infos)
    assert all(KEY_PATTERN.match(key) for info in infos for key in info.requires | info.provides)


def test_each_stage_requires_two_keys_of_the_previous_layer() -> None:
    infos = layered_stage_infos(10, 50)
    first, rest = infos[:50], infos[50:]
    assert all(info.requires == {TARGET} for info in first)
    for info in rest:
        layer = int(info.name[1:3])
        assert len(info.requires) == 2
        assert all(key.startswith(f"l{layer - 1:02d}.") for key in info.requires)
        assert all(not key.startswith(f"l{layer:02d}.") for key in info.requires)


def test_the_graph_resolves_into_ten_waves_of_fifty() -> None:
    graph = build_graph(layered_stage_infos(10, 50), initial_keys=(TARGET,))
    order = resolve_order(graph)
    waves = resolve_waves(graph)
    assert len(order) == 500
    assert [len(wave) for wave in waves] == [50] * 10
    # A stage comes after both stages it depends on.
    position = {name: index for index, name in enumerate(order)}
    for name, dependencies in graph.edges.items():
        assert all(position[dependency] < position[name] for dependency in dependencies)


@pytest.mark.parametrize(("layers", "width"), [(1, 1), (2, 1), (3, 2), (4, 7), (10, 50)])
def test_other_shapes_resolve_too(layers: int, width: int) -> None:
    infos = layered_stage_infos(layers, width)
    assert len(infos) == layers * width
    graph = build_graph(infos, initial_keys=(TARGET,))
    assert len(resolve_order(graph)) == layers * width
    assert [len(wave) for wave in resolve_waves(graph)] == [width] * layers


def test_without_the_initial_key_the_first_layer_cannot_run() -> None:
    with pytest.raises(UnsatisfiedRequirementError, match=re.escape("scan.target")):
        build_graph(layered_stage_infos(2, 3), initial_keys=())


# --- the timing helpers --------------------------------------------------------------------------


def test_median_of_five_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([0.0, 1.0, 10.0, 12.0, 20.0, 25.0, 30.0, 40.0, 50.0, 53.0])
    monkeypatch.setattr(time, "perf_counter", lambda: next(ticks))
    calls: list[int] = []
    # durations 1, 2, 5, 10, 3 -> median 3
    assert median_seconds(lambda: calls.append(1), repeat=5) == 3.0
    assert len(calls) == 5


def test_median_runs_the_requested_number_of_repetitions() -> None:
    counter = itertools.count()
    median_seconds(lambda: next(counter), repeat=7)
    assert next(counter) == 7


def test_the_measurement_line_has_the_four_fields() -> None:
    assert (
        measurement_line("resolve_500_stages", 0.0023, 50, 500) == "resolve_500_stages 2.3 50 500"
    )
    assert measurement_line("x", 1.5, 400, 3000.5) == "x 1500.0 400 3000.5"
