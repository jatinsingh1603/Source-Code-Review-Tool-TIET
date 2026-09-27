import random
from collections.abc import Iterable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.pipeline.errors import (
    DuplicateProviderError,
    DuplicateStageError,
    StageCycleError,
    UnsatisfiedRequirementError,
)
from codekavach.core.pipeline.graph import (
    GraphProblem,
    build_graph,
    diagnose,
    resolve_order,
    resolve_waves,
)
from codekavach.core.pipeline.stage import StageCategory, StageInfo, describe_stage
from tests.support.pipeline import FakeStage

C = StageCategory


def info(
    name: str,
    requires: Iterable[str] = (),
    provides: Iterable[str] = (),
    *,
    optional: Iterable[str] = (),
    category: StageCategory | None = None,
    parallel_safe: bool = True,
) -> StageInfo:
    stage = FakeStage(
        name,
        requires=requires,
        provides=provides,
        optional_requires=optional,
        category=category,
        parallel_safe=parallel_safe,
    )
    return describe_stage(stage)


def default_pipeline() -> list[StageInfo]:
    return [
        info("ingest", ["scan.target"], ["files", "languages"], category=C.INGEST),
        info("parse", ["files"], ["ast", "symbols", "callgraph"], category=C.PARSE),
        info("analyse-rules", ["files", "symbols"], ["candidates.raw"], category=C.ANALYSE),
        info("analyse-taint", ["symbols", "callgraph"], ["candidates.raw"], category=C.ANALYSE),
        info("aggregate", ["candidates.raw"], ["candidates"], category=C.AGGREGATE),
        info(
            "privacy-prepare", ["candidates", "files"], ["payloads.sanitised"], category=C.PRIVACY
        ),
        info("llm-review", ["payloads.sanitised"], ["verdicts.raw"], category=C.LLM),
        info("restore", ["verdicts.raw"], ["verdicts.restored"], category=C.RESTORE),
        info(
            "rate",
            ["candidates"],
            ["findings", "scan.summary"],
            optional=["verdicts.restored"],
            category=C.RATE,
        ),
        info("report", ["findings"], ["report.outputs"], category=C.REPORT),
        info("sync", ["findings"], ["sync.result"], category=C.SYNC),
    ]


ORDER = (
    "ingest", "parse", "analyse-rules", "analyse-taint", "aggregate", "privacy-prepare",
    "llm-review", "restore", "rate", "report", "sync",
)  # fmt: skip
WAVES = (
    ("ingest",), ("parse",), ("analyse-rules", "analyse-taint"), ("aggregate",),
    ("privacy-prepare",), ("llm-review",), ("restore",), ("rate",), ("report", "sync"),
)  # fmt: skip


def test_worked_example_for_every_permutation() -> None:
    stages = default_pipeline()
    generator = random.Random(4)  # noqa: S311 - reproducible shuffles, not security
    for _ in range(50):
        generator.shuffle(stages)
        graph = build_graph(stages, {"scan.target"})
        assert resolve_order(graph) == ORDER
        assert resolve_waves(graph) == WAVES
    graph = build_graph(stages, {"scan.target"})
    assert graph.providers["candidates.raw"] == ("analyse-rules", "analyse-taint")


def test_without_llm_path_rate_follows_aggregate() -> None:
    llm_path = {"privacy-prepare", "llm-review", "restore"}
    stages = [stage for stage in default_pipeline() if stage.name not in llm_path]
    order = resolve_order(build_graph(stages, {"scan.target"}))
    assert order[order.index("aggregate") + 1] == "rate"


def test_removing_privacy_breaks_resolution() -> None:
    stages = [stage for stage in default_pipeline() if stage.name != "privacy-prepare"]
    with pytest.raises(UnsatisfiedRequirementError) as error:
        build_graph(stages, {"scan.target"})
    assert (error.value.stage, error.value.key) == ("llm-review", "payloads.sanitised")
    assert str(error.value) == (
        "stage 'llm-review' requires 'payloads.sanitised', which no stage in the plan provides"
    )


def test_duplicate_providers() -> None:
    with pytest.raises(DuplicateProviderError) as error:
        build_graph([info("a", provides=["candidates"]), info("b", provides=["candidates"])])
    assert str(error.value) == "artefact 'candidates' is provided by more than one stage: a, b"
    build_graph([info("a", provides=["candidates.raw"]), info("b", provides=["candidates.raw"])])
    build_graph([info("a", provides=["x.parts"]), info("b", provides=["x.parts"])])
    with pytest.raises(DuplicateProviderError) as initial:
        build_graph([info("a", provides=["files"])], {"files"})
    assert initial.value.stages == ("<initial>", "a")


def test_duplicate_stage() -> None:
    with pytest.raises(DuplicateStageError, match="'a' appears more than once"):
        build_graph([info("a", provides=["x"]), info("a", provides=["y"])])


def test_three_stage_cycle() -> None:
    stages = [
        info("c", ["x"], ["z"]),
        info("b", ["z"], ["y"]),
        info("a", ["y"], ["x"]),
    ]
    with pytest.raises(StageCycleError) as error:
        resolve_order(build_graph(stages))
    assert error.value.cycle == ("a", "b", "c", "a")
    assert str(error.value) == (
        "dependency cycle: a -> b -> c -> a "
        "(a requires 'y' from b; b requires 'z' from c; c requires 'x' from a)"
    )


def test_two_stage_cycle_message() -> None:
    stages = [info("a", ["y"], ["x"]), info("b", ["x"], ["y"])]
    with pytest.raises(StageCycleError) as error:
        resolve_order(build_graph(stages))
    assert str(error.value) == (
        "dependency cycle: a -> b -> a (a requires 'y' from b; b requires 'x' from a)"
    )


def test_shapes() -> None:
    chain = build_graph(
        [info("c", ["y"], ["z"]), info("a", provides=["x"]), info("b", ["x"], ["y"])]
    )
    assert resolve_order(chain) == ("a", "b", "c")
    diamond = build_graph(
        [
            info("top", provides=["t"]),
            info("left", ["t"], ["l"]),
            info("right", ["t"], ["r"]),
            info("bottom", ["l", "r"], ["b"]),
        ]
    )
    assert resolve_waves(diamond) == (("top",), ("left", "right"), ("bottom",))
    fan_in = build_graph(
        [
            info("p1", provides=["candidates.raw"]),
            info("p2", provides=["candidates.raw"]),
            info("agg", ["candidates.raw"], ["candidates"]),
        ]
    )
    assert fan_in.edges["agg"] == {"p1", "p2"}
    optional = build_graph([info("a", provides=["x"]), info("b", provides=["y"], optional=["x"])])
    assert optional.edges["b"] == {"a"}
    absent = build_graph([info("b", provides=["y"], optional=["x"])])
    assert absent.edges["b"] == frozenset()
    initial = build_graph([info("a", ["seed"], ["x"])], {"seed"})
    assert resolve_order(initial) == ("a",)


def test_parallel_unsafe_stage_is_alone() -> None:
    graph = build_graph(
        [
            info("root", provides=["r"]),
            info("a", ["r"], ["x"]),
            info("b", ["r"], ["y"], parallel_safe=False),
            info("c", ["r"], ["z"]),
            info("d", ["x", "y"], ["w"]),
        ]
    )
    assert resolve_waves(graph) == (("root",), ("a", "c"), ("b",), ("d",))


def test_diagnose_reports_everything() -> None:
    stages = [
        info("dup", provides=["one"]),
        info("dup", provides=["two"]),
        info("p", provides=["candidates"]),
        info("q", provides=["candidates"]),
        info("needy", ["missing"], ["n"]),
        info("a", ["y"], ["x"]),
        info("b", ["x"], ["y"]),
        info("seeded", provides=["seed"]),
    ]
    problems = diagnose(stages, {"seed"})
    codes = sorted((problem.code, problem.stage, problem.key) for problem in problems)
    assert codes == [
        ("cycle", "a", None),
        ("duplicate_provider", None, "candidates"),
        ("duplicate_provider", None, "seed"),
        ("duplicate_stage", "dup", None),
        ("unsatisfied_requirement", "needy", "missing"),
    ]
    cycle = next(problem for problem in problems if problem.code == "cycle")
    assert cycle == GraphProblem("cycle", "a", None, ("a", "b", "a"))
    assert diagnose(default_pipeline(), {"scan.target"}) == []


@st.composite
def dags(draw: st.DrawFn, back_edge: bool = False) -> list[StageInfo]:
    count = draw(st.integers(2 if back_edge else 1, 12))
    names = draw(st.permutations([f"s{index:02d}" for index in range(count)]))
    requires: dict[str, set[str]] = {name: set() for name in names}
    for position, name in enumerate(names):
        for earlier in names[:position]:
            if draw(st.booleans()):
                requires[name].add(f"k.{earlier}")
    if back_edge:
        first, later = names[0], names[-1]
        requires[later].add(f"k.{first}")
        requires[first].add(f"k.{later}")
    stages = [info(name, sorted(requires[name]), [f"k.{name}"]) for name in names]
    return draw(st.permutations(stages))


def valid_order(stages: list[StageInfo], order: Iterable[str]) -> bool:
    position = {name: index for index, name in enumerate(order)}
    providers = {key: stage.name for stage in stages for key in stage.provides}
    return len(position) == len(stages) and all(
        position[providers[key]] < position[stage.name]
        for stage in stages
        for key in stage.requires
    )


@given(dags(), st.randoms(use_true_random=False))
def test_property_topological(stages: list[StageInfo], generator: random.Random) -> None:
    graph = build_graph(stages)
    order = resolve_order(graph)
    assert valid_order(stages, order)
    shuffled = list(stages)
    generator.shuffle(shuffled)
    assert resolve_order(build_graph(shuffled)) == order
    flattened = [name for wave in resolve_waves(graph) for name in wave]
    assert sorted(flattened) == sorted(stage.name for stage in stages)
    assert valid_order(stages, flattened)


@given(dags(back_edge=True))
def test_property_back_edge_is_a_cycle(stages: list[StageInfo]) -> None:
    with pytest.raises(StageCycleError):
        resolve_order(build_graph(stages))
