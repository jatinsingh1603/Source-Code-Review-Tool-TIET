"""The run plan: which discovered stages this scan runs, in which order, and why others do not.

Owning epic: E04.

Rules, in order: (1) a broken stage plugin fails the plan unless it is skipped by name; (2) skip
selectors from ``scan.skip_stages`` and the caller exclude stages, and a selector that matches
nothing is an error; (3) with ``llm.enabled = false`` every privacy, LLM and restore stage is
excluded, so nothing is prepared for egress; (4) ``until`` keeps the stages up to the last one it
matches; (5) the privacy structure checks run on what remains; (6) the order and waves are
resolved.

The structure checks are the pipeline-level expression of I2 and of the processing order of
ARCHITECTURE section 6.2: a plan in which an LLM stage could read raw-code artefacts, or in which
the privacy stage is skipped while an LLM stage remains, cannot be built. A plan that passes shows
that the wiring is as designed; it does not show that the payloads are safe, which is tested
elsewhere (E12, E25, E28).
"""

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from codekavach.config import Settings
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.errors import PipelineError
from codekavach.core.pipeline.graph import build_graph, resolve_order, resolve_waves
from codekavach.core.pipeline.stage import Stage, StageCategory, StageInfo, describe_stage
from codekavach.core.plugins.registry import STAGES_GROUP, PluginRegistry

EGRESS_CATEGORIES = frozenset({StageCategory.PRIVACY, StageCategory.LLM, StageCategory.RESTORE})
_SANITISED_PRODUCERS = frozenset({StageCategory.PRIVACY, StageCategory.LLM})
_MESSAGES = {
    "stage_plugin_failed": "a stage plugin failed to load; fix it or skip it by name",
    "unknown_stage_selector": "a stage selector matches no stage",
    "llm_reads_unsanitised": "an LLM stage reads an artefact not produced by the privacy layer",
    "llm_without_payloads": "an LLM stage does not require sanitised payloads",
    "sanitised_key_wrong_provider": "sanitised payloads are provided by a non-privacy stage",
    "privacy_skipped_with_llm": "privacy stage skipped while an LLM stage is active",
    "uncategorised_reads_sanitised": "a stage without a category reads sanitised artefacts",
}


class PlanError(PipelineError):
    """The plan cannot be built; ``code`` is a stable machine code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        message = _MESSAGES.get(code, code)
        super().__init__(f"{message} ({detail})" if detail else message)


@dataclass(frozen=True, slots=True)
class PlanProblem:
    """One violation of the privacy structure."""

    code: str
    stage: str | None = None
    key: str | None = None

    def detail(self) -> str:
        """Stage and key, for messages."""
        parts = [f"stage {self.stage!r}"] if self.stage else []
        if self.key:
            parts.append(f"key {self.key!r}")
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class ExcludedStage:
    """A discovered stage that this scan does not run."""

    name: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class RunPlan:
    """The stages of one scan in resolved order, with waves and exclusions."""

    stages: tuple[Stage, ...]
    infos: Mapping[str, StageInfo]
    order: tuple[str, ...]
    waves: tuple[tuple[str, ...], ...]
    excluded: tuple[ExcludedStage, ...]
    initial_keys: frozenset[str]

    def stage_by_name(self, name: str) -> Stage:
        """The stage called ``name``.

        Raises:
            KeyError: no stage of the plan has that name.
        """
        for stage in self.stages:
            if stage.name == name:
                return stage
        raise KeyError(name)


def check_privacy_structure(
    infos: Collection[StageInfo], *, initial_keys: Collection[str] = (keys.TARGET,)
) -> list[PlanProblem]:
    """Every privacy-structure violation of a set of stages, in a stable order."""
    by_name = {info.name: info for info in infos}
    providers: dict[str, list[StageInfo]] = {}
    for info in by_name.values():
        for key in info.provides:
            providers.setdefault(key, []).append(info)
    initial = frozenset(initial_keys)
    problems: list[PlanProblem] = []
    llm_stages = sorted(
        (info for info in by_name.values() if info.category is StageCategory.LLM),
        key=lambda info: info.name,
    )
    privacy_present = any(info.category is StageCategory.PRIVACY for info in by_name.values())
    if llm_stages and not privacy_present:
        problems.append(PlanProblem("privacy_skipped_with_llm", llm_stages[0].name))
    problems.extend(
        PlanProblem("sanitised_key_wrong_provider", source.name, keys.PAYLOADS_SANITISED)
        for source in sorted(providers.get(keys.PAYLOADS_SANITISED, []), key=lambda i: i.name)
        if source.category is not StageCategory.PRIVACY
    )
    for info in llm_stages:
        for key in sorted(info.requires | info.optional_requires):
            sources = providers.get(key, [])
            raw = key in keys.RAW_CODE_KEYS
            only_initial = not sources and key in initial
            foreign = any(source.category not in _SANITISED_PRODUCERS for source in sources)
            if raw or only_initial or foreign:
                problems.append(PlanProblem("llm_reads_unsanitised", info.name, key))
        if keys.PAYLOADS_SANITISED not in info.requires:
            problems.append(PlanProblem("llm_without_payloads", info.name, keys.PAYLOADS_SANITISED))
    problems.extend(
        PlanProblem("uncategorised_reads_sanitised", info.name, key)
        for info in sorted(by_name.values(), key=lambda info: info.name)
        if info.category is None
        for key in sorted((info.requires | info.optional_requires) & keys.SANITISED_KEYS)
    )
    return problems


def _raise_first(problems: list[PlanProblem]) -> None:
    if problems:
        raise PlanError(problems[0].code, problems[0].detail())


def _plan(
    stages: Mapping[str, Stage],
    infos: Mapping[str, StageInfo],
    *,
    selectors: Collection[str],
    llm_enabled: bool,
    until: str | None,
    initial_keys: Collection[str],
    failed_names: frozenset[str] = frozenset(),
) -> RunPlan:
    excluded: dict[str, str] = {}
    for selector in sorted(selectors):
        matched = [
            name for name, info in infos.items() if keys.matches_stage_selector(info, selector)
        ]
        if not matched and selector not in failed_names:
            raise PlanError("unknown_stage_selector", repr(selector))
        for name in matched:
            excluded.setdefault(name, "skipped_by_config")
    if not llm_enabled:
        for name, info in infos.items():
            if info.category in EGRESS_CATEGORIES:
                excluded.setdefault(name, "llm_disabled")
    remaining = {name: info for name, info in infos.items() if name not in excluded}
    _raise_first(
        [
            problem
            for problem in check_privacy_structure(remaining.values(), initial_keys=initial_keys)
            if problem.code == "privacy_skipped_with_llm"
        ]
    )
    if until is not None:
        order = resolve_order(build_graph(remaining.values(), initial_keys))
        matches = [
            index
            for index, name in enumerate(order)
            if keys.matches_stage_selector(remaining[name], until)
        ]
        if not matches:
            raise PlanError("unknown_stage_selector", repr(until))
        for name in order[matches[-1] + 1 :]:
            excluded[name] = "after_until"
            del remaining[name]
    _raise_first(check_privacy_structure(remaining.values(), initial_keys=initial_keys))
    graph = build_graph(remaining.values(), initial_keys)
    order = resolve_order(graph)
    return RunPlan(
        stages=tuple(stages[name] for name in order),
        infos=MappingProxyType({name: remaining[name] for name in order}),
        order=order,
        waves=resolve_waves(graph),
        excluded=tuple(ExcludedStage(name, excluded[name]) for name in sorted(excluded)),
        initial_keys=frozenset(initial_keys),
    )


def build_plan(
    registry: PluginRegistry,
    settings: Settings,
    *,
    skip: Collection[str] = (),
    until: str | None = None,
    initial_keys: Collection[str] = (keys.TARGET,),
) -> RunPlan:
    """The plan for one scan from the discovered stages and the settings.

    Raises:
        PlanError: a rule is violated (see ``code``).
        GraphError: the selected stages cannot be ordered.
    """
    selectors = set(settings.scan.skip_stages) | set(skip)
    failed = frozenset(
        failure.spec.name for failure in registry.failures() if failure.spec.group == STAGES_GROUP
    )
    for name in sorted(failed):
        if name not in selectors:
            raise PlanError("stage_plugin_failed", repr(name))
    return _plan(
        registry.stages(),
        registry.stage_infos(),
        selectors=selectors,
        llm_enabled=settings.llm.enabled,
        until=until,
        initial_keys=initial_keys,
        failed_names=failed,
    )


def plan_from_stages(
    stages: Sequence[Stage],
    *,
    initial_keys: Collection[str] = (keys.TARGET,),
    llm_enabled: bool = True,
    skip: Collection[str] = (),
    until: str | None = None,
) -> RunPlan:
    """The same rules as ``build_plan`` for stage objects given directly (tests, embedding)."""
    infos = {stage.name: describe_stage(stage) for stage in stages}
    return _plan(
        {stage.name: stage for stage in stages},
        infos,
        selectors=set(skip),
        llm_enabled=llm_enabled,
        until=until,
        initial_keys=initial_keys,
    )
