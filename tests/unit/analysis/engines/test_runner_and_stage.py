"""run_engine, the scheduler cache and AnalyseEnginesStage (E14-01)."""

import importlib.metadata
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, JsonValue

from codekavach.analysis.engines import scheduler
from codekavach.analysis.engines.base import OUTPUT_TOKEN, EngineInvocation, EngineRun
from codekavach.analysis.engines.doctor import engine_checks
from codekavach.analysis.engines.errors import (
    CODE_ERROR,
    CODE_LICENCE_BLOCKED,
    CODE_SANDBOX_ERROR,
    CODE_TIMEOUT,
    CODE_TRUNCATED,
    CODE_UNAVAILABLE,
    EngineUnavailable,
)
from codekavach.analysis.engines.install import GENERIC_HINT, install_hint, verify_installed
from codekavach.analysis.engines.manifest import parse_manifest
from codekavach.analysis.engines.registry import HOSTED_VARIABLE, EngineRegistry, default_registry
from codekavach.analysis.engines.runner import RunLimits, run_engine
from codekavach.analysis.engines.sandbox import SandboxLimits, SandboxSet, SubprocessSandbox
from codekavach.analysis.engines.stage import AnalyseEnginesStage
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import MemoStats
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from tests.support.engines import (
    FakeAdapter,
    StubSandbox,
    make_engine_context,
    source_file,
    stub_sandboxes,
)


def limits(tmp_path: Path, cap: int = 1024 * 1024) -> RunLimits:
    return RunLimits(
        timeout_seconds=5.0,
        root=tmp_path,
        out_dir=tmp_path / "o",
        sandbox=SandboxLimits(max_output_bytes=cap),
    )


def one(
    adapter: FakeAdapter, sandbox: StubSandbox, tmp_path: Path, cap: int = 1024 * 1024
) -> EngineRun:
    found = adapter.build_invocation(tmp_path, [source_file()], Settings())
    assert found is not None
    return run_engine(
        adapter, found, sandbox=sandbox, limits=limits(tmp_path, cap), version="1.0.0"
    )


def test_a_clean_run_is_ok(tmp_path: Path) -> None:
    run = one(FakeAdapter(), StubSandbox(), tmp_path)
    assert (run.status, run.error_code, run.truncated) == ("ok", None, False)
    assert run.output_path is not None and run.output_path.is_file()
    assert run.stdout_path is not None and run.stderr_path is not None
    assert run.version == "1.0.0"


def test_an_unexpected_exit_code_is_an_error(tmp_path: Path) -> None:
    run = one(FakeAdapter(), StubSandbox(exit_code=2), tmp_path)
    assert (run.status, run.error_code, run.exit_code) == ("error", CODE_ERROR, 2)


def test_an_exit_code_the_spec_expects_is_fine(tmp_path: Path) -> None:
    adapter = FakeAdapter(expect_exit_codes=frozenset({0, 1}))
    assert one(adapter, StubSandbox(exit_code=1), tmp_path).status == "ok"


def test_a_timeout_has_no_exit_code(tmp_path: Path) -> None:
    run = one(FakeAdapter(), StubSandbox(timed_out=True), tmp_path)
    assert (run.status, run.error_code, run.exit_code) == ("timeout", CODE_TIMEOUT, None)


def test_a_truncated_run_says_so(tmp_path: Path) -> None:
    run = one(FakeAdapter(), StubSandbox(truncated=True), tmp_path)
    assert (run.status, run.error_code, run.truncated) == ("ok", CODE_TRUNCATED, True)


def test_an_output_file_over_the_cap_is_cut_to_the_cap(tmp_path: Path) -> None:
    big = {"results": [{"rule": "r" * 5000, "line": 1}]}
    run = one(FakeAdapter(), StubSandbox(output=big), tmp_path, cap=100)
    assert run.truncated is True and run.error_code == CODE_TRUNCATED
    assert run.output_path is not None and run.output_path.stat().st_size == 100


class RaisingSandbox(StubSandbox):
    def run(self, request: Any) -> Any:
        raise EngineUnavailable(request.engine_id, "executable not found")


def test_a_missing_engine_is_unavailable_not_an_exception(tmp_path: Path) -> None:
    run = one(FakeAdapter(), RaisingSandbox(), tmp_path)
    assert (run.status, run.error_code) == ("unavailable", CODE_UNAVAILABLE)


def test_an_output_path_that_escapes_the_output_directory_is_refused(tmp_path: Path) -> None:
    adapter = FakeAdapter()
    found = EngineInvocation(argv=("tool",), output_file="../escape.json")
    run = run_engine(adapter, found, sandbox=StubSandbox(), limits=limits(tmp_path))
    assert (run.status, run.error_code) == ("error", CODE_SANDBOX_ERROR)


def real_sandboxes() -> SandboxSet:
    return SandboxSet(SubprocessSandbox(isolate_network=False), None, "subprocess")


def make_stage(
    registry: EngineRegistry, sandboxes: Callable[[Any], SandboxSet] = lambda _s: real_sandboxes()
) -> AnalyseEnginesStage:
    return AnalyseEnginesStage(registry, sandboxes=sandboxes, discover_plugins=False)


def failures(ctx: RunContext) -> set[tuple[str, str]]:
    return {(f.item_id, f.error_code) for f in ctx.item_failures.snapshot()}


def candidates_of(ctx: RunContext) -> list[Candidate]:
    return ctx.artefacts.get_parts(keys.CANDIDATES_RAW, Candidate)["analyse-engines"]


def test_the_stage_declares_itself_as_a_degrading_analyse_stage() -> None:
    info = describe_stage(AnalyseEnginesStage())
    assert info.name == "analyse-engines"
    assert info.category is StageCategory.ANALYSE
    assert info.failure_policy is FailurePolicy.DEGRADE
    assert info.requires == frozenset({keys.FILES})
    assert info.optional_requires == frozenset({keys.LANGUAGES})
    assert info.provides == frozenset({keys.CANDIDATES_RAW})
    assert info.cacheable is False


def test_the_stage_is_registered_as_a_stage_entry_point() -> None:
    points = importlib.metadata.entry_points(group="codekavach.stages")
    found = {point.name: point.value for point in points}
    assert found["analyse-engines"] == "codekavach.analysis.engines.stage:AnalyseEnginesStage"


def test_a_fake_engine_runs_end_to_end(tmp_path: Path) -> None:
    registry = EngineRegistry()
    registry.register(FakeAdapter("good"))
    ctx = make_engine_context(tmp_path, engines={"sandbox": {"mode": "subprocess"}})
    make_stage(registry).run(ctx)
    found = candidates_of(ctx)
    assert [c.engine for c in found] == ["good"]
    assert failures(ctx) == set()


def test_one_engine_unavailable_one_timing_out_and_one_succeeding_still_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scheduler, "_timeout", lambda *_args: 1.0)
    registry = EngineRegistry()
    registry.register(FakeAdapter("good"))
    registry.register(FakeAdapter("gone", available=False))
    registry.register(FakeAdapter("slow", arguments=("sleep", "60")))
    ctx = make_engine_context(tmp_path, engines={"enabled": ["good", "gone", "slow"]})
    make_stage(registry).run(ctx)
    assert [c.engine for c in candidates_of(ctx)] == ["good"]
    assert failures(ctx) == {("gone", CODE_UNAVAILABLE), ("slow", CODE_TIMEOUT)}


def test_a_crashing_engine_and_a_broken_parser_degrade(tmp_path: Path) -> None:
    registry = EngineRegistry()
    registry.register(FakeAdapter("crash", arguments=("exit", "9")))
    registry.register(FakeAdapter("parser", parse_error=True))
    registry.register(FakeAdapter("good"))
    ctx = make_engine_context(tmp_path)
    make_stage(registry).run(ctx)
    assert [c.engine for c in candidates_of(ctx)] == ["good"]
    assert failures(ctx) == {("crash", CODE_ERROR), ("parser", CODE_ERROR)}


def test_a_blocked_engine_is_reported_and_not_run(tmp_path: Path) -> None:
    registry = EngineRegistry()
    registry.register(FakeAdapter("share", scans_proprietary_code=False))
    sandbox = StubSandbox()
    ctx = make_engine_context(tmp_path, engines={"enabled": ["share"]})
    make_stage(registry, lambda _s: stub_sandboxes(sandbox)).run(ctx)
    assert failures(ctx) == {("share", CODE_LICENCE_BLOCKED)}
    assert sandbox.requests == []
    assert candidates_of(ctx) == []


def test_a_hosted_deployment_refuses_the_engine_with_its_own_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HOSTED_VARIABLE, "hosted")
    registry = EngineRegistry()
    registry.register(FakeAdapter("copyleft", hosted_allowed=False))
    sandbox = StubSandbox()
    ctx = make_engine_context(tmp_path)
    make_stage(registry, lambda _s: stub_sandboxes(sandbox)).run(ctx)
    assert failures(ctx) == {("copyleft", CODE_LICENCE_BLOCKED)}
    assert sandbox.requests == []


class ConfigAdapter(FakeAdapter):
    """Records what the engine reports about the configuration it could see."""

    seen: dict[str, Any]

    def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
        assert run.output_path is not None
        self.seen = json.loads(run.output_path.read_text(encoding="utf-8"))
        return []


def test_a_repository_config_file_is_hidden_from_the_engine(tmp_path: Path) -> None:
    adapter = ConfigAdapter(
        "cfg", arguments=("config", f"{OUTPUT_TOKEN}/out.json"), config_filenames=(".fakerc",)
    )
    registry = EngineRegistry()
    registry.register(adapter)
    ctx = make_engine_context(tmp_path)
    (ctx.project_root / ".fakerc").write_text("{}", encoding="utf-8")
    make_stage(registry).run(ctx)
    assert adapter.seen["rc_present"] is False
    assert ".fakerc" not in adapter.seen["files"]
    assert (ctx.project_root / ".fakerc").is_file(), "the original tree is untouched"


class DictMemo:
    """An in-memory ItemMemo that never stores a failed compute."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], list[Any]] = {}

    def get_or_compute_list[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], Sequence[M]], item: type[M]
    ) -> list[M]:
        key = (namespace, item_key)
        if key not in self.store:
            self.store[key] = list(compute())
        return list(self.store[key])

    def get_or_compute[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], M], model: type[M]
    ) -> M:
        raise NotImplementedError

    def get_or_compute_json(
        self, namespace: str, item_key: str, compute: Callable[[], JsonValue]
    ) -> JsonValue:
        raise NotImplementedError

    def stats(self) -> MemoStats:
        return MemoStats()


def run_twice(
    tmp_path: Path, adapter: FakeAdapter, sandbox: StubSandbox, memo: DictMemo
) -> list[EngineRun]:
    ctx = make_engine_context(tmp_path).for_stage("analyse-engines", memo=memo)
    view = tmp_path / "view"
    view.mkdir(exist_ok=True)
    return scheduler.run_all(
        [adapter],
        ctx,
        languages=[Language.PYTHON],
        files=[source_file()],
        view=view,
        work_dir=tmp_path / "work",
        sandboxes=stub_sandboxes(sandbox),
    )


def test_a_successful_run_is_cached_and_a_failed_one_is_not(tmp_path: Path) -> None:
    memo, good = DictMemo(), StubSandbox()
    first = run_twice(tmp_path, FakeAdapter("good"), good, memo)[0]
    second = run_twice(tmp_path, FakeAdapter("good"), good, memo)[0]
    assert (first.cached, second.cached) == (False, True)
    assert len(good.requests) == 1
    assert len(second.candidates) == 1

    bad = StubSandbox(exit_code=3)
    run_twice(tmp_path, FakeAdapter("bad"), bad, memo)
    run_twice(tmp_path, FakeAdapter("bad"), bad, memo)
    assert len(bad.requests) == 2, "a failure must be tried again"


def test_the_cache_key_ignores_temporary_paths_and_tracks_inputs() -> None:
    def key(root: str, **changes: Any) -> str:
        found = EngineInvocation(argv=("tool", f"{root}/src"), workdir=root)
        arguments: dict[str, Any] = {
            "engine_id": "e",
            "version": "1",
            "invocation": found,
            "root": Path(root),
            "files": [source_file()],
            "fingerprint": "f",
        }
        arguments.update(changes)
        return scheduler.cache_key(**arguments)

    base = key("/tmp/a")
    assert key("/tmp/b") == base
    assert key("/tmp/a", version="2") != base
    assert key("/tmp/a", fingerprint="g") != base
    changed = source_file().model_copy(update={"sha256": "1" * 64})
    assert key("/tmp/a", files=[changed]) != base


def test_install_hints_and_version_checks_need_no_network() -> None:
    """Sockets are disabled for the whole suite, so these succeeding proves they use none."""
    manifest = parse_manifest(
        '[engines.sample]\npinned_version = "2.0.0"\nmin_version = "1.5.0"\nspdx_licence = "MIT"\n'
        'distribution = "bundled"\nhosted_allowed = true\nscans_proprietary_code = true\n'
        'install = "pipx install sample"\ntelemetry_env = { A = "1" }\n'
    )
    assert install_hint("sample", manifest) == "pipx install sample"
    assert install_hint("unknown-engine", manifest) == GENERIC_HINT
    adapter = FakeAdapter("hinted")
    default_registry().register(adapter)
    try:
        assert install_hint("hinted", manifest) == "pip install hinted"
    finally:
        default_registry().unregister("hinted")
    probe = FakeAdapter(version="1.0.0").probe(None)  # type: ignore[arg-type]
    assert verify_installed("sample", probe, manifest) == [
        "version 1.0.0 is older than the minimum 1.5.0"
    ]
    assert verify_installed("other", probe, manifest) == []
    missing = FakeAdapter(available=False).probe(None)  # type: ignore[arg-type]
    assert verify_installed("sample", missing, manifest) == ["not installed"]


class BrokenProbe(FakeAdapter):
    def probe(self, settings: Any) -> Any:
        raise RuntimeError("boom")


def test_doctor_reports_every_registered_engine_even_a_broken_one() -> None:
    default_registry().register(FakeAdapter("doc-ok"))
    default_registry().register(BrokenProbe("doc-bad"))
    try:
        by_id = {probe.engine_id: probe for probe in engine_checks()}
    finally:
        default_registry().unregister("doc-ok")
        default_registry().unregister("doc-bad")
    assert by_id["doc-ok"].available is True
    assert by_id["doc-bad"].available is False
