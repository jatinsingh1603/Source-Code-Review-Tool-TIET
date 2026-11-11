"""Test kit for the engine framework (E14-01): a fake adapter, a stub sandbox and builders."""

import json
import sys
from collections.abc import Collection, Sequence
from pathlib import Path

from codekavach.analysis.engines.base import (
    OUTPUT_TOKEN,
    BuildTier,
    DistributionMode,
    EngineInvocation,
    EngineProbe,
    EngineRun,
    EngineSpec,
)
from codekavach.analysis.engines.sandbox import (
    SandboxRequest,
    SandboxResult,
    SandboxSet,
    SubprocessSandbox,
)
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.ingest.models import SourceFile
from tests.support.factories import make_candidate
from tests.support.pipeline import make_run_context

FAKE_ENGINE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "engines" / "fake" / "fake_engine.py"
)
OUTPUT_FILE = "out.json"


def make_spec(engine_id: str = "fake", /, **overrides: object) -> EngineSpec:
    """A valid spec for a Python engine; override any field."""
    fields: dict[str, object] = {
        "id": engine_id,
        "name": f"Fake {engine_id}",
        "languages": frozenset({Language.PYTHON}),
        "tier": BuildTier.NO_BUILD,
        "output_format": "json",
        "spdx_licence": "MIT",
        "distribution": DistributionMode.CLIENT_INSTALLED,
        "hosted_allowed": True,
        "scans_proprietary_code": True,
    }
    fields.update(overrides)
    return EngineSpec(**fields)  # type: ignore[arg-type]


def source_file(path: str = "app.py", language: Language = Language.PYTHON) -> SourceFile:
    """A source-file record with a stable hash."""
    return SourceFile(
        path=path,
        sha256="0" * 63 + "1",
        size_bytes=10,
        language=language,
        line_count=1,
        encoding="utf-8",
    )


class FakeAdapter:
    """An adapter whose engine is ``fake_engine.py`` run with the given arguments."""

    def __init__(
        self,
        engine_id: str = "fake",
        *,
        arguments: tuple[str, ...] = ("ok", f"{OUTPUT_TOKEN}/{OUTPUT_FILE}"),
        available: bool = True,
        version: str = "1.0.0",
        parse_error: bool = False,
        **spec_overrides: object,
    ) -> None:
        self.spec = make_spec(engine_id, **spec_overrides)
        self._arguments = arguments
        self._available = available
        self._version = version
        self._parse_error = parse_error
        self.invocations: list[EngineInvocation] = []

    def probe(self, settings: Settings) -> EngineProbe:
        return EngineProbe(
            self.spec.id,
            available=self._available,
            version=self._version if self._available else None,
            path=sys.executable if self._available else None,
            reason=None if self._available else "not installed",
        )

    def applies_to(self, languages: Collection[Language], files: Sequence[SourceFile]) -> bool:
        return bool(self.spec.languages & set(languages))

    def build_invocation(
        self, root: Path, files: Sequence[SourceFile], settings: Settings
    ) -> EngineInvocation | None:
        invocation = EngineInvocation(
            argv=(sys.executable, str(FAKE_ENGINE), *self._arguments),
            output_file=OUTPUT_FILE,
            expect_exit_codes=self.spec.expect_exit_codes,
        )
        self.invocations.append(invocation)
        return invocation

    def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
        if self._parse_error:
            raise ValueError("broken output")
        assert run.output_path is not None
        results = json.loads(run.output_path.read_text(encoding="utf-8"))["results"]
        return [make_candidate(engine=self.spec.id, rule_id=item["rule"]) for item in results]

    def install_hint(self) -> str:
        return f"pip install {self.spec.id}"


class StubSandbox(SubprocessSandbox):
    """A sandbox that runs nothing: it writes a canned output file and returns a canned result."""

    name = "stub"

    def __init__(
        self,
        *,
        exit_code: int = 0,
        timed_out: bool = False,
        truncated: bool = False,
        output: object = None,
    ) -> None:
        super().__init__(isolate_network=False)
        self._result = SandboxResult(
            exit_code=None if timed_out else exit_code,
            timed_out=timed_out,
            truncated=truncated,
            duration_seconds=0.01,
        )
        self._output = {"results": [{"rule": "fake.rule", "line": 1}]} if output is None else output
        self.requests: list[SandboxRequest] = []

    def run(self, request: SandboxRequest) -> SandboxResult:
        self.requests.append(request)
        request.out_dir.mkdir(parents=True, exist_ok=True)
        request.stdout_path.write_bytes(b"")
        request.stderr_path.write_bytes(b"")
        (request.out_dir / OUTPUT_FILE).write_text(json.dumps(self._output), encoding="utf-8")
        return self._result


def stub_sandboxes(sandbox: SubprocessSandbox) -> SandboxSet:
    """A sandbox set that always picks ``sandbox``."""
    return SandboxSet(sandbox, None, "subprocess")


def make_engine_context(
    tmp_path: Path, *, engines: dict[str, object] | None = None, state: bool = False
) -> RunContext:
    """A stage-bound context over a one-file project, with the ``files`` artefact stored."""
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "app.py").write_text("print(1)\n", encoding="utf-8")
    settings = Settings.model_validate({"engines": engines or {}})
    ctx = make_run_context(
        settings=settings,
        project_root=project,
        state_dir=(tmp_path / "state") if state else None,
    ).for_stage("analyse-engines")
    ctx.artefacts.put(keys.FILES, [source_file()])
    return ctx
