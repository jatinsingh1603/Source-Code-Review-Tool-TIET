"""Test kit for the engine framework (E14-01): a fake adapter, a stub sandbox and builders."""

import json
import os
import shutil
import sys
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from codekavach.analysis.engines.base import (
    OUTPUT_TOKEN,
    BuildTier,
    DistributionMode,
    EngineAdapter,
    EngineInvocation,
    EngineProbe,
    EngineRun,
    EngineSpec,
)
from codekavach.analysis.engines.runner import RunLimits, run_engine
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
from tests.support.golden import assert_matches_golden
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


# --- the conformance kit (E14-02) -------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "engines"
SHELL_METACHARACTERS = frozenset(";|&`$<>\n\r")
CI_VARIABLE = "CI"


@dataclass(frozen=True)
class RecordedCase:
    """One recorded engine run: ``tests/fixtures/engines/<engine-id>/<case>/``.

    The directory holds ``spec.json`` (``engine_version``, ``output_file``, ``languages`` and
    optionally ``planted_secrets``), the engine's raw output, ``expected_candidates.json`` and a
    ``tree/`` with the synthetic project the engine scanned.
    """

    engine_id: str
    name: str
    directory: Path
    spec: dict[str, Any]

    @classmethod
    def load(cls, directory: Path) -> "RecordedCase":
        spec = json.loads((directory / "spec.json").read_text(encoding="utf-8"))
        return cls(directory.parent.name, directory.name, directory, spec)

    @property
    def tree(self) -> Path:
        return self.directory / "tree"

    @property
    def output(self) -> Path:
        return self.directory / str(self.spec["output_file"])

    @property
    def expected(self) -> Path:
        return self.directory / "expected_candidates.json"

    @property
    def label(self) -> str:
        return f"{self.engine_id}/{self.name}"


def discover_cases(base: Path = FIXTURES) -> list[RecordedCase]:
    """Every recorded case below ``base``, in a stable order."""
    return [RecordedCase.load(spec.parent) for spec in sorted(base.glob("*/*/spec.json"))]


def canonical_candidates(candidates: Sequence[Candidate]) -> str:
    """The comparison form: canonical JSON with the random candidate ids replaced by positions."""
    rows = [{**c.model_dump(mode="json"), "id": f"cand-{n}"} for n, c in enumerate(candidates)]
    return json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def tree_files(tree: Path) -> list[SourceFile]:
    """Source-file records for every file of a case's tree."""
    return [
        source_file(path.relative_to(tree).as_posix())
        for path in sorted(tree.rglob("*"))
        if path.is_file()
    ]


def run_adapter_contract(adapter: EngineAdapter, case_dir: Path) -> list[Candidate]:
    """Check ``adapter`` against one recorded case; return the candidates it parsed.

    Asserts: the adapter declares languages and a tier (and the case's languages are among them);
    ``build_invocation`` gives an argument vector with an executable first and no shell
    metacharacter; ``parse`` of the recorded output equals the golden candidates byte for byte;
    every candidate validates, every path it names is in the case's tree, and none carries a
    planted synthetic secret.
    """
    case = RecordedCase.load(case_dir)
    spec = adapter.spec
    assert spec.languages, f"{case.label}: the adapter declares no language"
    assert isinstance(spec.tier, BuildTier)
    declared = {language.value for language in spec.languages}
    assert set(case.spec["languages"]) <= declared, f"{case.label}: languages not declared"
    invocation = adapter.build_invocation(case.tree, tree_files(case.tree), Settings())
    assert invocation is not None, f"{case.label}: no invocation for the recorded project"
    assert invocation.argv, f"{case.label}: empty argument vector"
    assert invocation.argv[0] and not invocation.argv[0].startswith("-")
    for argument in invocation.argv:
        assert isinstance(argument, str)
        assert not SHELL_METACHARACTERS & set(argument), f"{case.label}: shell metacharacter"
    run = EngineRun(
        engine=spec.id,
        version=str(case.spec["engine_version"]),
        exit_code=0,
        duration_seconds=0.0,
        status="ok",
        output_path=case.output,
    )
    found = list(adapter.parse(run, case.tree))
    for candidate in found:
        Candidate.model_validate(candidate.model_dump())
        for path in candidate.files:
            assert (case.tree / path).is_file(), f"{case.label}: {path} is not in the tree"
        dumped = candidate.model_dump_json()
        for secret in case.spec.get("planted_secrets", []):
            assert secret not in dumped, f"{case.label}: a planted secret reached a candidate"
    assert_matches_golden(canonical_candidates(found), case.expected)
    return found


def record_case(adapter: EngineAdapter, case_dir: Path) -> None:
    """Re-record a case by running the installed engine on its tree (``--engines-live``).

    Refused when ``CI`` is set. Skips the test when the engine is not installed. Writes the raw
    output next to ``spec.json``; the golden file is then rewritten by the comparison with
    ``CODEKAVACH_UPDATE_GOLDEN=1``.
    """
    if os.environ.get(CI_VARIABLE):
        raise pytest.UsageError("--engines-live is refused when CI is set")
    case = RecordedCase.load(case_dir)
    probe = adapter.probe(Settings())
    if not probe.available:
        pytest.skip(f"{adapter.spec.id} is not installed")
    invocation = adapter.build_invocation(case.tree, tree_files(case.tree), Settings())
    assert invocation is not None
    out_dir = case_dir / "live-output"
    out_dir.mkdir(exist_ok=True)
    limits = RunLimits(timeout_seconds=300.0, root=case.tree, out_dir=out_dir)
    run = run_engine(
        adapter, invocation, sandbox=SubprocessSandbox(), limits=limits, version=probe.version or ""
    )
    assert run.output_path is not None, f"{case.label}: the engine wrote no output"
    shutil.copyfile(run.output_path, case.output)
    case.spec["engine_version"] = probe.version or case.spec["engine_version"]
    (case_dir / "spec.json").write_text(json.dumps(case.spec, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(out_dir)
