from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from codekavach.core.pipeline.manifest import (
    ManifestCounters,
    ScanManifest,
    build_manifest,
    collect_tool_versions,
    render_manifest_summary,
)
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import StageOutcome, StageRun
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.plugins.registry import PluginRow
from tests.support.golden import assert_matches_golden
from tests.support.pipeline import CollectingBus, FakeStage, make_run_context

GOLDEN = Path(__file__).parent / "golden" / "manifest_basic.json"
C = StageCategory
START = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
ENV = {
    "codekavach_version": "0.1.0",
    "python_version": "3.12.6",
    "python_implementation": "CPython",
    "os": "linux",
    "machine": "x86_64",
}


def fixed_manifest() -> ScanManifest:
    stages = [
        FakeStage("ingest", requires={"scan.target"}, provides={"files"}, category=C.INGEST),
        FakeStage("analyse-engines", requires={"files"}, provides={"x"}, category=C.ANALYSE,
                  version="3"),
    ]  # fmt: skip
    runs = [
        StageRun(stage="ingest", outcome=StageOutcome.SUCCEEDED, duration_ms=120),
        StageRun(
            stage="analyse-engines",
            outcome=StageOutcome.FAILED,
            duration_ms=61234,
            error_code="stage_timeout",
            error_type="TimeoutError",
        ),
    ]
    rows = [
        PluginRow(
            group="codekavach.stages", kind="stage", name="analyse-engines",
            target="pkg.module:factory", dist="codekavach", version="0.1.0", status="ok",
        )
    ]  # fmt: skip
    return build_manifest(
        scan_id="scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P",  # pragma: allowlist secret
        plan=plan_from_stages(stages),
        stage_runs=runs,
        registry_rows=rows,
        settings_fp="9c" * 32,
        salt_fp="ab" * 8,
        started_at=START,
        finished_at=START + timedelta(seconds=62),
        status="completed_with_errors",
        counters=ManifestCounters(cache_hits=1, item_failures=2),
        tool_versions={"analyse-engines": {"semgrep": "1.90.0"}},
        consent_source="env",
        env=lambda: dict(ENV),
    )


def test_golden() -> None:
    assert_matches_golden(fixed_manifest().to_json(), GOLDEN)


def test_manifest_holds_no_plugin_target() -> None:
    assert "pkg.module:factory" not in fixed_manifest().to_json()


class Probe:
    def __init__(self, value: Any = None, error: Exception | None = None) -> None:
        self._value, self._error = value, error

    def tool_versions(self) -> Any:
        if self._error is not None:
            raise self._error
        return self._value


@pytest.mark.parametrize(
    ("probe", "expected", "rejected"),
    [
        (object(), {}, False),
        (Probe({"semgrep": "1.90.0", "opengrep": "1.0.0+local"}),
         {"semgrep": "1.90.0", "opengrep": "1.0.0+local"}, False),
        (Probe({"semgrep": "1.90/0"}), {}, True),
        (Probe({"semgrep": "1.90\n0"}), {}, True),
        (Probe({"Semgrep": "1"}), {}, True),
        (Probe({f"t{i}": "1" for i in range(21)}), {}, True),
        (Probe(["not", "a", "mapping"]), {}, True),
        (Probe(error=RuntimeError("boom")), {}, False),
    ],
    ids=["none", "valid", "slash", "newline", "upper", "too-many", "not-mapping", "raises"],
)  # fmt: skip
def test_tool_versions_validation(probe: object, expected: dict[str, str], rejected: bool) -> None:
    assert collect_tool_versions(probe) == (expected, rejected)


class Versioned(FakeStage):
    def __init__(self, name: str, versions: Any, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self._versions = versions

    def tool_versions(self) -> Any:
        if isinstance(self._versions, Exception):
            raise self._versions
        return self._versions


@pytest.mark.parametrize(
    ("versions", "warned"), [({"semgrep": "a/b"}, True), (RuntimeError("x"), False)]
)
def test_invalid_versions_do_not_affect_the_scan(versions: Any, warned: bool) -> None:
    bus = CollectingBus()
    stage = Versioned("analyse-a", versions, requires={"scan.target"}, provides={"x"},
                      category=C.ANALYSE)  # fmt: skip
    ctx = make_run_context(bus=bus)
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = Orchestrator().run(plan_from_stages([stage]), ctx)
    assert result.status.value == "completed"
    assert result.tool_versions == {"analyse-a": {}}
    codes = [getattr(e, "code", None) for e in bus.of("warning")]
    assert ("tool_versions_invalid" in codes) is warned


def test_summary_lines() -> None:
    lines = render_manifest_summary(fixed_manifest())
    assert lines[0].startswith("scan scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P: completed_with_errors")
    assert any("analyse-engines" in line and "stage_timeout" in line for line in lines)
    assert lines[-1].startswith("cache: 1 hits, 0 misses; item failures: 2")
