"""The report stage resolves formats through the renderer registry (E13-03)."""

from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.report.model.document import ReportOutput
from codekavach.report.render.stage import ReportStage
from tests.support.factories import make_finding, make_summary
from tests.support.pipeline import make_run_context


def run_stage(tmp_path: Path, formats: list[str]) -> tuple[InMemoryArtefactStore, list[str]]:
    store = InMemoryArtefactStore()
    store.put(keys.FINDINGS, [make_finding()])
    store.put(keys.SCAN_SUMMARY, make_summary(findings_total=1))
    settings = Settings.model_validate(
        {"reporting": {"formats": formats, "output_dir": str(tmp_path / "out")}}
    )
    ctx = make_run_context(store=store, settings=settings, project_root=tmp_path)
    scoped = ctx.for_stage("report")
    ReportStage().run(scoped)
    return store, [failure.error_code for failure in ctx.item_failures.snapshot()]


def test_the_stage_declares_the_documented_keys() -> None:
    info = describe_stage(ReportStage())
    assert set(info.requires) == {keys.FINDINGS, keys.SCAN_SUMMARY}
    assert set(info.provides) == {keys.REPORT_OUTPUTS}
    assert info.category is StageCategory.REPORT
    assert info.failure_policy is FailurePolicy.DEGRADE


def test_a_configured_format_is_written_and_recorded(tmp_path: Path) -> None:
    store, failures = run_stage(tmp_path, ["html"])
    (output,) = store.get_list(keys.REPORT_OUTPUTS, ReportOutput)
    assert output.format == "html" and Path(output.path).is_file() and output.size_bytes > 0
    assert failures == []


def test_a_format_without_a_renderer_is_a_named_failed_item_and_the_rest_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codekavach.report.render import stage  # noqa: PLC0415
    from codekavach.report.render.base import RendererRegistry  # noqa: PLC0415
    from codekavach.report.render.html import HtmlRenderer  # noqa: PLC0415

    only_html = RendererRegistry({"html": HtmlRenderer()})
    monkeypatch.setattr(stage, "renderer_registry", lambda _config=None: only_html)
    store, failures = run_stage(tmp_path, ["html", "sarif"])
    assert [o.format for o in store.get_list(keys.REPORT_OUTPUTS, ReportOutput)] == ["html"]
    assert failures == ["renderer_unavailable"]
