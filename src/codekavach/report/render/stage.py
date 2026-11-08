"""The report stage: renders the findings of a scan in the configured formats.

Owning epic: E13. MVP; extended by E31, which adds the remaining formats.

Renderers are found through the ``Renderer`` registry (the ``codekavach.renderers`` entry-point
group); the stage never imports one. A format that is configured but has no installed renderer is
recorded as a failed item named for the format, so the gap is visible in the scan's failures and
the other formats are still written (policy ``DEGRADE``). A format name the configuration does not
know is refused at the start of the stage.
"""

import hashlib
from pathlib import Path

from codekavach import __version__
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.config.models.reporting import ReportFormat
from codekavach.core.log import get_logger
from codekavach.core.models.enums import ScanStatus
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import ScanId, new_project_id
from codekavach.core.models.scan import Scan
from codekavach.core.models.summary import ScanSummary
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.items import guard_item
from codekavach.core.pipeline.stage import StageCategory
from codekavach.report.model.build import build_report_document, summarise_ledger
from codekavach.report.model.document import ReportOutput
from codekavach.report.render.base import renderer_registry

_log = get_logger(__name__)
RENDER_FAILED = "render_failed"
RENDERER_UNAVAILABLE = "renderer_unavailable"
FILE_MODE = 0o640


def provisional_scan(ctx: RunContext, summary: ScanSummary) -> Scan:
    """A ``Scan`` describing the scan so far; the final record exists only after the run."""
    provider_id: str | None = None
    model: str | None = None
    if ctx.config.llm.enabled:
        provider_id, provider = ctx.config.llm.selected_provider()
        model = provider.model
    return Scan(
        id=ScanId(ctx.scan_id),
        project_id=new_project_id(),
        status=ScanStatus.COMPLETED,
        started_at=utc_now(),
        finished_at=utc_now(),
        codekavach_version=__version__,
        config_hash=hashlib.sha256(ctx.config.model_dump_json().encode()).hexdigest(),
        privacy_level=ctx.config.privacy.level,
        provider=provider_id,
        model=model,
        summary=summary,
    )


class ReportStage:
    """Renders ``findings`` and ``scan.summary`` into one file per configured format."""

    name = "report"
    version = "1"
    requires = frozenset({keys.FINDINGS, keys.SCAN_SUMMARY})
    provides = frozenset({keys.REPORT_OUTPUTS})
    category = StageCategory.REPORT

    def run(self, ctx: RunContext) -> None:
        """Write each configured format below ``reporting.output_dir`` and record the files."""
        registry = renderer_registry(ctx.config)
        wanted = [item.value for item in ctx.config.reporting.formats]
        known = {item.value for item in ReportFormat}
        unknown = [name for name in wanted if name not in known]
        if unknown:
            issue = ConfigIssue(
                code=ConfigErrorCode.CK_CFG_003,
                severity="error",
                message=f"reporting.formats names {len(unknown)} unknown format(s)",
                key="reporting.formats",
            )
            raise ConfigError([issue])
        findings = ctx.artefacts.get_list(keys.FINDINGS, Finding)
        summary = ctx.artefacts.get(keys.SCAN_SUMMARY, ScanSummary)
        scan = provisional_scan(ctx, summary)
        ledger = summarise_ledger(ctx.state_dir, ctx.scan_id, ctx.config) if ctx.state_dir else None
        document = build_report_document(scan, findings, ctx.config, ledger)
        out_dir = (ctx.project_root / ctx.config.reporting.output_dir).resolve()
        outputs: list[ReportOutput] = []
        for name in wanted:
            ctx.check_cancelled()
            if name not in registry.names():
                ctx.fail_item(name, RENDERER_UNAVAILABLE)
                continue
            with guard_item(ctx, name, RENDER_FAILED):
                renderer = registry.get(name)
                target = out_dir / f"report.{renderer.extension}"
                written = renderer.render(document, target)
                data = Path(written).read_bytes()
                outputs.append(
                    ReportOutput(
                        format=name,
                        path=str(written),
                        size_bytes=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),
                    )
                )
        _log.info("report_written", formats=[item.format for item in outputs])
        ctx.artefacts.put(keys.REPORT_OUTPUTS, outputs)
