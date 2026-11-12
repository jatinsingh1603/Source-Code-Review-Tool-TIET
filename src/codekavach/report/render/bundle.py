"""The compliance annex, the delta report between two scans, and the integrity manifest.

Owning epic: E31 (E31-04).

* ``ComplianceRenderer`` writes the control-versus-finding matrix as its own HTML document. It
  presents findings as evidence against a clause, never as an opinion of compliance.
* ``build_delta`` compares two documents by fingerprint into new, fixed, unchanged and regressed
  (severity raised) sets; ``render_delta_html`` and ``delta_json`` write it.
* ``write_manifest`` records the SHA-256 and size of every rendered file, with the report and
  scan identifiers, as ``manifest.json`` and as a ``sha256sum``-compatible ``SHA256SUMS`` file, so
  a client can show which files belong to which scan and that none was altered.
"""

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Final

from jinja2 import FunctionLoader, StrictUndefined, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.timeutil import utc_now
from codekavach.report.model.document import ReportDocument
from codekavach.report.model.finding_view import FindingView
from codekavach.report.render.html import (
    REPORT_CSP,
    _css_source,
    _template_source,
    compliance_rows,
    running_header,
)
from codekavach.report.render.theme import DEFAULT_THEME, Theme

MANIFEST_NAME: Final = "manifest.json"
SUMS_NAME: Final = "SHA256SUMS"


def _env() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FunctionLoader(_template_source),
        autoescape=select_autoescape(default=True, default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _css(theme: Theme) -> Markup:
    return Markup(  # noqa: S704 - generated from validated theme values
        _css_source("html/report.css", theme) + _css_source("html/screen.css", theme)
    )


class ComplianceRenderer:
    """Writes the compliance annex as a standalone HTML document."""

    format = "compliance"
    extension = "compliance.html"
    binary = False

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write the annex of ``doc`` to ``out``."""
        rows = compliance_rows(doc)
        frameworks = sorted({row.framework for row in rows})
        views = {view.report_id: view for view in doc.views}
        tops = {
            row.clause + row.framework: max(
                (views[rid] for rid in row.ids), key=lambda v: v.severity_rank
            ).severity
            for row in rows
        }
        page = (
            _env()
            .get_template("html/annex.html.j2")
            .render(
                doc=doc,
                rows=rows,
                frameworks=frameworks,
                tops=tops,
                csp=REPORT_CSP,
                css=_css(theme or DEFAULT_THEME),
                header=running_header(doc.classification),
            )
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(page, encoding="utf-8", newline="\n")
        return out


class DeltaEntry(KavachModel):
    """One finding in the delta, with its severity in each scan."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    fingerprint: str
    report_id: str
    title: str
    location: str
    severity: str
    previous_severity: str | None = None
    status: str
    previous_status: str | None = None


class DeltaReport(KavachModel):
    """What changed between a baseline scan and the current one."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    baseline_scan: str
    current_scan: str
    baseline_date: datetime
    current_date: datetime
    new: tuple[DeltaEntry, ...] = ()
    fixed: tuple[DeltaEntry, ...] = ()
    regressed: tuple[DeltaEntry, ...] = ()
    unchanged: tuple[DeltaEntry, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        """The size of each set."""
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "regressed": len(self.regressed),
            "unchanged": len(self.unchanged),
        }


def _entry(view: FindingView, before: FindingView | None = None) -> DeltaEntry:
    return DeltaEntry(
        fingerprint=view.fingerprint,
        report_id=view.report_id,
        title=view.title,
        location=view.location_label,
        severity=view.severity,
        previous_severity=before.severity if before else None,
        status=view.status,
        previous_status=before.status if before else None,
    )


def build_delta(current: ReportDocument, baseline: ReportDocument) -> DeltaReport:
    """Compare ``current`` with ``baseline`` by finding fingerprint.

    A baseline finding that is absent now, or whose status is now ``fixed``, is fixed. A finding
    present in both whose severity rank rose is regressed. Everything else present in both is
    unchanged.
    """
    before = {view.fingerprint: view for view in baseline.views}
    now = {view.fingerprint: view for view in current.views}
    new, regressed, unchanged, fixed = [], [], [], []
    for fp, view in now.items():
        old = before.get(fp)
        if old is None:
            new.append(_entry(view))
        elif view.status == "fixed":
            fixed.append(_entry(view, old))
        elif view.severity_rank > old.severity_rank:
            regressed.append(_entry(view, old))
        else:
            unchanged.append(_entry(view, old))
    fixed.extend(_entry(old) for fp, old in before.items() if fp not in now)
    return DeltaReport(
        baseline_scan=str(baseline.scan.id),
        current_scan=str(current.scan.id),
        baseline_date=baseline.scan.started_at,
        current_date=current.scan.started_at,
        new=tuple(new),
        fixed=tuple(fixed),
        regressed=tuple(regressed),
        unchanged=tuple(unchanged),
    )


def delta_json(delta: DeltaReport) -> str:
    """The delta as JSON."""
    data = delta.model_dump(mode="json")
    data["counts"] = delta.counts
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def render_delta_html(
    delta: DeltaReport, current: ReportDocument, out: Path, *, theme: Theme | None = None
) -> Path:
    """Write the delta report as a standalone HTML document."""
    page = (
        _env()
        .get_template("html/delta.html.j2")
        .render(
            delta=delta,
            doc=current,
            csp=REPORT_CSP,
            css=_css(theme or DEFAULT_THEME),
            header=running_header(current.classification),
        )
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8", newline="\n")
    return out


def sha256_file(path: Path) -> str:
    """The SHA-256 of the file at ``path``."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(
    files: Sequence[Path], out_dir: Path, *, doc: ReportDocument
) -> tuple[Path, Path]:
    """Write ``manifest.json`` and ``SHA256SUMS`` for ``files`` and return both paths."""
    entries = []
    for path in sorted(files, key=lambda p: p.name):
        if not path.is_file():
            continue
        entries.append(
            {
                "file": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    manifest = {
        "schema": "codekavach.report-manifest/v1",
        "report_id": doc.report_id,
        "scan_id": str(doc.scan.id),
        "project": doc.project_name,
        "classification": doc.classification,
        "codekavach_version": doc.scan.codekavach_version,
        "config_hash": doc.scan.config_hash,
        "ledger_head_hash": doc.privacy_attestation.ledger_head_hash
        if doc.privacy_attestation
        else None,
        "generated_at": utc_now().isoformat(),
        "files": entries,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sums = out_dir / SUMS_NAME
    lines = [f"{item['sha256']}  {item['file']}" for item in entries]
    lines.append(f"{sha256_file(manifest_path)}  {MANIFEST_NAME}")
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest_path, sums


def verify_manifest(out_dir: Path) -> list[str]:
    """The files whose hash no longer matches ``manifest.json``; empty when all match."""
    manifest = json.loads((out_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    bad = []
    for item in manifest["files"]:
        path = out_dir / item["file"]
        if not path.is_file() or sha256_file(path) != item["sha256"]:
            bad.append(item["file"])
    return bad


DEFAULT_BUNDLE: Final = (
    "html",
    "pdf",
    "sarif",
    "json",
    "csv",
    "xlsx",
    "docx",
    "markdown",
    "compliance",
)


def render_bundle(
    doc: ReportDocument,
    out_dir: Path,
    *,
    formats: Sequence[str] = DEFAULT_BUNDLE,
    stem: str = "report",
    theme: Theme | None = None,
    manifest: bool = True,
) -> tuple[dict[str, Path], dict[str, str]]:
    """Render ``formats`` of ``doc`` into ``out_dir`` and write the integrity manifest.

    Returns the written files by format and, for each format that could not be written, its
    reason code (never the error text, which may quote report content). This is the entry point
    for the API server and other callers that want every format at once.
    """
    from codekavach.report.render.base import renderer_registry  # noqa: PLC0415 - avoid cycle

    registry = renderer_registry()
    written: dict[str, Path] = {}
    failed: dict[str, str] = {}
    for name in formats:
        if name not in registry.names():
            failed[name] = "renderer_unavailable"
            continue
        renderer = registry.get(name)
        target = out_dir / f"{stem}.{renderer.extension}"
        try:
            try:
                path = renderer.render(doc, target, theme=theme)  # type: ignore[call-arg]
            except TypeError:
                path = renderer.render(doc, target)
            written[name] = Path(path)
        except Exception as error:  # noqa: BLE001 - one format must not stop the others
            reason = getattr(error, "reason_code", None)
            failed[name] = reason if isinstance(reason, str) else "render_failed"
    if manifest and written:
        manifest_path, sums = write_manifest(list(written.values()), out_dir, doc=doc)
        written["manifest"] = manifest_path
        written["sha256sums"] = sums
    return written, failed
