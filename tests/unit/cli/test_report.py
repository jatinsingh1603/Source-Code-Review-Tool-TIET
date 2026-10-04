import hashlib
import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli import backends
from codekavach.cli.report import (
    REPORT_DIR_MODE,
    REPORT_FILE_MODE,
    human_size,
    parse_formats,
)
from codekavach.config import load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import new_finding_id, new_project_id, new_scan_id
from codekavach.core.models.scan import Scan
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.repositories import ScanRecorder, open_scan_lookup
from tests.support.cli import CliResult
from tests.support.factories import FIXED_NOW, make_finding, make_project, make_scan, make_summary
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden" / "report_table.txt"
SNIPPET = "cur.execute('SELECT * FROM accounts WHERE owner = ' + owner)"
SCAN_ID = "scan_01ARYZ6S410000000000000000"
LOOKUP = "codekavach.core.store.repositories.open_scan_lookup"
DOCUMENT = "codekavach.report.model.build_report_document"
REGISTRY = "codekavach.report.render.renderer_registry"


class PrerequisiteMissingError(RuntimeError):
    """What E31 raises when a renderer's system libraries are missing."""

    reason_code = "weasyprint_missing"


@dataclass
class FakeRenderer:
    extension: str
    content: bytes = b"report"
    error: Exception | None = None
    calls: int = 0

    def render(self, document: object, destination: Path) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error
        destination.write_bytes(self.content + repr(document).encode())


@dataclass
class FakeRegistry:
    renderers: dict[str, FakeRenderer]

    def names(self) -> Sequence[str]:
        return list(self.renderers)

    def get(self, name: str) -> FakeRenderer:
        return self.renderers[name]


@dataclass
class FakeLookup:
    scans: list[Scan] = field(default_factory=list)
    stored: dict[str, Sequence[Finding] | None] = field(default_factory=dict)
    roots: list[Path] = field(default_factory=list)

    def latest(self, project_root: Path) -> Scan | None:
        self.roots.append(project_root)
        finished = [scan for scan in self.scans if scan.status is ScanStatus.COMPLETED]
        return max(finished, key=lambda scan: scan.started_at, default=None)

    def get(self, scan_id: str) -> Scan | None:
        return next((scan for scan in self.scans if scan.id == scan_id), None)

    def findings(self, scan_id: str) -> Sequence[Finding] | None:
        return self.stored.get(scan_id)


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


@pytest.fixture
def renderers() -> dict[str, FakeRenderer]:
    return {"html": FakeRenderer("html", b"<html>"), "pdf": FakeRenderer(".pdf", b"%PDF")}


@pytest.fixture
def lookup() -> FakeLookup:
    scan = make_scan()
    return FakeLookup(scans=[scan], stored={scan.id: [make_finding()]})


@pytest.fixture
def backends_installed(
    monkeypatch: pytest.MonkeyPatch, renderers: dict[str, FakeRenderer], lookup: FakeLookup
) -> None:
    fake_backend(monkeypatch, LOOKUP, lambda _state_dir: lookup)
    fake_backend(monkeypatch, DOCUMENT, lambda scan, findings: (scan.id, len(findings)))
    fake_backend(monkeypatch, REGISTRY, lambda: FakeRegistry(renderers))


def report(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["report", str(project), *args], cwd=project, **kwargs)


# parse_formats


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ([], ()),
        (["html,pdf"], ("html", "pdf")),
        (["html", "pdf"], ("html", "pdf")),
        (["HTML, pdf"], ("html", "pdf")),
        ([" ,html,, ", ""], ("html",)),
        (["pdf,html", "HTML", "sarif,pdf"], ("pdf", "html", "sarif")),
    ],
)
def test_parse_formats(values: list[str], expected: tuple[str, ...]) -> None:
    assert parse_formats(values) == expected


def test_human_size() -> None:
    assert [human_size(size) for size in (0, 999, 1000, 412_000, 1_100_000)] == [
        "0 B",
        "999 B",
        "1 kB",
        "412 kB",
        "1.1 MB",
    ]


# rendering


def test_two_formats_are_written_and_listed(
    cli: Cli, project: Path, backends_installed: None, lookup: FakeLookup
) -> None:
    result = report(cli, project, "--format", "html,pdf", "--output-dir", "out")
    assert result.exit_code == 0, result.stderr
    html, pdf = project / "out" / "report.html", project / "out" / "report.pdf"
    assert html.read_bytes().startswith(b"<html>")
    assert pdf.read_bytes().startswith(b"%PDF")
    assert_matches_golden(result.stdout, GOLDEN)
    assert lookup.roots == [load_settings(target=project, env={}).project_root]
    if os.name != "nt":
        assert stat.S_IMODE(html.stat().st_mode) == REPORT_FILE_MODE
        assert stat.S_IMODE(html.parent.stat().st_mode) == REPORT_DIR_MODE


def test_format_spellings_are_equivalent(cli: Cli, project: Path, backends_installed: None) -> None:
    repeated = report(cli, project, "--format", "html", "--format", "pdf", "--json")
    joined = report(cli, project, "--format", "HTML, pdf", "--json")
    assert repeated.exit_code == joined.exit_code == 0
    assert repeated.json["data"] == joined.json["data"]


def test_json_lists_paths_sizes_and_hashes(
    cli: Cli, project: Path, backends_installed: None
) -> None:
    result = report(
        cli, project, "--format", "html,pdf", "--output-dir", "out", "--name", "audit", "--json"
    )
    data = result.json["data"]
    assert data["scan_id"] == SCAN_ID
    assert [item["format"] for item in data["files"]] == ["html", "pdf"]
    for item in data["files"]:
        path = Path(item["path"])
        assert path.name == f"audit.{item['format']}"
        assert set(item) == {"format", "path", "size_bytes", "sha256", "status"}
        assert item["status"] == "written"
        assert item["size_bytes"] == path.stat().st_size
        assert item["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "<html>" not in result.stdout


def test_default_formats_and_directory_come_from_settings(
    cli: Cli, project: Path, backends_installed: None, renderers: dict[str, FakeRenderer]
) -> None:
    (project / "codekavach.toml").write_text(
        '[reporting]\nformats = ["pdf"]\noutput_dir = "reports"\n', encoding="utf-8"
    )
    result = report(cli, project)
    assert result.exit_code == 0, result.stderr
    assert (project / "reports" / "report.pdf").is_file()
    assert (renderers["pdf"].calls, renderers["html"].calls) == (1, 0)


# errors


def test_unknown_format(cli: Cli, project: Path, backends_installed: None) -> None:
    result = report(cli, project, "--format", "docx")
    assert result.exit_code == 2
    assert "error[unknown_format]" in result.stderr
    assert "html, pdf" in result.stderr


def test_no_stored_scan(
    cli: Cli, project: Path, backends_installed: None, lookup: FakeLookup
) -> None:
    lookup.scans.clear()
    result = report(cli, project, "--format", "html")
    assert result.exit_code == 2
    assert "error[scan_not_found]" in result.stderr
    assert "run codekavach scan first" in result.stderr
    assert report(cli, project, "--format", "html", "--scan", new_scan_id()).exit_code == 2


def test_latest_skips_cancelled_scans(
    cli: Cli, project: Path, backends_installed: None, lookup: FakeLookup
) -> None:
    newer = make_scan(
        id=new_scan_id(),
        status=ScanStatus.CANCELLED,
        started_at=FIXED_NOW + timedelta(days=1),
        finished_at=FIXED_NOW + timedelta(days=1, seconds=2),
        summary=None,
    )
    lookup.scans.append(newer)
    result = report(cli, project, "--format", "html", "--json")
    assert result.json["data"]["scan_id"] == SCAN_ID
    named = report(cli, project, "--format", "html", "--scan", newer.id)
    assert named.exit_code == 2
    assert "error[scan_incomplete]" in named.stderr


def test_output_dir_must_be_a_usable_directory(
    cli: Cli, project: Path, backends_installed: None
) -> None:
    (project / "taken").write_text("x", encoding="utf-8")
    a_file = report(cli, project, "--format", "html", "--output-dir", "taken")
    assert (a_file.exit_code, "error[output_dir_invalid]" in a_file.stderr) == (2, True)
    inside = report(cli, project, "--format", "html", "--output-dir", ".codekavach/reports")
    assert (inside.exit_code, "error[output_dir_invalid]" in inside.stderr) == (2, True)
    assert cli(["report", str(project / "missing"), "--format", "html"]).exit_code == 2


def test_failing_renderer_is_reported_without_its_text(
    cli: Cli, project: Path, backends_installed: None, renderers: dict[str, FakeRenderer]
) -> None:
    renderers["html"].error = RuntimeError(f"template error near {SNIPPET}")
    result = report(cli, project, "--format", "html,pdf", "--output-dir", "out")
    assert result.exit_code == 4
    assert "error[render_failed]" in result.stderr
    assert "codekavach doctor --category report" in result.stderr
    assert "failed (render_error)" in result.stdout
    assert (project / "out" / "report.pdf").is_file()
    assert SNIPPET not in result.stdout + result.stderr
    assert "template error" not in result.stdout + result.stderr
    machine = report(cli, project, "--format", "html,pdf", "--output-dir", "out", "--json")
    files = machine.json["data"]["files"]
    assert [(item["format"], item["status"]) for item in files] == [
        ("html", "failed"),
        ("pdf", "written"),
    ]
    assert files[0]["reason_code"] == "render_error"
    assert SNIPPET not in machine.stdout
    assert machine.json["exit_code"] == 4


def test_prerequisite_failure_and_fail_fast(
    cli: Cli, project: Path, backends_installed: None, renderers: dict[str, FakeRenderer]
) -> None:
    renderers["pdf"].error = PrerequisiteMissingError("libpango not found")
    result = report(cli, project, "--format", "pdf,html", "--output-dir", "out", "--fail-fast")
    assert result.exit_code == 4
    assert "failed (weasyprint_missing)" in result.stdout
    assert "libpango" not in result.stdout + result.stderr
    assert renderers["html"].calls == 0
    assert not (project / "out" / "report.html").exists()


def test_no_overwrite_keeps_existing_files(
    cli: Cli, project: Path, backends_installed: None
) -> None:
    assert report(cli, project, "--format", "html", "--output-dir", "out").exit_code == 0
    before = (project / "out" / "report.html").read_bytes()
    kept = report(cli, project, "--format", "html", "--output-dir", "out", "--no-overwrite")
    assert kept.exit_code == 4
    assert "failed (file_exists)" in kept.stdout
    assert (project / "out" / "report.html").read_bytes() == before


def test_build_without_report_back_ends(cli: Cli, project: Path) -> None:
    assert ("codekavach.report.model", "build_report_document") not in backends._OVERRIDES
    result = report(cli, project, "--format", "html")
    assert result.exit_code == 2
    assert "error[backend_unavailable]" in result.stderr


# the real lookup


def test_stored_scan_lookup(tmp_path: Path) -> None:
    state = tmp_path / ".codekavach"
    lookup = open_scan_lookup(state)
    root = tmp_path / "project"
    assert lookup.latest(root) is None
    assert lookup.get(SCAN_ID) is None
    assert lookup.findings(SCAN_ID) is None
    assert not state.exists()

    recorder = ScanRecorder(StateLayout(state))
    project = make_project(id=new_project_id(), root=str(root))

    def record(status: ScanStatus, days: int, findings: list[Finding] | None) -> Scan:
        started = FIXED_NOW + timedelta(days=days)
        running = make_scan(
            id=new_scan_id(),
            project_id=project.id,
            status=ScanStatus.RUNNING,
            started_at=started,
            finished_at=None,
            summary=None,
        )
        recorder.start(project, running, stale_before=FIXED_NOW, now=started)
        finished = status in {ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS}
        final = running.finish(
            status, make_summary() if finished else None, started + timedelta(seconds=5)
        )
        recorder.finish(final, [], findings)
        return final

    stored = [
        make_finding(id=new_finding_id(), fingerprint=f"ckfp1:{index:032x}") for index in range(2)
    ]
    completed = record(ScanStatus.COMPLETED, 0, stored)
    cancelled = record(ScanStatus.CANCELLED, 2, None)
    assert lookup.latest(root) == completed
    assert lookup.latest(tmp_path / "elsewhere") is None
    assert lookup.get(cancelled.id) == cancelled
    found = lookup.findings(completed.id)
    assert found is not None
    assert {finding.id for finding in found} == {finding.id for finding in stored}
    assert lookup.findings(cancelled.id) is None
    with_errors = record(ScanStatus.COMPLETED_WITH_ERRORS, 3, [])
    assert lookup.latest(root) == with_errors
    assert lookup.findings(with_errors.id) == []
