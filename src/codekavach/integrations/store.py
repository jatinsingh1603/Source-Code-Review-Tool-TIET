"""Read a stored scan and its findings for the integrations (GitHub, MCP, IDE export).

Owning epic: E34.

Read-only access to the local database through the stored-scan lookup. Findings are returned as
plain dictionaries that carry metadata and the evidence lines the scan already holds; the vault
is not touched, so original identifiers or secrets that were replaced never appear here.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ScanNotFoundError(LookupError):
    """No stored scan matches."""


@dataclass(frozen=True)
class StoredScan:
    """A stored scan with its findings as dictionaries."""

    scan_id: str
    state_dir: Path
    findings: list[dict[str, Any]]
    summary: dict[str, Any]


def load_scan(target: Path, settings: Any, scan: str = "latest") -> StoredScan:
    """The scan ``scan`` (an id or ``latest``) of the project at ``target``.

    Raises:
        ScanNotFoundError: there is no such finished scan.
    """
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415
    from codekavach.core.store.repositories import open_scan_lookup  # noqa: PLC0415

    root = target.resolve()
    state_dir = resolve_state_dir(root, settings.project.state_dir)
    lookup = open_scan_lookup(state_dir)
    stored = lookup.latest(root) if scan == "latest" else lookup.get(scan)
    if stored is None:
        raise ScanNotFoundError("no stored scan found; run codekavach scan first")
    findings = lookup.findings(str(stored.id))
    if findings is None:
        raise ScanNotFoundError("the scan did not finish; it has no findings")
    dumped = [f.model_dump(mode="json") for f in findings]
    by_severity: dict[str, int] = {}
    for item in dumped:
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
    return StoredScan(
        scan_id=str(stored.id),
        state_dir=state_dir,
        findings=dumped,
        summary={"findings_total": len(dumped), "by_severity": by_severity},
    )
