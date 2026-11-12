"""Exposure budgets: how much of the repository has each provider been shown (E26-01).

``ExposureAccount`` keeps, per provider and per scan, the union of line intervals disclosed, keyed
by a keyed hash of the file path (HMAC with a per-state pepper), so the stored account holds no
path and no name. ``snapshot(provider, scope="scan"|"engagement")`` returns distinct files and
lines and the percentage of the inventory; ``scope="engagement"`` unions every scan the account
has seen for that provider. ``AggregationBudget.would_exceed`` answers before a slice is prepared,
so a slice that would push the account over ``privacy.egress.aggregation_budget_pct`` is refused
(fail closed) instead of being disclosed and then noticed.

The account is a local file below the state directory (mode 0600, atomic replace). It is advisory
bookkeeping for a control, not a secret store: losing it resets the engagement figures, never the
per-scan ones, which the egress guard also enforces from the in-memory disclosure record.

Not delivered here (research notes only): slice-shape uniqueness and cover traffic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from codekavach.core.models import CodeSlice
from codekavach.privacy.slicing.metrics import IntervalSet

Scope = Literal["scan", "engagement"]
ACCOUNT_FILE: Final = "exposure.json"
PEPPER_BYTES: Final = 32
_PERCENT: Final = 100.0


@dataclass(frozen=True, slots=True)
class ExposureSnapshot:
    """Distinct files and lines disclosed to one provider within a scope."""

    provider_id: str
    scope: Scope
    files: int
    lines: int
    repo_lines: int

    @property
    def pct(self) -> float:
        """Disclosed lines as a percentage of the inventory."""
        return self.lines / self.repo_lines * _PERCENT if self.repo_lines else 0.0


@dataclass(frozen=True, slots=True)
class AggregationBudget:
    """A ceiling, in percent of the inventory, per scan and per engagement."""

    scan_pct: float = 100.0
    engagement_pct: float = 100.0

    @property
    def active(self) -> bool:
        """True when any ceiling is below 100 percent."""
        return self.scan_pct < _PERCENT or self.engagement_pct < _PERCENT


class ExposureAccount:
    """Per-provider, per-scan exposure of one repository, path-free on disk."""

    def __init__(self, repo_lines: int, *, path: Path | None = None) -> None:
        self._repo_lines = max(repo_lines, 1)
        self._path = path
        self._pepper = secrets.token_bytes(PEPPER_BYTES)
        # provider -> scan -> file key -> intervals
        self._data: dict[str, dict[str, dict[str, IntervalSet]]] = {}
        if path is not None:
            self._load(path)

    # ---- persistence -------------------------------------------------------------------

    def _load(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            self._pepper = bytes.fromhex(raw["pepper"])
            for provider, scans in raw["data"].items():
                for scan, files in scans.items():
                    for key, spans in files.items():
                        bucket = self._data.setdefault(provider, {}).setdefault(scan, {})
                        for start, end in spans:
                            bucket.setdefault(key, IntervalSet()).add(start, end)
        except (OSError, ValueError, KeyError, TypeError):
            self._data = {}  # unreadable: start over rather than fail the scan

    def save(self) -> None:
        """Write the account atomically with mode 0600; a no-op without a path."""
        if self._path is None:
            return
        body = {
            "pepper": self._pepper.hex(),
            "data": {
                provider: {
                    scan: {key: [list(i) for i in ivs.intervals()] for key, ivs in files.items()}
                    for scan, files in scans.items()
                }
                for provider, scans in self._data.items()
            },
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(f".{self._path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(body, handle)
        tmp.replace(self._path)

    # ---- recording and reading ---------------------------------------------------------

    def _key(self, path: str) -> str:
        return hmac.new(self._pepper, path.encode(), hashlib.sha256).hexdigest()[:24]

    def record(self, scan_id: str, provider_id: str, slice_: CodeSlice) -> None:
        """Add the lines of ``slice_`` to the account of ``provider_id`` in ``scan_id``."""
        bucket = self._data.setdefault(provider_id, {}).setdefault(scan_id, {})
        for segment in slice_.segments:
            bucket.setdefault(self._key(segment.path), IntervalSet()).add(
                segment.region.start_line, segment.region.end_line
            )

    def _union(self, provider_id: str, scan_id: str | None) -> dict[str, IntervalSet]:
        merged: dict[str, IntervalSet] = {}
        scans = self._data.get(provider_id, {})
        for name, files in scans.items():
            if scan_id is not None and name != scan_id:
                continue
            for key, ivs in files.items():
                target = merged.setdefault(key, IntervalSet())
                for start, end in ivs.intervals():
                    target.add(start, end)
        return merged

    def snapshot(
        self, provider_id: str, *, scope: Scope, scan_id: str | None = None
    ) -> ExposureSnapshot:
        """Distinct files and lines for ``provider_id``; ``scope="scan"`` needs ``scan_id``."""
        if scope == "scan" and scan_id is None:
            raise ValueError("a scan-scoped snapshot needs a scan id")
        merged = self._union(provider_id, scan_id if scope == "scan" else None)
        lines = sum(ivs.total for ivs in merged.values())
        return ExposureSnapshot(provider_id, scope, len(merged), lines, self._repo_lines)

    def would_reach_pct(
        self, scan_id: str, provider_id: str, slice_: CodeSlice, scope: Scope
    ) -> float:
        """The percentage after ``slice_`` would be added; nothing is recorded."""
        merged = self._union(provider_id, scan_id if scope == "scan" else None)
        extra = 0
        for segment in slice_.segments:
            known = merged.get(self._key(segment.path))
            start, end = segment.region.start_line, segment.region.end_line
            extra += (end - start + 1) - (known.covered(start, end) if known else 0)
        lines = sum(ivs.total for ivs in merged.values()) + extra
        return lines / self._repo_lines * _PERCENT

    def would_exceed(
        self, budget: AggregationBudget, scan_id: str, provider_id: str, slice_: CodeSlice
    ) -> bool:
        """True when disclosing ``slice_`` would pass a ceiling of ``budget``."""
        if budget.scan_pct < _PERCENT and (
            self.would_reach_pct(scan_id, provider_id, slice_, "scan") > budget.scan_pct
        ):
            return True
        return budget.engagement_pct < _PERCENT and (
            self.would_reach_pct(scan_id, provider_id, slice_, "engagement") > budget.engagement_pct
        )
