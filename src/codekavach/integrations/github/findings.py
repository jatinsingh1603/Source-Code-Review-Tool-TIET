"""A neutral view of a finding for the GitHub integration, with masking.

Owning epic: E34.

The integration accepts a ``Finding`` model, its JSON dump, or the server's finding dictionary and
turns each into a ``FindingView``. Only metadata and a masked snippet survive: nothing from the
vault is ever read, and secret-looking tokens in a snippet are replaced before it is stored.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

SEVERITIES: Final = ("info", "low", "medium", "high", "critical")
_SECRET: Final = re.compile(
    r"(?i)(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}"
    r"|sk-[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_ASSIGNED: Final = re.compile(
    r"""(?ix)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|auth)\b(\s*[:=]\s*)
        (["']?)([^\s"',;)]{4,})(\3)"""
)
MAX_SNIPPET_LINES: Final = 12


def mask_text(text: str) -> str:
    """Replace secret-like values in ``text`` with a placeholder."""
    text = _SECRET.sub("[REDACTED]", text)
    return _ASSIGNED.sub(lambda m: f"{m[1]}{m[2]}{m[3]}[REDACTED]{m[5]}", text)


@dataclass(frozen=True)
class FindingView:
    """What the GitHub features need to know about one finding."""

    fingerprint: str
    id: str
    title: str
    severity: str
    confidence: str = ""
    status: str = "open"
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    rule_id: str = ""
    description: str = ""
    remediation: str = ""
    path: str = ""
    start_line: int = 1
    end_line: int = 1
    snippet: tuple[tuple[int, str], ...] = field(default=())
    references: tuple[str, ...] = ()

    @property
    def is_open(self) -> bool:
        """Open and confirmed findings are reported; the rest are resolved."""
        return self.status in ("open", "confirmed")

    @property
    def rank(self) -> int:
        """Severity as a number, higher is worse."""
        return SEVERITIES.index(self.severity) if self.severity in SEVERITIES else 0


def _dump(item: Any) -> Mapping[str, Any]:
    if isinstance(item, Mapping):
        return item
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        data: Mapping[str, Any] = dump(mode="json")
        return data
    raise TypeError(f"cannot read a finding from {type(item).__name__}")


def _ref_ids(items: Iterable[Any] | None) -> tuple[str, ...]:
    out = [str(r.get("id", "")) if isinstance(r, Mapping) else str(r) for r in items or ()]
    return tuple(x for x in out if x)


def _snippet(data: Mapping[str, Any], start: int, end: int) -> tuple[tuple[int, str], ...]:
    evidence = data.get("evidence")
    lines: list[tuple[int, str]] = []
    if isinstance(evidence, Mapping) and isinstance(evidence.get("snippet"), str):
        lines = [(start + i, t) for i, t in enumerate(evidence["snippet"].splitlines())]
    elif isinstance(evidence, list) and evidence and isinstance(evidence[0], Mapping):
        lines = [
            (int(x["number"]), str(x.get("text", ""))) for x in evidence[0].get("lines", ()) or ()
        ]
    keep = [(n, t) for n, t in lines if start - 2 <= n <= end + 2] or lines
    return tuple((n, mask_text(t)) for n, t in keep[:MAX_SNIPPET_LINES])


def normalize(item: Any) -> FindingView:
    """Build a ``FindingView`` from a model or a dictionary."""
    data = _dump(item)
    locations = data.get("locations") or []
    loc: Mapping[str, Any] = locations[0] if locations else {}
    start = int(loc.get("start_line") or 1)
    end = int(loc.get("end_line") or start)
    llm = data.get("llm") or data.get("llm_verdict") or {}
    prov = data.get("provenance") or {}
    engines = prov.get("engines") or []
    rule = data.get("rule_id") or (engines[0].get("rule_id") if engines else "") or ""
    fingerprint = str(data.get("fingerprint") or data.get("id") or "")
    if not fingerprint:
        raise ValueError("a finding needs a fingerprint or an id")
    refs = data.get("references") or []
    return FindingView(
        fingerprint=fingerprint,
        id=str(data.get("id") or fingerprint),
        title=mask_text(str(data.get("title") or "Finding"))[:200],
        severity=str(data.get("severity") or "info").lower(),
        confidence=str(data.get("confidence") or ""),
        status=str(data.get("status") or "open").lower(),
        cwe=tuple(f"CWE-{c}" if str(c).isdigit() else str(c) for c in data.get("cwe") or ()),
        owasp=_ref_ids(data.get("owasp")),
        rule_id=str(rule),
        description=mask_text(str(data.get("description") or llm.get("reasoning") or ""))[:3000],
        remediation=mask_text(str(data.get("remediation") or llm.get("remediation") or ""))[:3000],
        path=str(loc.get("path") or ""),
        start_line=start,
        end_line=end,
        snippet=_snippet(data, start, end),
        references=tuple(
            str(r.get("url") or r.get("id") or "") if isinstance(r, Mapping) else str(r)
            for r in refs
        ),
    )


def normalize_all(findings: Iterable[Any]) -> list[FindingView]:
    """Normalise a collection, dropping duplicate fingerprints (first one wins)."""
    seen: dict[str, FindingView] = {}
    for item in findings:
        view = normalize(item)
        seen.setdefault(view.fingerprint, view)
    return list(seen.values())


def scan_findings(scan: Any) -> list[Any]:
    """The raw findings of a scan object, a ``{"findings": [...]}`` dictionary or a list."""
    if isinstance(scan, Mapping):
        return list(scan.get("findings") or [])
    if isinstance(scan, (list, tuple)):
        return list(scan)
    return list(getattr(scan, "findings", ()) or ())
