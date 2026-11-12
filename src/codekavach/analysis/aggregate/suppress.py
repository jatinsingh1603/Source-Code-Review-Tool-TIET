"""Suppressions with a mandatory justification (#240).

Inline: a comment ``codekavach:ignore[<rule-or-CWE>,...] -- <justification>`` on the finding's line
or the line above (``#``, ``//``, ``--`` and ``/* */`` styles all work, only the marker is matched)
is matched). A suppression without a justification is ignored and reported as such, so a bare
``ignore`` never silences anything.

File: ``.codekavach/suppressions.yaml``::

    suppressions:
      - rule: iac.docker.root-user        # rule id, CWE-<n>, or "*"
        path: deploy/**                    # glob
        justification: "Sidecar runs in a locked-down namespace."
        expires: 2027-03-01                # optional ISO date

Suppressed candidates are removed from the scan, and every one is recorded with its justification
in the aggregate report so the audit trail shows what was silenced and why.
"""

import fnmatch
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Final

import yaml

from codekavach.core.models import Candidate

_INLINE: Final = re.compile(
    r"codekavach:ignore(?:\[(?P<ids>[^\]]*)\])?\s*(?:(?:--|:|-)\s*(?P<why>\S.*?))?\s*(?:\*/|-->)?\s*$",
    re.I,
)
_COMMENT_STARTS: Final = ("#", "//", "--", "/*", "<!--", ";")
DEFAULT_RELATIVE: Final = Path(".codekavach") / "suppressions.yaml"


@dataclass(frozen=True)
class Suppression:
    """One suppression decision: which candidate, by what means, and why."""

    fingerprint: str
    rule_id: str
    path: str
    line: int
    justification: str
    source: str  # "inline" or "file"


@dataclass(frozen=True)
class FileRule:
    """One entry of the suppressions file."""

    rule: str
    path: str
    justification: str
    expires: date | None = None


def load_file_rules(path: Path, *, today: date | None = None) -> list[FileRule]:
    """The valid, unexpired entries of the suppressions file (no justification: dropped)."""
    try:
        document: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    items = document.get("suppressions", []) if isinstance(document, dict) else []
    now = today or date.today()  # noqa: DTZ011 - a calendar date in the scanner's local zone
    rules: list[FileRule] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        why = str(item.get("justification", "")).strip()
        rule = str(item.get("rule", "")).strip()
        if not why or not rule:
            continue
        expires = item.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                expires = None
        if isinstance(expires, date) and expires < now:
            continue
        rules.append(FileRule(rule, str(item.get("path", "**")), why, expires))
    return rules


def _matches(rule: str, candidate: Candidate) -> bool:
    rule = rule.strip()
    if rule in {"*", candidate.rule_id}:
        return True
    if rule.upper().startswith("CWE-") and rule[4:].isdigit():
        return int(rule[4:]) in candidate.cwe
    return fnmatch.fnmatch(candidate.rule_id, rule)


def inline_justification(lines: list[str], candidate: Candidate) -> str | None:
    """The justification of an inline suppression that covers ``candidate``, else None."""
    line = candidate.primary_location.start_line
    for number in (line, line - 1):
        if not 1 <= number <= len(lines):
            continue
        match = _INLINE.search(lines[number - 1].rstrip())
        if match is None:
            continue
        if number == line - 1 and not lines[number - 1].lstrip().startswith(_COMMENT_STARTS):
            continue  # the line above counts only when it is a comment of its own
        ids = match.group("ids")
        if ids and not any(_matches(i, candidate) for i in ids.split(",") if i.strip()):
            continue
        why = (match.group("why") or "").strip()
        return why or None
    return None


def apply_suppressions(
    candidates: list[Candidate], root: Path, rules: list[FileRule]
) -> tuple[list[Candidate], list[Suppression], list[tuple[str, int]]]:
    """Split ``candidates`` into kept ones, applied suppressions and unjustified markers."""
    kept: list[Candidate] = []
    applied: list[Suppression] = []
    unjustified: list[tuple[str, int]] = []
    cache: dict[str, list[str]] = {}
    for candidate in candidates:
        place = candidate.primary_location
        reason: str | None = None
        source = ""
        for rule in rules:
            if _matches(rule.rule, candidate) and fnmatch.fnmatch(place.path, rule.path):
                reason, source = rule.justification, "file"
                break
        if reason is None:
            if place.path not in cache:
                try:
                    text = (root / place.path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                cache[place.path] = text.splitlines() if "codekavach:ignore" in text else []
            lines = cache[place.path]
            if lines:
                reason = inline_justification(lines, candidate)
                source = "inline"
                if reason is None and _has_marker(lines, place.start_line):
                    unjustified.append((place.path, place.start_line))
        if reason is None:
            kept.append(candidate)
        else:
            applied.append(
                Suppression(
                    candidate.fingerprint,
                    candidate.rule_id,
                    place.path,
                    place.start_line,
                    reason,
                    source,
                )
            )
    return kept, applied, unjustified


def _has_marker(lines: list[str], line: int) -> bool:
    return any(
        1 <= n <= len(lines) and "codekavach:ignore" in lines[n - 1] for n in (line, line - 1)
    )


def describe_file_rules(path: Path, *, today: date | None = None) -> list[dict[str, str]]:
    """Every entry of the suppressions file with its state: active, expired or invalid.

    ``invalid`` means the entry has no rule or no justification, so it silences nothing.
    """
    try:
        document: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    items = document.get("suppressions", []) if isinstance(document, dict) else []
    now = today or date.today()  # noqa: DTZ011 - a calendar date in the scanner's local zone
    rows: list[dict[str, str]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        why = str(item.get("justification", "")).strip()
        rule = str(item.get("rule", "")).strip()
        expires = item.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                expires = None
        state = "invalid" if not why or not rule else "active"
        if state == "active" and isinstance(expires, date) and expires < now:
            state = "expired"
        rows.append(
            {
                "source": "file",
                "rule": rule,
                "path": str(item.get("path", "**")),
                "justification": why,
                "expires": expires.isoformat() if isinstance(expires, date) else "",
                "state": state,
            }
        )
    return rows


def inline_markers(text: str, path: str) -> list[dict[str, str]]:
    """Every ``codekavach:ignore`` marker in ``text``; ``state`` is invalid without a reason."""
    if "codekavach:ignore" not in text:
        return []
    rows: list[dict[str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if "codekavach:ignore" not in line:
            continue
        match = _INLINE.search(line.rstrip())
        if match is None:
            continue
        why = (match.group("why") or "").strip()
        rows.append(
            {
                "source": "inline",
                "rule": (match.group("ids") or "*").strip(),
                "path": f"{path}:{number}",
                "justification": why,
                "expires": "",
                "state": "active" if why else "invalid",
            }
        )
    return rows
