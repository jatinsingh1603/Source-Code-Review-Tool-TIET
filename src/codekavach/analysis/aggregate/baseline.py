"""Baseline files: the findings a team has accepted as known (#240).

``.codekavach/baseline.json`` lists fingerprints with the rule and path they were recorded for.
A candidate whose fingerprint is in the baseline is *known*: it is not sent to review again and is
reported as ``unchanged`` in the delta. The file holds no code and no secret values.
"""

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from codekavach.core.models import Candidate

BASELINE_VERSION: Final = 1
DEFAULT_RELATIVE: Final = Path(".codekavach") / "baseline.json"


def load_baseline(path: Path) -> dict[str, dict[str, str]]:
    """Fingerprint to entry; an empty mapping when the file is absent or unreadable."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        entries = document.get("entries", [])
        return {
            str(e["fingerprint"]): {k: str(v) for k, v in e.items()}
            for e in entries
            if isinstance(e, dict) and "fingerprint" in e
        }
    except (OSError, ValueError, AttributeError):
        return {}


def write_baseline(path: Path, candidates: Iterable[Candidate]) -> int:
    """Record ``candidates`` as the baseline; returns the number of entries."""
    entries = [
        {
            "fingerprint": c.fingerprint,
            "rule_id": c.rule_id,
            "path": c.primary_location.path,
            "line": str(c.primary_location.start_line),
        }
        for c in sorted(
            candidates, key=lambda c: (c.primary_location.path, c.primary_location.start_line)
        )
    ]
    document = {
        "version": BASELINE_VERSION,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "entries": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    return len(entries)


def write_entries(path: Path, entries: Iterable[dict[str, str]]) -> int:
    """Record ready-made entries (fingerprint, rule_id, path, line) as the baseline."""
    ordered = sorted(
        entries, key=lambda e: (e.get("path", ""), e.get("line", ""), e["fingerprint"])
    )
    document = {
        "version": BASELINE_VERSION,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "entries": ordered,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    return len(ordered)
