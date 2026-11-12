"""Exploitation signals and local CVSS recomputation (E19-02).

Every number carries its source and snapshot date. The snapshots are plain files written by
``codekavach sca update``: ``kev.json`` (CISA Known Exploited Vulnerabilities) and
``epss.csv.gz`` / ``epss.csv`` (FIRST EPSS). With no snapshot the signal is reported as
unavailable, never as zero. The CVSS v3.1 base score is recomputed here from the advisory's own
vector instead of being trusted.
"""

import csv
import gzip
import json
import math
from dataclasses import dataclass
from pathlib import Path

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31_score(vector: str) -> float | None:
    """The CVSS v3.x base score of ``vector``, or None when it is not a valid v3 vector."""
    if not vector.startswith(("CVSS:3.1/", "CVSS:3.0/")):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["C"][m["I"]]) * (1 - _W["C"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(raw, 10.0))


@dataclass(frozen=True)
class Signals:
    """Exploitation data for one CVE, with provenance."""

    kev: bool | None  # None: no KEV snapshot
    kev_date_added: str | None
    epss: float | None
    epss_percentile: float | None
    kev_snapshot: str | None
    epss_snapshot: str | None


class Enricher:
    """Reads the KEV and EPSS snapshots under ``directory`` once."""

    def __init__(self, directory: Path) -> None:
        self.kev: dict[str, str] = {}
        self.kev_snapshot: str | None = None
        self.epss: dict[str, tuple[float, float]] = {}
        self.epss_snapshot: str | None = None
        self._load_kev(directory / "kev.json")
        self._load_epss(directory)

    def _load_kev(self, path: Path) -> None:
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text("utf-8"))
        except (ValueError, OSError):
            return
        self.kev_snapshot = str(data.get("dateReleased", ""))[:10] or "unknown"
        self.kev = {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}

    def _load_epss(self, directory: Path) -> None:
        for name in ("epss.csv.gz", "epss.csv"):
            path = directory / name
            if not path.is_file():
                continue
            opener = gzip.open if name.endswith(".gz") else open
            try:
                with opener(path, "rt", encoding="utf-8") as handle:
                    first = handle.readline()
                    if first.startswith("#"):
                        for part in first.lstrip("#").split(","):
                            if part.startswith("score_date:"):
                                self.epss_snapshot = part.split(":", 1)[1].strip()[:10]
                        header = handle.readline()
                    else:
                        header = first
                    del header
                    for row in csv.reader(handle):
                        if len(row) >= 3 and row[0].startswith("CVE-"):
                            self.epss[row[0]] = (float(row[1]), float(row[2]))
            except (OSError, ValueError):
                self.epss = {}
            return

    def signals(self, cve: str | None) -> Signals:
        """Signals for ``cve`` (None values mean a missing snapshot or an unscored CVE)."""
        if cve is None:
            return Signals(None, None, None, None, self.kev_snapshot, self.epss_snapshot)
        kev = (cve in self.kev) if self.kev_snapshot else None
        score = self.epss.get(cve)
        return Signals(
            kev,
            self.kev.get(cve) or None,
            score[0] if score else None,
            score[1] if score else None,
            self.kev_snapshot,
            self.epss_snapshot,
        )
