"""``codekavach sca update``: refresh the advisory mirror (E19-01).

This module is the one allow-listed, non-LLM outbound path of the SCA feature (ADR-0003
exception, recorded in ``docs/adr/``): it fetches public vulnerability data only, sends nothing
about the project (no package names, no versions), refuses any host outside ``ALLOWED_HOSTS`` and
any non-HTTPS URL, follows redirects only to allow-listed hosts, and never runs when
``offline`` is set. Nothing here imports a provider or the LLM layer.
"""

import json
import urllib.request  # I1 exception: see the module docstring and pyproject per-file ignores
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from urllib.parse import urlparse

OSV_BASE: Final = "https://osv-vulnerabilities.storage.googleapis.com"
KEV_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_URL: Final = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
ALLOWED_HOSTS: Final = frozenset(
    {
        "osv-vulnerabilities.storage.googleapis.com",
        "www.cisa.gov",
        "epss.empiricalsecurity.com",
    }
)
DEFAULT_ECOSYSTEMS: Final = ("PyPI", "npm", "Maven", "Go", "RubyGems", "Packagist", "crates.io")
MAX_BYTES: Final = 600 * 1024 * 1024
TIMEOUT: Final = 120


class OfflineError(RuntimeError):
    """An update was requested while ``--offline`` is in force."""


def _check_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"refusing to fetch from a host that is not allow-listed: {parsed.hostname}"
        )


class _AllowListRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str, dest: Path) -> int:
    _check_url(url)
    opener = urllib.request.build_opener(_AllowListRedirects)
    request = urllib.request.Request(url, headers={"User-Agent": "codekavach-sca-update"})  # noqa: S310
    tmp = dest.with_suffix(dest.suffix + ".part")
    size = 0
    with opener.open(request, timeout=TIMEOUT) as response, tmp.open("wb") as out:
        while chunk := response.read(1 << 20):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("download exceeds the size limit")
            out.write(chunk)
    tmp.replace(dest)
    return size


@dataclass(frozen=True)
class UpdateResult:
    """What one update fetched."""

    fetched: dict[str, int]
    failed: dict[str, str]
    directory: Path


def update_mirror(
    directory: Path,
    ecosystems: tuple[str, ...] = DEFAULT_ECOSYSTEMS,
    *,
    offline: bool = False,
    kev: bool = True,
    epss: bool = True,
) -> UpdateResult:
    """Download OSV snapshots, the KEV catalogue and the EPSS scores into ``directory``."""
    if offline:
        raise OfflineError("sca update opens a connection; it is refused with --offline")
    (directory / "osv").mkdir(parents=True, exist_ok=True)
    jobs: dict[str, tuple[str, Path]] = {
        f"osv:{eco}": (f"{OSV_BASE}/{eco}/all.zip", directory / "osv" / f"{eco}.zip")
        for eco in ecosystems
    }
    if kev:
        jobs["kev"] = (KEV_URL, directory / "kev.json")
    if epss:
        jobs["epss"] = (EPSS_URL, directory / "epss.csv.gz")
    fetched: dict[str, int] = {}
    failed: dict[str, str] = {}
    for name, (url, dest) in jobs.items():
        try:
            fetched[name] = _fetch(url, dest)
        except Exception as error:  # noqa: BLE001 - one source failing must not lose the rest
            failed[name] = type(error).__name__
    if fetched:
        (directory / "snapshot.json").write_text(
            json.dumps({"date": datetime.now(UTC).date().isoformat(), "sources": sorted(fetched)}),
            encoding="utf-8",
        )
    return UpdateResult(fetched, failed, directory)
