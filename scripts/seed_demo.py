#!/usr/bin/env python3
"""Seed a running CodeKavach server with demo data, using only its REST API.

    uv run codekavach serve &                      # dashboard and API on http://127.0.0.1:8080
    uv run python scripts/seed_demo.py             # about two minutes

What it does, in order (every number on the dashboard is the output of a real scan; nothing is
written to the database directly):

1. Logs in as ``admin`` (password from ``--password`` or ``CODEKAVACH_ADMIN_PASSWORD``, default
   ``kavach-admin``).
2. Makes sure three projects exist: the KavachBank sample the server already seeds, plus
   ``fixtures/demo-ledgerly`` (Python) and ``fixtures/demo-shopfront`` (Node), the last two as
   path sources over a scratch copy of the fixture.
3. Runs scans with the offline ``mock`` provider at different privacy levels: KavachBank at L1, L2
   and L3; Ledgerly at L2, then again at L3 after a few of its planted flaws are really fixed in
   the scratch copy; Shopfront at L3, then L0 (nothing leaves the machine), then L3 after fixes.
4. Triages findings the way a reviewer would, through ``PATCH /findings/{id}``: findings that a
   re-scan no longer reports are marked ``fixed``; a few high-severity ones ``confirmed``; one low
   one a ``false_positive`` and one an ``accepted_risk`` on KavachBank. The triage choices are the
   script's, the findings are the scanner's.

Safe to run twice: projects that already have scans are skipped unless ``--again`` is given.
Needs no API key and opens no connection except to the server. Requires a checkout (it reads
``fixtures/``). Python standard library only.
"""

# ruff: noqa: T201, D102, D103
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

REPO = Path(__file__).resolve().parents[1]
DEFAULT_PASSWORD = "kavach-admin"  # noqa: S105 - the documented demo default, not a secret
SAMPLE_ID = "prj_kavachbank_sample"
TERMINAL = {"completed", "failed", "cancelled"}

LEDGERLY_FIXES: tuple[tuple[str, str, str], ...] = (
    (
        "app/db.py",
        '    query = "SELECT id, total FROM invoices WHERE customer = \'" + customer + "\'"\n'
        "    cur = conn.cursor()\n    cur.execute(query)\n",
        "    cur = conn.cursor()\n"
        '    cur.execute("SELECT id, total FROM invoices WHERE customer = ?", (customer,))\n',
    ),
    ("app/importer.py", "yaml.load(text, Loader=yaml.Loader)", "yaml.safe_load(text)"),
    ("app/web.py", "app.run(debug=True,", "app.run(debug=False,"),
)
SHOPFRONT_FIXES: tuple[tuple[str, str, str], ...] = (
    (
        "src/server.js",
        "const amount = eval(req.body.formula);",
        "const amount = Number(req.body.formula);",
    ),
    (
        "src/server.js",
        'path.join(__dirname, "uploads", req.query.label);',
        'path.join(__dirname, "uploads", path.basename(req.query.label));',
    ),
)


class Api:
    """A minimal JSON client for ``/api/v1`` with a bearer token."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/") + "/api/v1"
        self.token = ""

    def call(self, method: str, path: str, body: Any = None) -> Any:
        headers = {"authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            response = httpx.request(
                method, self.base + path, json=body, headers=headers, timeout=60.0
            )
        except httpx.HTTPError as error:
            raise SystemExit(f"cannot reach the server at {self.base}: {error}") from None
        if response.status_code >= 400:
            raise SystemExit(
                f"{method} {path} failed: HTTP {response.status_code} {response.text[:300]}"
            )
        return response.json() if response.content else None

    def login(self, username: str, password: str) -> None:
        self.token = self.call("POST", "/auth/login", {"username": username, "password": password})[
            "token"
        ]


def say(message: str) -> None:
    print(message, flush=True)


def wait_for_health(api: Api, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            if api.call("GET", "/health").get("status") == "ok":
                return
        except SystemExit:
            if time.monotonic() > deadline:
                raise
        time.sleep(1)


def run_scan(api: Api, project_id: str, level: str, label: str) -> dict[str, Any]:
    started = api.call(
        "POST",
        f"/projects/{project_id}/scans",
        {"privacy_level": level, "provider": "mock", "send": True},
    )
    scan = started
    while scan["status"] not in TERMINAL:
        time.sleep(2)
        scan = api.call("GET", f"/scans/{started['id']}")
    counts = scan.get("counts", {})
    summary = scan.get("privacy_summary") or {}
    say(
        f"  {label} at {level}: {scan['status']}, {scan.get('findings_total', 0)} findings "
        f"({counts.get('critical', 0)} critical, {counts.get('high', 0)} high), "
        f"{summary.get('payloads', 0)} payloads, {summary.get('blocked', 0)} blocked"
    )
    if scan["status"] != "completed":
        say(f"    warning: scan ended as {scan['status']}: {scan.get('error')}")
    return scan


def findings_of(api: Api, scan_id: str) -> list[dict[str, Any]]:
    return api.call("GET", f"/scans/{scan_id}/findings")


def triage(api: Api, finding: dict[str, Any], status: str, comment: str) -> None:
    api.call("PATCH", f"/findings/{finding['id']}", {"status": status, "comment": comment})


def mark_fixed(api: Api, before: dict[str, Any], after: dict[str, Any]) -> int:
    """Mark the findings of ``before`` that ``after`` no longer reports as fixed."""
    still = {item["fingerprint"] for item in findings_of(api, after["id"])}
    count = 0
    for item in findings_of(api, before["id"]):
        if item["fingerprint"] not in still and item["status"] == "open":
            triage(api, item, "fixed", f"Not reported by the re-scan {after['id']}.")
            count += 1
    return count


def confirm_top(api: Api, scan: dict[str, Any], limit: int) -> int:
    """Confirm the most severe open findings of a scan (the list is sorted most severe first)."""
    count = 0
    for item in findings_of(api, scan["id"]):
        if count >= limit:
            break
        if item["status"] == "open" and item["severity"] in {"critical", "high"}:
            triage(api, item, "confirmed", "Reproduced by the reviewer; fix scheduled.")
            count += 1
    return count


def mark_negative_controls(api: Api, scan: dict[str, Any], fixture: str) -> int:
    """Mark findings on a ground-truth negative control (safe code) as false positives."""
    manifest = REPO / "fixtures" / fixture / "ground-truth" / "manifest.yaml"
    controls = yaml.safe_load(manifest.read_text(encoding="utf-8")).get("negative_controls", [])
    count = 0
    for item in findings_of(api, scan["id"]):
        for control in controls:
            near = abs((item["line"] or 0) - control["line"]) <= 1
            if item["path"] == control["file"] and near and item["status"] == "open":
                note = f"Safe code: {control['note']} (ground-truth negative control)."
                triage(api, item, "false_positive", note)
                count += 1
    return count


def apply_fixes(root: Path, fixes: tuple[tuple[str, str, str], ...]) -> None:
    for relative, old, new in fixes:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise SystemExit(f"cannot apply the fix in {relative}: the fixture has changed")
        path.write_text(text.replace(old, new), encoding="utf-8")


def copy_fixture(name: str, scratch: Path) -> Path:
    source = REPO / "fixtures" / name
    if not source.is_dir():
        raise SystemExit(f"missing {source}; run this script from a checkout of the repository")
    target = scratch / name
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("ground-truth", "cassettes"))
    return target


def find_project(api: Api, name: str) -> dict[str, Any] | None:
    return next((p for p in api.call("GET", "/projects") if p["name"] == name), None)


def ensure_project(api: Api, name: str, path: Path, description: str) -> str:
    """The id of the project called ``name``, created over ``path`` or pointed at it."""
    source = {"type": "path", "path": str(path)}
    existing = find_project(api, name)
    if existing is not None:
        api.call("PATCH", f"/projects/{existing['id']}", {"source": source})
        return existing["id"]
    body = {"name": name, "description": description, "source": source}
    return api.call("POST", "/projects", body)["id"]


def seed(api: Api, scratch: Path, again: bool) -> None:
    say("KavachBank (sample)")
    sample = next((p for p in api.call("GET", "/projects") if p["id"] == SAMPLE_ID), None)
    if sample is None:
        say("  the sample project is missing; start the server from a checkout so it seeds it")
    elif sample["scan_count"] and not again:
        say("  already has scans, skipped (use --again)")
    else:
        scans = [run_scan(api, SAMPLE_ID, level, "KavachBank") for level in ("L1", "L2", "L3")]
        latest = findings_of(api, scans[-1]["id"])
        confirmed = confirm_top(api, scans[-1], 4)
        lows = [f for f in latest if f["severity"] in {"low", "medium"} and f["status"] == "open"]
        if lows:
            triage(
                api, lows[-1], "false_positive", "Test fixture path; not reachable in production."
            )
        if len(lows) > 1:
            triage(api, lows[-2], "accepted_risk", "Accepted by the owner until the next release.")
        say(f"  triaged: {confirmed} confirmed, {min(len(lows), 2)} low or medium triaged")

    for name, fixture, fixes, levels, blurb in (
        (
            "Ledgerly (demo)",
            "demo-ledgerly",
            LEDGERLY_FIXES,
            ("L2", "L3"),
            "Synthetic Python invoice service with planted flaws (fixtures/demo-ledgerly).",
        ),
        (
            "Shopfront (demo)",
            "demo-shopfront",
            SHOPFRONT_FIXES,
            ("L3", "L0", "L3"),
            "Synthetic Node storefront with planted flaws (fixtures/demo-shopfront).",
        ),
    ):
        say(name)
        existing = find_project(api, name)
        if existing is not None and existing["scan_count"] and not again:
            say("  already has scans, skipped (use --again)")
            continue
        work = copy_fixture(fixture, scratch)
        project_id = ensure_project(api, name, work, blurb)
        # Run the scans against the unfixed code first, then fix some flaws and re-scan.
        first = run_scan(api, project_id, levels[0], name)
        extra = [run_scan(api, project_id, level, name) for level in levels[1:-1]]
        apply_fixes(work, fixes)
        last = run_scan(api, project_id, levels[-1], name)
        fixed = mark_fixed(api, first, last)
        false_positives = mark_negative_controls(api, last, fixture)
        confirmed = confirm_top(api, last, 3)
        say(
            f"  triaged: {fixed} fixed (gone after the fixes), {false_positives} false positive "
            f"(negative control), {confirmed} confirmed"
        )
        _ = extra


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url", default=os.environ.get("CODEKAVACH_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--username", default="admin")
    parser.add_argument(
        "--password",
        default=os.environ.get("CODEKAVACH_ADMIN_PASSWORD", DEFAULT_PASSWORD),
        help="admin password (default: $CODEKAVACH_ADMIN_PASSWORD or the demo default)",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path.home() / ".cache" / "codekavach-demo",
        help="where the scratch copies of the sample projects live; the projects point at them, "
        "so keep them while you demo (default: ~/.cache/codekavach-demo)",
    )
    parser.add_argument(
        "--again", action="store_true", help="scan again even if projects have scans"
    )
    args = parser.parse_args()
    api = Api(args.url)
    wait_for_health(api)
    api.login(args.username, args.password)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    seed(api, args.work_dir, args.again)
    stats = api.call("GET", "/stats")
    say(
        f"done: {stats['projects']} projects, {stats['scans']} scans, "
        f"{stats['findings_total']} findings, {stats['open_findings']} still open"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
