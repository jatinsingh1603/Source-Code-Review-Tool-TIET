"""Routes for the platform the server runs on: engines, project inventory, health, invariants.

Owning epic: E32.

``/engines`` lists the built-in analysers and the external engines of the plugin registry with
the install status the ``codekavach doctor`` engine checks report (a probe asks an engine for its
version only; nothing is scanned and no network is used). ``/projects/{id}/inventory`` reads the
file inventory the ingest stage stored for the project's latest scan; before the first scan it
counts a local folder or the bundled sample in place (files are read, nothing is analysed).
``/system/health`` runs the server's own checks plus the doctor's engine and report checks.
``/privacy/invariants`` reports the recorded results of the privacy invariant suite (I1 to
I6): the server never runs the tests, it reads the JUnit XML that ``pytest -m privacy
--junitxml=...`` wrote into the data directory, and adds the guard evidence of the latest scan
(ledger chain, zero-leak check, blocked payloads).
"""

import os
import shutil
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends
from sqlalchemy import select

from codekavach.core.log import get_logger
from codekavach.server.auth.dependencies import SessionDep, StateDep, require
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import Project, ScanRow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import Permission
from codekavach.server.results import ScanPaths
from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.platform")

router = APIRouter(tags=["platform"])
ReadDep = Depends(require(Permission.read))
AdminDep = Depends(require(Permission.users_admin))
BUILTIN_ANALYSERS: Final = (
    ("rules", "CodeKavach rules", "Pattern rules for Python and JavaScript"),
    ("taint", "CodeKavach taint", "Source-to-sink data flow for Python, JavaScript, TypeScript"),
    ("secrets", "CodeKavach secrets", "Credential detectors with checksums and entropy"),
    ("iac", "CodeKavach IaC", "Terraform, Dockerfile, Kubernetes and CI misconfiguration"),
    ("sca", "CodeKavach SCA", "Dependency manifests against the offline advisory set"),
)
INVARIANTS: Final = (
    ("I1", "Only the egress transport opens connections to LLM endpoints",
     ("test_i1_single_egress", "test_network_blocked", "test_cli_no_network",
      "test_core_offline", "test_ingest_remote_url")),
    ("I2", "The LLM layer accepts sanitised payloads only",
     ("test_i2_static_guard", "test_import_contracts", "test_import_purity")),
    ("I3", "Vault contents are never logged, exported or serialised outside the vault",
     ("test_vault_locality", "test_log_redaction_properties", "test_scoped_store")),
    ("I4", "Any failure in a privacy step aborts the request (fail closed)",
     ("test_fail_closed_pipeline", "test_timeout_fail_closed", "test_egress_guard",
      "test_guard_bites")),
    ("I5", "Same scan salt and input give the same pseudonyms",
     ("test_pseudonym_determinism", "test_pipeline_salt_locality")),
    ("I6", "No listed identifier, literal or secret appears in a ledger payload",
     ("test_i6_ledger", "test_redaction_invariants", "test_ledger_tamper",
      "test_level_differential")),
)  # fmt: skip
INVARIANT_REPORT_ENV: Final = "CODEKAVACH_SERVER_INVARIANTS_REPORT"
ENGINE_CACHE_SECONDS: Final = 60.0
# The engine and report probes of ``codekavach doctor`` do not read the CLI context.
NO_CONTEXT: Any = None
_engine_cache: dict[str, Any] = {}
_engine_lock = threading.Lock()


def server_settings(state: ServerState) -> Any:
    """The settings a server scan would load (no project)."""
    from codekavach.server.routers.system import _server_settings  # noqa: PLC0415

    return _server_settings(state)


# --- engines --------------------------------------------------------------------------------


def _external_engines(settings: Any) -> list[dict[str, Any]]:
    from codekavach.cli.doctor_checks import engine_checks  # noqa: PLC0415

    try:
        from codekavach.core.plugins.registry import registry_from_environment  # noqa: PLC0415

        adapters = dict(registry_from_environment(settings).engines())
    except Exception as error:  # noqa: BLE001 - no registry means no external engines
        _log.info("server_engine_registry_unavailable", error_type=type(error).__name__)
        adapters = {}
    rows = []
    for check in engine_checks(settings):
        try:
            result = check.run(NO_CONTEXT)
        except Exception as error:  # noqa: BLE001 - a broken probe is a row, not a crash
            rows.append({"id": check.name.removeprefix("engine:"), "installed": False,
                         "status": "error", "summary": type(error).__name__})  # fmt: skip
            continue
        engine_id = check.name.removeprefix("engine:")
        spec = getattr(adapters.get(engine_id), "spec", None)
        details = dict(result.details)
        status = str(result.status.value)
        rows.append(
            {
                "id": engine_id,
                "name": getattr(spec, "name", engine_id),
                "kind": "external",
                "installed": status == "pass",
                "status": {"pass": "installed", "warn": "missing", "skip": (
                    "disabled" if result.summary == "disabled" else "not_installed"),
                    "fail": "error"}.get(status, status),
                "summary": result.summary,
                "version": details.get("version"),
                "remediation": result.remediation,
                "languages": sorted(str(item.value) for item in getattr(spec, "languages", ())),
                "licence": getattr(spec, "spdx_licence", None),
                "homepage": getattr(spec, "homepage", None),
                "default_enabled": getattr(spec, "default_enabled", None),
            }
        )  # fmt: skip
    return rows


def engine_list(state: ServerState) -> list[dict[str, Any]]:
    """Built-in analysers and external engines with their install status (cached a minute)."""
    with _engine_lock:
        cached = _engine_cache.get("engines")
        if cached is not None and time.monotonic() - cached[0] < ENGINE_CACHE_SECONDS:
            return list(cached[1])
    rows: list[dict[str, Any]] = [
        {"id": engine_id, "name": name, "kind": "builtin", "installed": True,
         "status": "installed", "summary": summary, "version": None, "remediation": None,
         "languages": [], "licence": "MIT", "homepage": None, "default_enabled": True}
        for engine_id, name, summary in BUILTIN_ANALYSERS
    ]  # fmt: skip
    try:
        rows += _external_engines(server_settings(state))
    except Exception as error:  # noqa: BLE001 - the built-ins are still reported
        _log.info("server_engine_checks_failed", error_type=type(error).__name__)
    with _engine_lock:
        _engine_cache["engines"] = (time.monotonic(), rows)
    return rows


@router.get("/engines", dependencies=[ReadDep])
def engines(state: StateDep) -> list[dict[str, Any]]:
    """Every analyser a scan can run and whether it is installed on this server."""
    return engine_list(state)


# --- project inventory ----------------------------------------------------------------------


def _support(language: str) -> dict[str, Any]:
    from codekavach.analysis.rules.engine import SUPPORTED_LANGUAGES  # noqa: PLC0415
    from codekavach.analysis.taint.stage import LANGUAGES as TAINT  # noqa: PLC0415
    from codekavach.core.models.enums import Language  # noqa: PLC0415
    from codekavach.parsing.stage import SUPPORTED as PARSED  # noqa: PLC0415
    from codekavach.privacy.slicing.shape import SUPPORTED as SLICED  # noqa: PLC0415

    try:
        lang = Language(language)
    except ValueError:
        lang = None
    features = {
        "parse": lang in PARSED,
        "rules": lang in SUPPORTED_LANGUAGES,
        "taint": lang in TAINT,
        "slicing": lang in SLICED,
        "secrets": True,
    }
    level = "full" if features["taint"] else "partial" if features["parse"] else "basic"
    return {"support": level, "features": features}


def _source_root(state: ServerState, project: Project) -> tuple[Path, tuple[str, ...]] | None:
    """The folder a not yet scanned project reads in place, with the parts the scan leaves out."""
    from codekavach.server.jobs.workspace import COPY_IGNORE, SAMPLE_IGNORE  # noqa: PLC0415

    config = state.config
    if project.source_type == "sample" and config.sample_dir is not None:
        root, ignore = config.sample_dir, SAMPLE_IGNORE
    elif project.source_type == "path" and config.allow_local_paths and project.source_path:
        root, ignore = Path(project.source_path), COPY_IGNORE
    else:
        return None
    return (root, ignore) if root.is_dir() else None


def _count_in_place(root: Path, ignore: tuple[str, ...]) -> list[Any]:
    """Discover the files of ``root`` the way the ingest stage does, without copying them."""
    from codekavach.config.models.root import Settings  # noqa: PLC0415
    from codekavach.ingest.discovery import discover  # noqa: PLC0415

    skipped = set(ignore)
    return [
        item for item in discover(root, Settings())
        if not skipped.intersection(str(item.path).split("/"))
    ]  # fmt: skip


@router.get("/projects/{project_id}/inventory", dependencies=[ReadDep])
def inventory(project_id: str, state: StateDep, session: SessionDep) -> dict[str, Any]:
    """Files, lines and bytes per language from the project's latest completed scan.

    Before the first scan, a local folder or the bundled sample is counted in place
    (``scan_id`` is then null); an archive or a git source is counted on the first scan.
    """
    project = session.get(Project, project_id)
    if project is None:
        raise not_found("project")
    scan = session.scalars(
        select(ScanRow)
        .where(ScanRow.project_id == project_id, ScanRow.status == "completed")
        .order_by(ScanRow.finished_at.desc())
    ).first()
    files: list[Any]
    if scan is None or not scan.workspace or not scan.core_scan_id:
        source = _source_root(state, project)
        empty = {"project_id": project_id, "scan_id": None, "languages": [], "totals": None}
        if source is None:
            return empty
        try:
            files = _count_in_place(*source)
        except Exception as error:  # noqa: BLE001 - a folder that cannot be counted is no inventory
            _log.info("server_inventory_uncounted", error_type=type(error).__name__)
            return empty
        return _inventory_json(project_id, None, None, files)
    from codekavach.core.pipeline import keys  # noqa: PLC0415
    from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415
    from codekavach.ingest.models import SourceFile  # noqa: PLC0415

    try:
        store = OnDiskArtefactStore.open_existing(
            StateLayout(ScanPaths(Path(scan.workspace)).state_dir), scan.core_scan_id
        )
        files = list(store.get_list(keys.FILES, SourceFile)) if store.has(keys.FILES) else []
    except Exception as error:  # noqa: BLE001 - an unreadable store is reported, not raised
        raise ApiError(409, "inventory_unavailable", "the scan's file inventory cannot be read",
                       hint=type(error).__name__) from None  # fmt: skip
    return _inventory_json(project_id, scan.id, as_utc(scan.finished_at), files)


def _inventory_json(
    project_id: str, scan_id: str | None, scanned_at: Any, files: list[Any]
) -> dict[str, Any]:
    per: dict[str, Counter[str]] = {}
    for item in files:
        language = str(item.language.value)
        counter = per.setdefault(language, Counter())
        counter["files"] += 1
        counter["lines"] += int(item.line_count)
        counter["bytes"] += int(item.size_bytes)
        counter["generated"] += int(item.is_generated or item.is_minified or item.is_vendored)
    languages = [
        {"language": language, **dict(counts), **_support(language)}
        for language, counts in sorted(per.items(), key=lambda pair: -pair[1]["lines"])
    ]
    return {
        "project_id": project_id,
        "scan_id": scan_id,
        "scanned_at": scanned_at,
        "languages": languages,
        "totals": {
            "files": sum(row["files"] for row in languages),
            "lines": sum(row["lines"] for row in languages),
            "bytes": sum(row["bytes"] for row in languages),
        },
    }


# --- invariants -----------------------------------------------------------------------------


def invariant_report_path(state: ServerState) -> Path:
    """Where the recorded JUnit XML of the privacy suite is read from."""
    configured = os.environ.get(INVARIANT_REPORT_ENV)
    return Path(configured) if configured else state.config.data_dir / "invariants" / "junit.xml"


def _recorded(path: Path) -> tuple[dict[str, Counter[str]], float | None]:
    """Per test module: passed, failed and skipped counts; and the file's time."""
    if not path.is_file():
        return {}, None
    try:
        root = ET.parse(path).getroot()  # noqa: S314 - a local report the operator wrote
    except (ET.ParseError, OSError):
        return {}, None
    modules: dict[str, Counter[str]] = {}
    for case in root.iter("testcase"):
        name = str(case.get("classname") or "").split(".")
        module = next((part for part in reversed(name) if part.startswith("test_")), "")
        outcome = "passed"
        for child in case:
            if child.tag in {"failure", "error"}:
                outcome = "failed"
            elif child.tag == "skipped":
                outcome = "skipped"
        modules.setdefault(module, Counter())[outcome] += 1
    return modules, path.stat().st_mtime


def _guard_evidence(session: Any) -> dict[str, dict[str, Any]]:
    scan = session.scalars(
        select(ScanRow).where(ScanRow.status == "completed").order_by(ScanRow.finished_at.desc())
    ).first()
    if scan is None or not scan.privacy:
        return {}
    privacy = scan.privacy
    zero = privacy.get("zero_leak") or {}
    return {
        "I4": {"scan_id": scan.id, "blocked": privacy.get("blocked"),
               "passed": privacy.get("chain_ok") is True,
               "detail": "payloads the egress guard blocked were recorded and not sent"},
        "I6": {"scan_id": scan.id, "terms_checked": zero.get("checked"),
               "occurrences": zero.get("occurrences"),
               # No listed terms means the check did not run: that is not a failed invariant.
               "passed": (bool(zero.get("passed")) and privacy.get("chain_ok") is True)
               if zero.get("checked") else None,
               "detail": "verbatim search of the latest scan's ledger payloads"},
    }  # fmt: skip


def invariants(state: ServerState, session: Any) -> dict[str, Any]:
    """The I1 to I6 status from the recorded suite run and the latest scan's guard evidence."""
    path = invariant_report_path(state)
    modules, mtime = _recorded(path)
    evidence = _guard_evidence(session)
    rows = []
    for key, title, tests in INVARIANTS:
        counts: Counter[str] = Counter()
        for test in tests:
            counts.update(modules.get(test, Counter()))
        guard = evidence.get(key)
        if not counts:
            status = "not_recorded"
        elif counts["failed"]:
            status = "failed"
        else:
            status = "passed"
        if guard is not None and guard["passed"] is False:
            status = "failed"
        rows.append(
            {
                "id": key,
                "title": title,
                "status": status,
                "passed": status == "passed",
                "tests": {"passed": counts["passed"], "failed": counts["failed"],
                          "skipped": counts["skipped"], "modules": list(tests)},
                "guard": guard,
            }
        )  # fmt: skip
    return {
        "recorded": mtime is not None,
        "run_at": as_utc(_utc(mtime)) if mtime is not None else None,
        "source": "pytest -m privacy --junitxml (recorded run; the server does not run tests)",
        "how_to_record": f"uv run pytest -m privacy --junitxml={path}",
        "invariants": rows,
    }


def _utc(timestamp: float) -> Any:
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.fromtimestamp(timestamp, tz=UTC)


@router.get("/privacy/invariants", dependencies=[ReadDep])
def privacy_invariants(state: StateDep, session: SessionDep) -> dict[str, Any]:
    """The recorded status of the privacy invariants I1 to I6."""
    return invariants(state, session)


# --- system health --------------------------------------------------------------------------


def _check(name: str, status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "summary": summary, "details": details}


@router.get("/system/health", dependencies=[AdminDep])
def system_health(state: StateDep, session: SessionDep) -> dict[str, Any]:
    """Server checks (database, data directory, disk, workers, vault key, UI) and doctor checks."""
    config = state.config
    checks = []
    try:
        session.execute(select(1))
        checks.append(_check("server:database", "pass", "SQLite answers", path=str(config.db_path)))
    except Exception as error:  # noqa: BLE001 - reported, not raised
        checks.append(_check("server:database", "fail", type(error).__name__))
    writable = os.access(config.data_dir, os.W_OK)
    checks.append(_check("server:data_dir", "pass" if writable else "fail",
                         "writable" if writable else "not writable"))  # fmt: skip
    usage = shutil.disk_usage(config.data_dir)
    free_gb = usage.free / 1024**3
    checks.append(_check("server:disk", "pass" if free_gb > 1 else "warn",
                         f"{free_gb:.1f} GB free", free_bytes=usage.free))  # fmt: skip
    checks.append(_check("server:workers", "pass", f"{len(state.runner.active())} active scans",
                         workers=config.workers))  # fmt: skip
    passphrase = bool(os.environ.get(state.passphrase_env))
    checks.append(
        _check(
            "server:vault_key",
            "pass" if passphrase else "fail",
            "vault passphrase available" if passphrase else "no vault passphrase",
        )
    )
    ui = config.ui_dir is not None and (config.ui_dir / "index.html").is_file()
    checks.append(_check("server:ui", "pass" if ui else "warn",
                         "dashboard build served" if ui else "dashboard not built"))  # fmt: skip
    checks.append(_check("server:python", "pass", sys.version.split()[0]))
    try:
        from codekavach.cli.doctor_checks import report_checks  # noqa: PLC0415

        for item in report_checks(server_settings(state)):
            result = item.run(NO_CONTEXT)
            checks.append(_check(result.name, str(result.status.value), result.summary,
                                 remediation=result.remediation))  # fmt: skip
    except Exception as error:  # noqa: BLE001 - optional checks
        _log.info("server_report_checks_failed", error_type=type(error).__name__)
    for engine in engine_list(state):
        if engine["kind"] == "external":
            status = {"installed": "pass", "missing": "warn"}.get(engine["status"], "skip")
            checks.append(_check(f"engine:{engine['id']}", status, engine["summary"] or "",
                                 remediation=engine["remediation"]))  # fmt: skip
    totals = Counter(item["status"] for item in checks)
    return {
        "status": "fail" if totals["fail"] else "warn" if totals["warn"] else "pass",
        "totals": dict(totals),
        "checks": checks,
        "invariants": invariants(state, session),
        "uptime_seconds": int(time.time() - state.started_at),
    }
