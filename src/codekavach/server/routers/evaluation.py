"""Routes ``/evaluation``: the latest detection and leakage results, and a run on the sample.

Owning epic: E32.

``GET /evaluation`` reads the newest ``results.json`` of each kind (detection, leakage) below
``<data_dir>/evaluation``, where ``POST /evaluation/run`` writes and where an operator may point
``codekavach eval detection|leakage --out``. A run evaluates the bundled KavachBank sample with
the mock provider only: it starts ``codekavach eval detection`` and then ``codekavach eval
leakage`` as child processes (each with its own home directory and vault passphrase, so the
server's environment is untouched) on a background thread, one run at a time. Nothing is sent to a
model; the leakage harness attacks the payloads locally.
"""

import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends, Request

from codekavach.core.log import get_logger
from codekavach.server import audit
from codekavach.server.auth.dependencies import Principal, StateDep, client_of, require
from codekavach.server.errors import ApiError
from codekavach.server.rbac import Permission
from codekavach.server.results import SERVER_ONLY_VARIABLES
from codekavach.server.schemas import EvaluationRunBody
from codekavach.server.state import ServerState, new_id

_log = get_logger("codekavach.server.evaluation")

router = APIRouter(tags=["evaluation"])
ReadDep = Depends(require(Permission.read))
RunDep = Depends(require(Permission.settings_write))
KINDS: Final = ("detection", "leakage")
JOB_FILE: Final = "job.json"
RUN_TIMEOUT_SECONDS: Final = 3600
_lock = threading.Lock()
_running: dict[str, threading.Thread] = {}


def evaluation_dir(state: ServerState) -> Path:
    """Where evaluation runs are written."""
    return state.config.data_dir / "evaluation"


def _latest(root: Path, kind: str) -> tuple[Path, dict[str, Any]] | None:
    best: tuple[float, Path, dict[str, Any]] | None = None
    if not root.is_dir():
        return None
    for path in root.rglob("results.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            mtime = path.stat().st_mtime
        except (OSError, ValueError):
            continue
        if (
            isinstance(data, dict)
            and data.get("kind") == kind
            and (best is None or mtime > best[0])
        ):
            best = (mtime, path, data)
    return (best[1], best[2]) if best is not None else None


def _benchmarks(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    dataset = (data.get("dataset") or {}).get("name")
    for arm in data.get("arms") or []:
        overall = arm.get("overall") or {}
        rows.append(
            {
                "dataset": dataset,
                "arm": arm.get("arm"),
                "level": arm.get("level"),
                "provider": arm.get("provider"),
                "findings": arm.get("findings"),
                "precision": overall.get("precision"),
                "recall": overall.get("recall"),
                "f1": overall.get("f1"),
                "f1_ci": overall.get("f1_ci"),
                "tp": overall.get("tp"),
                "fp": overall.get("fp"),
                "fn": overall.get("fn"),
                "skipped_reason": arm.get("skipped_reason"),
            }
        )
    return rows


def _attacks(data: dict[str, Any]) -> list[dict[str, Any]]:
    levels = data.get("levels") or {}
    experiments: tuple[tuple[str, str, str | None, str], ...] = (
        ("canary", "Canary exposure (passed)", "canary", "passed"),
        ("identifier", "Identifier recovery (sub-word rate)", "identifier", "subword_rate"),
        ("inference", "Sector inference (evidence share)", "inference", "evidence_share"),
        ("stitching", "Slice stitching (coverage)", "stitching", "coverage"),
        ("leakage_score", "Leakage score (0 to 100)", None, "leakage_score"),
    )

    def read(entry: dict[str, Any], section: str | None, name: str) -> Any:
        holder = entry.get(section) if section else entry
        return holder.get(name) if isinstance(holder, dict) else None

    return [
        {
            "experiment": key,
            "description": label,
            "by_level": {level: read(entry, section, name) for level, entry in levels.items()},
        }
        for key, label, section, name in experiments
    ]


def _job(state: ServerState) -> dict[str, Any] | None:
    root = evaluation_dir(state)
    jobs = (
        sorted(root.glob(f"*/{JOB_FILE}"), key=lambda p: p.stat().st_mtime) if root.is_dir() else []
    )
    if not jobs:
        return None
    try:
        data: dict[str, Any] = json.loads(jobs[-1].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data


@router.get("/evaluation", dependencies=[ReadDep])
def get_evaluation(state: StateDep) -> dict[str, Any]:
    """The newest detection and leakage results, shaped for the evaluation page."""
    root = evaluation_dir(state)
    detection = _latest(root, "detection")
    leakage = _latest(root, "leakage")
    result: dict[str, Any] = {
        "sample": False,
        "available": detection is not None or leakage is not None,
        "benchmarks": _benchmarks(detection[1]) if detection else [],
        "frontier": (leakage[1].get("frontier") or []) if leakage else [],
        "attacks": _attacks(leakage[1]) if leakage else [],
        "zero_leak": leakage[1].get("zero_leak") if leakage else None,
        "ablations": (leakage[1].get("ablations") or []) if leakage else [],
        "detection": None,
        "leakage": None,
        "job": _job(state),
    }
    for kind, found in (("detection", detection), ("leakage", leakage)):
        if found is not None:
            path, data = found
            result[kind] = {
                "dataset": data.get("dataset"),
                "method": data.get("method") or data.get("adversary"),
                "generated_at": datetime.fromtimestamp(path.stat().st_mtime, tz=UTC),
                "path": str(path.relative_to(root)) if root in path.parents else path.name,
                "results": data,
            }
    return result


def _write_job(path: Path, job: dict[str, Any]) -> None:
    path.write_text(json.dumps(job, default=str, indent=2), encoding="utf-8")


def _command(
    kind: str, dataset: Path, levels: list[str], out: Path, limit: int | None
) -> list[str]:
    command = [sys.executable, "-m", "codekavach", "eval", kind, "--dataset", str(dataset)]
    for level in levels:
        command += ["--level", level]
    if kind == "detection":
        command += ["--provider", "mock"]
        if limit is not None:
            command += ["--limit", str(limit)]
    return [*command, "--out", str(out)]


def _child_env(home: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(SERVER_ONLY_VARIABLES) and not key.startswith("CODEKAVACH_LLM")
    }
    env["CODEKAVACH_HOME"] = str(home)
    return env


def run_job(state: ServerState, run_dir: Path, job: dict[str, Any], dataset: Path) -> None:
    """Run detection then leakage in child processes; record each step in ``job.json``."""
    job_file = run_dir / JOB_FILE
    home = run_dir / "home"
    home.mkdir(parents=True, exist_ok=True)
    for step in job["steps"]:
        step["status"] = "running"
        step["started_at"] = datetime.now(UTC)
        _write_job(job_file, job)
        out = run_dir / step["kind"]
        try:
            completed = subprocess.run(
                _command(step["kind"], dataset, job["levels"], out, job.get("limit")),
                env=_child_env(home),
                cwd=run_dir,
                capture_output=True,
                text=True,
                timeout=RUN_TIMEOUT_SECONDS,
                check=False,
            )
            ok = completed.returncode == 0 and (out / "results.json").is_file()
            step["status"] = "completed" if ok else "failed"
            step["exit_code"] = completed.returncode
            if not ok:
                step["error"] = (completed.stderr or completed.stdout or "")[-500:]
        except (OSError, subprocess.SubprocessError) as error:
            step["status"], step["error"] = "failed", type(error).__name__
        step["finished_at"] = datetime.now(UTC)
        _write_job(job_file, job)
    job["status"] = (
        "completed" if all(step["status"] == "completed" for step in job["steps"]) else "failed"
    )
    job["finished_at"] = datetime.now(UTC)
    _write_job(job_file, job)
    _log.info("server_evaluation_finished", run_id=job["id"], status=job["status"])


def _start(target: Any, *args: Any) -> threading.Thread:
    thread = threading.Thread(target=target, args=args, name="ck-evaluation", daemon=True)
    thread.start()
    return thread


@router.post("/evaluation/run", status_code=202)
def run_evaluation(
    request: Request,
    state: StateDep,
    body: EvaluationRunBody | None = None,
    principal: Principal = RunDep,
) -> dict[str, Any]:
    """Start the detection and leakage evaluation of the sample with the mock provider."""
    dataset = state.config.sample_dir
    if dataset is None or not (dataset / "ground-truth").is_dir():
        raise ApiError(409, "sample_missing", "the KavachBank sample and its ground truth are "
                       "not installed on this server")  # fmt: skip
    chosen = body or EvaluationRunBody()
    levels = list(chosen.levels or ["L2", "L3", "L4"])
    with _lock:
        active = [thread for thread in _running.values() if thread.is_alive()]
        if active:
            raise ApiError(409, "evaluation_running", "an evaluation run is already in progress")
        run_id = new_id("eval")
        run_dir = evaluation_dir(state) / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        job: dict[str, Any] = {
            "id": run_id,
            "status": "running",
            "provider": "mock",
            "dataset": "kavachbank",
            "levels": levels,
            "limit": chosen.limit,
            "requested_by": principal.username,
            "started_at": datetime.now(UTC),
            "finished_at": None,
            "steps": [{"kind": kind, "status": "queued"} for kind in KINDS],
        }
        _write_job(run_dir / JOB_FILE, job)
        _running.clear()
        _running[run_id] = _start(run_job, state, run_dir, job, dataset)
    audit.record(state.db, actor=principal.username, action="evaluation.run", resource=run_id,
                 client=client_of(request), detail={"levels": levels})  # fmt: skip
    return job


@router.get("/evaluation/runs/{run_id}", dependencies=[ReadDep])
def evaluation_run(run_id: str, state: StateDep) -> dict[str, Any]:
    """The status of one evaluation run."""
    path = evaluation_dir(state) / run_id / JOB_FILE
    if not run_id.startswith("eval_") or "/" in run_id or not path.is_file():
        raise ApiError(404, "not_found", "no such evaluation run")
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data
