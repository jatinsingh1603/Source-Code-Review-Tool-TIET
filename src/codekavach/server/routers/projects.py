"""Routes ``/projects``: create, list, read, update, delete, upload an archive, start a scan.

Owning epic: E32.

A project names a source: the bundled ``sample``, a local ``path`` on the server, an allow-listed
https ``git`` URL, or an ``upload``ed zip or tar archive. A git URL is checked when the project is
saved and again when it is cloned; an upload is checked as an archive (size, entry count,
compression ratio, traversal, links) before it is accepted, by a trial extraction into a scratch
directory that is removed afterwards.
"""

import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from codekavach.server import audit
from codekavach.server.auth.dependencies import SessionDep, StateDep, client_of, require
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import Project, ScanRow, utcnow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.jobs.workspace import (
    ARCHIVE_SUFFIXES,
    ArchiveLimits,
    IntakeError,
    assert_safe_clone_url,
    extract_archive,
)
from codekavach.server.rbac import Permission, permitted
from codekavach.server.routers.scans import scan_json, start_scan
from codekavach.server.schemas import ProjectCreate, ProjectUpdate, ScanCreate, SourceBody
from codekavach.server.state import ServerState, new_id

router = APIRouter(tags=["projects"])
ReadDep = Depends(require(Permission.read))
WriteDep = Depends(require(Permission.project_write))
RunDep = Depends(require(Permission.scan_run))


def project_json(session: Session, project: Project) -> dict[str, Any]:
    """The JSON of a project with its scan count and last scan."""
    scans = session.scalar(
        select(func.count()).select_from(ScanRow).where(ScanRow.project_id == project.id)
    )
    last = session.scalars(
        select(ScanRow)
        .where(ScanRow.project_id == project.id)
        .order_by(ScanRow.created_at.desc())
        .limit(1)
    ).first()
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "source": {
            "type": project.source_type,
            "path": project.source_path,
            "url": project.source_url,
            "ref": project.source_ref,
            "upload_name": project.upload_name,
        },
        "created_at": as_utc(project.created_at),
        "updated_at": as_utc(project.updated_at),
        "scans": scans or 0,
        "scan_count": scans or 0,
        "languages": (last.languages or []) if last is not None else [],
        "files": last.files if last is not None else 0,
        "last_scan": scan_json(last, project) if last is not None else None,
    }


def _check_path(state: ServerState, principal: Any, raw: str | None) -> None:
    """A local path names a directory on the server host: admin only, never the data dir."""
    if not state.config.allow_local_paths:
        raise ApiError(400, "path_source_disabled", "local path sources are disabled")
    if not permitted(principal.role, Permission.settings_write):
        raise ApiError(
            403, "forbidden", "only an admin may point a project at a directory on the server"
        )
    if not raw or not Path(raw).expanduser().is_dir():
        raise ApiError(400, "source_not_found", "the path is not a directory on the server")
    path = Path(raw).expanduser().resolve()
    data = state.config.data_dir.resolve()
    if path == data or path.is_relative_to(data) or data.is_relative_to(path):
        raise ApiError(400, "path_source_forbidden", "the path overlaps the server data directory")


def _check_source(state: ServerState, source: SourceBody, principal: Any) -> None:
    if source.type == "path":
        _check_path(state, principal, source.path)
    elif source.type == "git":
        try:
            assert_safe_clone_url(source.url or "", state.config.git_allowed_hosts)
        except IntakeError as error:
            raise ApiError(400, error.code, error.message) from None
    elif source.type == "sample" and state.config.sample_dir is None:
        raise ApiError(400, "sample_missing", "the KavachBank sample is not installed")


def _apply_source(project: Project, source: SourceBody) -> None:
    project.source_type = source.type
    project.source_path = (
        str(Path(source.path).expanduser().resolve()) if source.type == "path" and source.path
        else None
    )  # fmt: skip
    project.source_url = source.url if source.type == "git" else None
    project.source_ref = source.ref if source.type == "git" else None


@router.get("/projects", dependencies=[ReadDep])
def list_projects(session: SessionDep) -> list[dict[str, Any]]:
    """Every project, newest first."""
    projects = session.scalars(select(Project).order_by(Project.created_at.desc()))
    return [project_json(session, project) for project in projects]


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectCreate,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = WriteDep,
) -> dict[str, Any]:
    """Create a project."""
    _check_source(state, body.source, principal)
    project = Project(
        id=new_id("prj"),
        name=body.name,
        description=body.description or "",
        source_type=body.source.type,
        created_by=principal.user_id,
    )
    _apply_source(project, body.source)
    session.add(project)
    session.flush()
    audit.record(state.db, actor=principal.username, action="project.create",
                 resource=project.id, client=client_of(request),
                 detail={"source": body.source.type})  # fmt: skip
    return project_json(session, project)


@router.get("/projects/{project_id}", dependencies=[ReadDep])
def get_project(project_id: str, session: SessionDep) -> dict[str, Any]:
    """One project."""
    project = session.get(Project, project_id)
    if project is None:
        raise not_found("project")
    return project_json(session, project)


@router.patch("/projects/{project_id}")
def update_project(
    project_id: str,
    body: ProjectUpdate,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = WriteDep,
) -> dict[str, Any]:
    """Rename, describe or re-point a project."""
    project = session.get(Project, project_id)
    if project is None:
        raise not_found("project")
    if body.name is not None:
        project.name = body.name
    if body.description is not None:
        project.description = body.description
    if body.source is not None:
        _check_source(state, body.source, principal)
        _apply_source(project, body.source)
    project.updated_at = utcnow()
    audit.record(state.db, actor=principal.username, action="project.update",
                 resource=project.id, client=client_of(request))  # fmt: skip
    return project_json(session, project)


@router.delete("/projects/{project_id}")
def delete_project(
    project_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = WriteDep,
) -> dict[str, Any]:
    """Delete a project, its scans and their workspaces."""
    project = session.get(Project, project_id)
    if project is None:
        raise not_found("project")
    scans = session.scalars(select(ScanRow).where(ScanRow.project_id == project_id)).all()
    for scan in scans:
        state.runner.cancel(scan.id)
        if scan.workspace:
            shutil.rmtree(scan.workspace, ignore_errors=True)
        state.hub.forget(scan.id)
        session.delete(scan)
    shutil.rmtree(state.config.uploads_dir / project_id, ignore_errors=True)
    session.delete(project)
    audit.record(state.db, actor=principal.username, action="project.delete",
                 resource=project_id, client=client_of(request))  # fmt: skip
    return {"ok": True, "deleted_scans": len(scans)}


@router.post("/projects/{project_id}/upload")
def upload_archive(
    project_id: str,
    file: UploadFile,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = WriteDep,
) -> dict[str, Any]:
    """Attach a zip or tar archive as the project's source (checked before it is kept)."""
    project = session.get(Project, project_id)
    if project is None:
        raise not_found("project")
    name = Path(file.filename or "upload.zip").name
    if not name.lower().endswith(ARCHIVE_SUFFIXES):
        raise ApiError(400, "archive_unsupported", "upload a .zip, .tar, .tar.gz or .tgz file")
    target_dir = state.config.uploads_dir / project_id
    target_dir.mkdir(parents=True, exist_ok=True)
    staging = target_dir / f".incoming-{new_id('up')}"
    size = 0
    with staging.open("wb") as out:
        while chunk := file.file.read(1024 * 1024):
            size += len(chunk)
            if size > state.config.max_upload_bytes:
                out.close()
                staging.unlink(missing_ok=True)
                raise ApiError(413, "upload_too_large", "the archive exceeds the upload limit")
            out.write(chunk)
    limits = ArchiveLimits(
        max_entries=state.config.max_archive_entries,
        max_bytes=state.config.max_extracted_bytes,
        max_ratio=state.config.max_compression_ratio,
    )
    with tempfile.TemporaryDirectory(dir=state.config.data_dir) as scratch:
        try:
            root = extract_archive(staging, Path(scratch) / "check", limits)
            files = sum(1 for item in root.rglob("*") if item.is_file())
        except IntakeError as error:
            staging.unlink(missing_ok=True)
            audit.record(state.db, actor=principal.username, action="project.upload",
                         resource=project_id, outcome="rejected", client=client_of(request),
                         detail={"code": error.code})  # fmt: skip
            raise ApiError(400, error.code, error.message) from None
    for old in target_dir.iterdir():
        if old != staging and old.is_file():
            old.unlink()
    final = target_dir / name
    staging.rename(final)
    project.source_type = "upload"
    project.upload_name = name
    project.source_path = project.source_url = project.source_ref = None
    project.updated_at = utcnow()
    audit.record(state.db, actor=principal.username, action="project.upload", resource=project_id,
                 client=client_of(request), detail={"bytes": size, "files": files})  # fmt: skip
    return {"ok": True, "file": name, "bytes": size, "files": files,
            "project": project_json(session, project)}  # fmt: skip


@router.post("/projects/{project_id}/scans", status_code=201)
def create_scan(
    project_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    body: ScanCreate | None = None,
    principal: Any = RunDep,
) -> dict[str, Any]:
    """Start a scan of the project."""
    project = session.get(Project, project_id)
    if project is None:
        raise not_found("project")
    return start_scan(state, session, project, body or ScanCreate(), principal,
                      client_of(request))  # fmt: skip
