"""The server audit log: who did what to which resource, allowed or denied.

Owning epic: E32.

Each event is chained to the previous one by SHA-256 (``entry_hash`` covers the previous hash and
the event's fields), so ``verify_audit_chain`` notices an edited or deleted row. Events are written
by one writer thread per database, in transactions of their own, so the chain stays linear and an
audit write never waits on the request transaction that caused it. Details carry identifiers only,
never payload text, source code or credentials.
"""

import hashlib
import json
import queue
import threading
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.core.log import get_logger
from codekavach.server.db.engine import Database, as_utc
from codekavach.server.db.models import AuditEvent, utcnow

GENESIS = "0" * 64
_log = get_logger("codekavach.server.audit")
_writers: dict[int, "_Writer"] = {}
_writers_lock = threading.Lock()


def _digest(prev_hash: str, event: AuditEvent) -> str:
    at = as_utc(event.at)
    body = json.dumps(
        {
            "prev": prev_hash,
            "at": at.isoformat() if at else "",
            "actor": event.actor,
            "action": event.action,
            "resource": event.resource,
            "outcome": event.outcome,
            "detail": event.detail,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class _Writer:
    """Appends queued events to one database, in order."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="codekavach-audit", daemon=True)
        self._thread.start()

    def put(self, item: dict[str, Any]) -> None:
        self._queue.put(item)

    def join(self) -> None:
        self._queue.join()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                self._write(item)
            except Exception as error:  # noqa: BLE001 - the writer must survive a bad event
                _log.error("audit_write_failed", error_type=type(error).__name__)
            finally:
                self._queue.task_done()

    def _write(self, item: dict[str, Any]) -> None:
        with self._db.transaction() as session:
            last = session.scalars(
                select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
            ).first()
            prev = last.entry_hash if last is not None else GENESIS
            event = AuditEvent(prev_hash=prev, **item)
            event.entry_hash = _digest(prev, event)
            session.add(event)


def _writer(db: Database) -> _Writer:
    with _writers_lock:
        found = _writers.get(id(db))
        if found is None:
            found = _Writer(db)
            _writers[id(db)] = found
        return found


def record(
    db: Database,
    *,
    actor: str,
    action: str,
    resource: str = "",
    outcome: str = "allowed",
    client: str = "",
    detail: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> None:
    """Queue one event for the database's audit writer."""
    _writer(db).put(
        {
            "at": (at or utcnow()).replace(microsecond=0),
            "actor": actor,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "client": client,
            "detail": detail or {},
        }
    )


def flush(db: Database) -> None:
    """Wait until every queued event of ``db`` is written."""
    _writer(db).join()


def verify_audit_chain(session: Session) -> tuple[bool, int]:
    """``(intact, events checked)``; a broken link or a changed row makes it ``False``."""
    prev = GENESIS
    count = 0
    for event in session.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        if event.prev_hash != prev or _digest(prev, event) != event.entry_hash:
            return False, count
        prev = event.entry_hash
        count += 1
    return True, count
