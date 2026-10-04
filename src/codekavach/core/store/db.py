"""The local SQLite database: engine, session factory and session scope (E04-25).

Owning epic: E04.

The database holds final findings (real file paths, lines and evidence text from the client's
code), so it is client-confidential data at rest: it lives inside the state directory, the file is
created with mode ``0o600`` (the ``-wal`` and ``-shm`` files too, on POSIX), and SQL parameters
never appear in exception messages or logs (``hide_parameters=True``). It holds no vault contents,
scan salt or credentials (I3).

Every SQLite connection gets ``foreign_keys=ON``, ``journal_mode=WAL``, ``synchronous=NORMAL`` and
``busy_timeout=5000``. One engine per process; sessions are used from the runner's thread only,
never from stage threads. SQLAlchemy is imported only here and in ``orm``, ``migrate`` and
``repositories``, which the runner imports lazily, so ``codekavach --version`` stays fast.
"""

import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

if TYPE_CHECKING:
    from codekavach.core.store.layout import StateLayout

DB_FILE_MODE = 0o600
SQLITE_PRAGMAS = (
    "PRAGMA busy_timeout=5000",
    "PRAGMA foreign_keys=ON",
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
)
PRAGMA_ATTEMPTS = 100
PRAGMA_RETRY_SECONDS = 0.05
_MEMORY = ":memory:"


def sqlite_url(path: Path) -> str:
    """The SQLAlchemy URL of a SQLite database file (``:memory:`` for an in-memory one)."""
    if str(path) == _MEMORY:
        return f"sqlite+pysqlite:///{_MEMORY}"
    return f"sqlite+pysqlite:///{path.as_posix()}"


def _execute_pragma(cursor: Any, pragma: str) -> None:
    # Switching a fresh file to WAL needs an exclusive lock and SQLite reports "database is
    # locked" at once instead of waiting for ``busy_timeout``, so two first connections racing on
    # a new database are retried here.
    for attempt in range(PRAGMA_ATTEMPTS):
        try:
            cursor.execute(pragma)
        except sqlite3.OperationalError as error:
            if "locked" not in str(error) or attempt == PRAGMA_ATTEMPTS - 1:
                raise
            time.sleep(PRAGMA_RETRY_SECONDS)
        else:
            return


def _apply_pragmas(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        for pragma in SQLITE_PRAGMAS:
            _execute_pragma(cursor, pragma)
    finally:
        cursor.close()


def _restrict_mode(path: Path) -> None:
    if os.name == "nt":  # POSIX modes do not describe Windows ACLs
        return
    for candidate in (path, path.with_name(f"{path.name}-wal"), path.with_name(f"{path.name}-shm")):
        if candidate.exists():
            candidate.chmod(DB_FILE_MODE)


def create_db_engine(url: str) -> Engine:
    """A configured engine; for a SQLite file, the file is created first with mode 0o600."""
    parsed = make_url(url)
    is_sqlite = parsed.get_backend_name() == "sqlite"
    path = (
        Path(parsed.database) if is_sqlite and parsed.database not in (None, "", _MEMORY) else None
    )
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, DB_FILE_MODE)
        os.close(descriptor)
    engine = create_engine(url, hide_parameters=True)
    if is_sqlite:
        event.listen(engine, "connect", _apply_pragmas)
    if path is not None:
        with engine.connect():
            pass  # the first connection creates the -wal and -shm files
        _restrict_mode(path)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Sessions bound to ``engine``; objects stay usable after commit."""
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """A session that commits on success, rolls back on an exception and is always closed."""
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


INIT_ATTEMPTS = 5
INIT_RETRY_SECONDS = 0.2


def init_db(layout: "StateLayout") -> Engine:
    """Create or upgrade the local database below ``layout`` to the newest revision.

    A second call is a no-op. Two processes initialising a fresh database at the same time are
    serialised by SQLite's write lock; the one that loses the race finds the revision applied.

    Raises:
        DatabaseTooNewError: the database was migrated by a newer CodeKavach (nothing changed).
    """
    from codekavach.core.store.migrate import (  # noqa: PLC0415 - Alembic is imported lazily
        check_not_too_new,
        head_revision,
        upgrade_to_head,
    )
    from codekavach.core.store.migrate import current_revision as revision_of  # noqa: PLC0415

    layout.ensure()
    engine = create_db_engine(sqlite_url(layout.db_path))
    try:
        check_not_too_new(engine)
        head = head_revision()
        for attempt in range(INIT_ATTEMPTS):
            if revision_of(engine) == head:
                return engine
            try:
                upgrade_to_head(engine)
            except (OperationalError, IntegrityError):
                if attempt == INIT_ATTEMPTS - 1:
                    raise
                time.sleep(INIT_RETRY_SECONDS)  # another process is creating the schema
            else:
                return engine
    except BaseException:
        engine.dispose()
        raise
    return engine
