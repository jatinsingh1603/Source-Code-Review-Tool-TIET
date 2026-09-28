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
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

DB_FILE_MODE = 0o600
SQLITE_PRAGMAS = (
    "PRAGMA foreign_keys=ON",
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
)
_MEMORY = ":memory:"


def sqlite_url(path: Path) -> str:
    """The SQLAlchemy URL of a SQLite database file (``:memory:`` for an in-memory one)."""
    if str(path) == _MEMORY:
        return f"sqlite+pysqlite:///{_MEMORY}"
    return f"sqlite+pysqlite:///{path.as_posix()}"


def _apply_pragmas(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        for pragma in SQLITE_PRAGMAS:
            cursor.execute(pragma)
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
