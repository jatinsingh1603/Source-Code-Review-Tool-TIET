import stat
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

from codekavach.core.store.db import (
    create_db_engine,
    make_session_factory,
    session_scope,
    sqlite_url,
)

POSIX = sys.platform != "win32"


def test_file_mode_and_pragmas(tmp_path: Path) -> None:
    path = tmp_path / "state" / "codekavach.db"
    engine = create_db_engine(sqlite_url(path))
    try:
        assert path.is_file()
        if POSIX:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            for suffix in ("-wal", "-shm"):
                side = path.with_name(path.name + suffix)
                if side.exists():
                    assert stat.S_IMODE(side.stat().st_mode) == 0o600
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
            assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
            assert connection.execute(text("PRAGMA busy_timeout")).scalar() == 5000
    finally:
        engine.dispose()


def test_in_memory_url() -> None:
    url = sqlite_url(Path(":memory:"))
    assert url == "sqlite+pysqlite:///:memory:"
    engine = create_db_engine(url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
    finally:
        engine.dispose()


def test_session_scope_commits_and_rolls_back(tmp_path: Path) -> None:
    engine = create_db_engine(sqlite_url(tmp_path / "db.sqlite"))
    factory = make_session_factory(engine)
    try:
        with session_scope(factory) as session:
            session.execute(text("CREATE TABLE t (v INTEGER)"))
            session.execute(text("INSERT INTO t VALUES (1)"))
        with pytest.raises(RuntimeError), session_scope(factory) as session:
            session.execute(text("INSERT INTO t VALUES (2)"))
            raise RuntimeError("abort")
        with session_scope(factory) as other:
            assert other.execute(text("SELECT v FROM t")).scalars().all() == [1]
    finally:
        engine.dispose()
