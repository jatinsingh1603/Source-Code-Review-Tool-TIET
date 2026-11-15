"""The server's SQLAlchemy engine and session factory (SQLite, WAL mode).

Owning epic: E32.

One engine per server process. SQLite is opened with ``check_same_thread=False`` because request
handlers and scan workers run in different threads; every unit of work opens its own session.
Datetimes are stored naive by SQLite, so ``as_utc`` restores the time zone on the way out.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateColumn

from codekavach.server.db.models import ServerBase


def _pragmas(connection: Any, _record: Any) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.close()


def add_missing_columns(engine: Engine) -> list[str]:
    """Add the columns a newer release declares to the tables an older one created.

    ``create_all`` creates missing tables but never alters an existing one. Only additive
    changes are made here (``ALTER TABLE ... ADD COLUMN``): a new column must be nullable or
    carry a server default, so the rows already stored stay valid. Returns ``table.column``
    for each column added.
    """
    added: list[str] = []
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table in ServerBase.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            present = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                ddl = CreateColumn(column).compile(dialect=engine.dialect)
                connection.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN {ddl}'))
                added.append(f"{table.name}.{column.name}")
    return added


class Database:
    """The engine plus a session factory."""

    def __init__(self, path: Path) -> None:
        self.engine: Engine = create_engine(
            f"sqlite+pysqlite:///{path}",
            connect_args={"check_same_thread": False, "timeout": 30},
            hide_parameters=True,
        )
        event.listen(self.engine, "connect", _pragmas)
        ServerBase.metadata.create_all(self.engine)
        self.upgraded: list[str] = add_missing_columns(self.engine)
        self._factory = sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> Session:
        """A new session (the caller closes it)."""
        return self._factory()

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        """A session that commits on success and rolls back on error."""
        session = self._factory()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        """Close every pooled connection."""
        self.engine.dispose()


def as_utc(value: datetime | None) -> datetime | None:
    """``value`` with UTC attached when SQLite returned it naive."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
