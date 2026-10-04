"""Programmatic Alembic migrations of the local database (E04-26).

Owning epic: E04.

Migrations run from the installed package: the script location is found with
``importlib.resources`` and no ``alembic.ini`` is needed; everything runs offline. A database whose
revision this version does not know (created by a newer CodeKavach) is left untouched and reported
as ``DatabaseTooNewError``. Logging is not configured here.

Adding a revision (developers): ``python -m codekavach.core.store.migrate revision -m "..."``
autogenerates a draft against a temporary database at head; review it by hand, and never edit a
released revision.
"""

import argparse
import sys
import tempfile
import threading
from importlib.resources import as_file, files
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import Engine

from codekavach.core.pipeline.errors import PipelineError

# Alembic's ``context`` is a module-level proxy, so migrations of one process run one at a time;
# separate processes are serialised by SQLite's write lock (``init_db`` retries).
_MIGRATION_LOCK = threading.Lock()


class DatabaseTooNewError(PipelineError):
    """The database was migrated by a newer CodeKavach than this one."""

    def __init__(self, found: str, head: str) -> None:
        self.found = found
        self.head = head
        super().__init__(
            f"database schema revision {found!r} is newer than this CodeKavach supports "
            f"(head {head!r}); upgrade CodeKavach or use a different state directory"
        )


def _script_location() -> str:
    return str(files("codekavach.core.store").joinpath("migrations"))


def alembic_config(url: str) -> Config:
    """An Alembic configuration for ``url`` with the packaged script location."""
    config = Config()
    config.set_main_option("script_location", _script_location())
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(alembic_config("sqlite://"))


def head_revision() -> str:
    """The newest revision this version knows."""
    head = _script().get_current_head()
    if head is None:
        raise RuntimeError("the migration tree has no head revision")
    return head


def current_revision(engine: Engine) -> str | None:
    """The revision the database is at, or ``None`` for an unversioned database."""
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def check_not_too_new(engine: Engine) -> None:
    """Raise when the database revision is unknown to this version; changes nothing.

    Raises:
        DatabaseTooNewError: the revision is not in this version's migration tree.
    """
    found = current_revision(engine)
    if found is None:
        return
    try:
        known = _script().get_revision(found)
    except CommandError:
        known = None
    if known is None:
        raise DatabaseTooNewError(found, head_revision())


def upgrade_to_head(engine: Engine) -> str:
    """Upgrade the database to the newest revision and return it."""
    config = alembic_config(engine.url.render_as_string(hide_password=False))
    with _MIGRATION_LOCK, engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    revision = current_revision(engine)
    if revision is None:
        raise RuntimeError("the upgrade left the database unversioned")
    return revision


def _revision(message: str) -> None:
    """Autogenerate a draft revision against a temporary database at head."""
    from codekavach.core.store.db import create_db_engine, sqlite_url  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as directory:
        engine = create_db_engine(sqlite_url(Path(directory) / "draft.db"))
        try:
            upgrade_to_head(engine)
            with as_file(files("codekavach.core.store").joinpath("migrations")) as location:
                config = alembic_config(engine.url.render_as_string(hide_password=False))
                config.set_main_option("script_location", str(location))
                with _MIGRATION_LOCK, engine.begin() as connection:
                    config.attributes["connection"] = connection
                    command.revision(config, message=message, autogenerate=True)
        finally:
            engine.dispose()


def main(argv: list[str] | None = None) -> int:
    """``python -m codekavach.core.store.migrate revision -m "..."``."""
    parser = argparse.ArgumentParser(prog="python -m codekavach.core.store.migrate")
    commands = parser.add_subparsers(dest="command", required=True)
    revision = commands.add_parser("revision", help="autogenerate a draft revision")
    revision.add_argument("-m", "--message", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "revision":
        _revision(arguments.message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
