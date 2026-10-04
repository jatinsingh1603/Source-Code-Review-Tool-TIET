"""Alembic environment of the local database (E04-26).

Owning epic: E04.

This directory is data, not a package (ADR-0007 D14): it has no ``__init__.py`` and is located
with ``importlib.resources``, so nothing imports this file outside an Alembic run. The URL comes
from ``config.attributes["connection"]`` (programmatic runs) or ``sqlalchemy.url``. Logging is not
configured here (no ``fileConfig``): CodeKavach's own logging configuration stays in charge.
``render_as_batch`` is required because SQLite cannot alter constraints in place.
"""

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

from codekavach.core.store.orm import Base

config = context.config
target_metadata = Base.metadata


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit SQL for the configured URL without connecting."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run against the connection handed in by ``migrate``, or one made from the URL."""
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = engine_from_config(
        config.get_section(config.config_ini_section) or {},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with engine.connect() as fresh:
        _run(fresh)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
