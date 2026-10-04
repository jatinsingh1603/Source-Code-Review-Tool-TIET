import logging
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect, text

from codekavach.core.store.db import create_db_engine, init_db, sqlite_url
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.migrate import (
    DatabaseTooNewError,
    alembic_config,
    current_revision,
    head_revision,
    upgrade_to_head,
)
from codekavach.core.store.orm import Base

TABLES = {"projects", "scans", "stage_runs", "findings"}


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach")


@pytest.fixture
def migrated(tmp_path: Path) -> Iterator[Engine]:
    engine = create_db_engine(sqlite_url(tmp_path / "migrated.db"))
    upgrade_to_head(engine)
    yield engine
    engine.dispose()


def tables(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names()) - {"alembic_version"}


def test_init_db_creates_at_head_and_is_idempotent(layout: StateLayout) -> None:
    engine = init_db(layout)
    try:
        assert current_revision(engine) == head_revision() == "0001_initial"
        assert tables(engine) == TABLES
    finally:
        engine.dispose()
    again = init_db(layout)
    try:
        assert current_revision(again) == head_revision()
    finally:
        again.dispose()


def test_downgrade_and_upgrade_again(migrated: Engine) -> None:
    config = alembic_config(migrated.url.render_as_string(hide_password=False))
    with migrated.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, "base")
    assert tables(migrated) == set()
    assert current_revision(migrated) is None
    upgrade_to_head(migrated)
    assert tables(migrated) == TABLES


def test_models_and_migrations_do_not_drift(migrated: Engine) -> None:
    with migrated.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "render_as_batch": True}
        )
        assert compare_metadata(context, Base.metadata) == []


def _shape(engine: Engine) -> dict[str, Any]:
    inspector = inspect(engine)
    shape: dict[str, Any] = {}
    for table in sorted(tables(engine)):
        shape[table] = {
            "columns": [(c["name"], c["nullable"]) for c in inspector.get_columns(table)],
            "pk": inspector.get_pk_constraint(table)["constrained_columns"],
            "fks": sorted(
                (fk["name"], tuple(fk["constrained_columns"]), fk["referred_table"])
                for fk in inspector.get_foreign_keys(table)
            ),
            "unique": sorted(
                tuple(u["column_names"]) for u in inspector.get_unique_constraints(table)
            ),
            "indexes": sorted(index["name"] for index in inspector.get_indexes(table)),
        }
    return shape


def test_reflection_matches_create_all(tmp_path: Path, migrated: Engine) -> None:
    created = create_db_engine(sqlite_url(tmp_path / "created.db"))
    try:
        Base.metadata.create_all(created)
        assert _shape(created) == _shape(migrated)
    finally:
        created.dispose()


def test_too_new_database_is_left_untouched(layout: StateLayout) -> None:
    engine = init_db(layout)
    with engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num = '9999_future'"))
    engine.dispose()
    before = layout.db_path.read_bytes()
    with pytest.raises(DatabaseTooNewError, match="'9999_future' is newer"):
        init_db(layout)
    assert layout.db_path.read_bytes() == before


def test_concurrent_init(layout: StateLayout) -> None:
    errors: list[BaseException] = []
    engines: list[Engine] = []
    start = threading.Barrier(2)

    def work() -> None:
        start.wait()
        try:
            engines.append(init_db(layout))
        except BaseException as error:  # noqa: BLE001 - reported by the assertion
            errors.append(error)

    threads = [threading.Thread(target=work) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    try:
        assert errors == []
        assert all(current_revision(engine) == head_revision() for engine in engines)
    finally:
        for engine in engines:
            engine.dispose()


def test_import_does_not_configure_logging() -> None:
    code = (
        "import logging\n"
        "root = logging.getLogger()\n"
        "before = (list(root.handlers), root.level)\n"
        "import codekavach.core.store.migrate\n"
        "assert (list(root.handlers), root.level) == before\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_upgrade_leaves_root_logger_alone(tmp_path: Path) -> None:
    root = logging.getLogger()
    before = (list(root.handlers), root.level)
    engine = create_db_engine(sqlite_url(tmp_path / "log.db"))
    try:
        upgrade_to_head(engine)
    finally:
        engine.dispose()
    assert (list(root.handlers), root.level) == before


def test_migration_files_are_packaged_data() -> None:
    from importlib.resources import files  # noqa: PLC0415

    migrations = files("codekavach.core.store").joinpath("migrations")
    for name in ("env.py", "script.py.mako"):
        assert migrations.joinpath(name).is_file()
    assert migrations.joinpath("versions", "0001_initial.py").is_file()
    assert not migrations.joinpath("__init__.py").is_file()
