# Local database

CodeKavach keeps scan history and findings in one SQLite database per state directory: `<state_dir>/codekavach.db` (by default `.codekavach/codekavach.db` in the project). It is client-confidential data at rest and is created with mode `0o600`.

## Modules

| Module | Role |
|---|---|
| `codekavach.core.store.db` | Engine (`create_db_engine`), sessions (`make_session_factory`, `session_scope`) and `init_db(layout)` |
| `codekavach.core.store.orm` | Tables `projects`, `scans`, `stage_runs`, `findings`; `UtcDateTime`; the constraint naming convention |
| `codekavach.core.store.migrate` | Programmatic Alembic: `upgrade_to_head`, `current_revision`, `head_revision`, `DatabaseTooNewError` |
| `codekavach/core/store/migrations/` | Alembic `env.py`, `script.py.mako` and `versions/`: a data directory without `__init__.py` (ADR-0007 D14) |

`init_db(layout)` creates the database if needed and upgrades it to the newest revision. It runs offline and needs no `alembic.ini`. When the database was migrated by a newer CodeKavach, it raises `DatabaseTooNewError` and leaves the file unchanged.

## Adding a revision

1. Change the tables in `src/codekavach/core/store/orm.py`.
2. Generate a draft against a temporary database at head:

   ```bash
   uv run python -m codekavach.core.store.migrate revision -m "add finding owner"
   ```

   The draft appears in `src/codekavach/core/store/migrations/versions/`.
3. Review the draft by hand: check names against the naming convention and keep `render_as_batch`-compatible operations (SQLite cannot alter constraints in place). Rename the file to the `NNNN_short_name.py` pattern and set `revision` to the same id.
4. Run `uv run pytest tests/unit/core/store/test_migrations.py`. The drift check fails when `orm.py` and the migrations disagree.

Never edit a revision that has been released: add a new one instead. There is one migration tree for the local database and server mode (E32 extends it rather than starting a second).
