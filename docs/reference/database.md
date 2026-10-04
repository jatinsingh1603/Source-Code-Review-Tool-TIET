# Local database

CodeKavach keeps scan history and findings in one SQLite database per state directory: `<state_dir>/codekavach.db` (by default `.codekavach/codekavach.db` in the project). It is client-confidential data at rest and is created with mode `0o600`.

## Modules

| Module | Role |
|---|---|
| `codekavach.core.store.db` | Engine (`create_db_engine`), sessions (`make_session_factory`, `session_scope`) and `init_db(layout)` |
| `codekavach.core.store.orm` | Tables `projects`, `scans`, `stage_runs`, `findings`; `UtcDateTime`; the constraint naming convention |
| `codekavach.core.store.migrate` | Programmatic Alembic: `upgrade_to_head`, `current_revision`, `head_revision`, `DatabaseTooNewError` |
| `codekavach.core.store.repositories` | The only code that reads and writes the tables: `ProjectRepository`, `ScanRepository`, `FindingRepository`; `ScanRecorder` (used by `run_scan`); `db_probe` |
| `codekavach/core/store/migrations/` | Alembic `env.py`, `script.py.mako` and `versions/`: a data directory without `__init__.py` (ADR-0007 D14) |

`init_db(layout)` creates the database if needed and upgrades it to the newest revision. It runs offline and needs no `alembic.ini`. When the database was migrated by a newer CodeKavach, it raises `DatabaseTooNewError` and leaves the file unchanged.

## What `run_scan` records

With `persist=True` (the default) `run_scan` finds or creates the project by its root directory, inserts the scan with status `running` before the first stage, and afterwards stores the final scan, its stage runs and, when the `findings` artefact exists, its findings. Each step is one transaction; none stays open while the scan runs. `persist=False` leaves no database file behind.

- `document_json` (`model_dump_json()` of the E02 model) is authoritative. Models are rebuilt from it with `load_versioned`; the scalar columns are for filtering and sorting only.
- A finding row is keyed by (`id`, `scan_id`): a scan whose `rate` stage is served from the stage cache reuses the findings of an earlier scan and stores them under its own scan id.
- A scan of the same project still `running` and older than `scan.timeout_seconds` was left by a process that died; the next `run_scan` marks it `failed`. Younger ones are left alone, because they may belong to a scan running at the same time.
- A database error after the orchestrator finished is logged by exception class and raised as `PersistenceError`; the artefacts and the manifest are already on disk.

Findings hold real paths and evidence text, so the database is confidential client data. It holds no scan salt and no vault contents (tested in `tests/privacy/test_pipeline_salt_locality.py`).

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
