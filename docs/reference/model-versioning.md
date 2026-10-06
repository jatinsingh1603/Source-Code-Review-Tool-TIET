# Model versioning and migrations

Persisted documents (findings, scans, candidates, payloads, baselines, cassettes, evaluation result sets) derive from `VersionedModel` and carry a `schema_version`. A model refuses documents of any version other than its current `SCHEMA_VERSION`. To read older documents, use `codekavach.core.models.migrate.load_versioned`, which upgrades them step by step before validation.

## Rules for changing a model

| Change | Version bump | Migration needed |
|--------|--------------|------------------|
| Add an optional field with a default | no | no |
| Add a required field | yes | yes (supply a value) |
| Rename or remove a field | yes | yes (`extra="forbid"` would reject old documents) |
| Narrow a constraint or remove an enum member | yes | yes (map the old values) |
| Widen a constraint or add an enum member | no | no (old tools reading new data may fail, which is accepted) |
| Change the meaning of a field without changing its shape | yes | yes, even if it is the identity function, to mark the boundary |

A version bump means raising the model's `SCHEMA_VERSION` by one and registering a step from the previous version. Steps live at the bottom of the model's own module, so that they are registered whenever the model is imported. `check_migration_completeness` runs in CI (E02-23) and reports any migratable model that is missing a step between 1 and its current version.

Migration functions receive stored documents, which may contain raw client code. They must be pure: they must not log their input and must not perform I/O. The loader passes each step a deep copy, so a step may mutate its argument. `MigrationError` messages name the model and the versions, never field values.

## How the loader works

1. `str` or `bytes` input is parsed with `json.loads`. A top level that is not a JSON object raises `MigrationError`, and so does invalid JSON (the message does not quote the document).
2. A missing `schema_version` counts as 1. The value must be an `int` of at least 1; `True`, `1.0`, `"1"`, `0` and negative numbers raise `MigrationError`.
3. A version newer than the model's raises `UnsupportedSchemaVersion`. Documents are never downgraded.
4. Each registered step upgrades the document by one version, and the loader sets `schema_version` after each step. A missing step raises `MigrationError`.
5. The result is validated in JSON mode (`model_validate_json`), because stored documents are JSON, and models with `SanitisedText` fields accept plain strings only from JSON.

## Worked example

`Widget` version 1 had a field `name`. Version 2 renamed it to `title`, and version 3 added the required field `colour`:

```python
class Widget(VersionedModel):
    SCHEMA_VERSION: ClassVar[int] = 3

    title: str
    colour: str


@register_migration(Widget, 1)
def _rename_name_to_title(data: dict[str, Any]) -> dict[str, Any]:
    data["title"] = data.pop("name")
    return data


@register_migration(Widget, 2)
def _add_colour(data: dict[str, Any]) -> dict[str, Any]:
    return {**data, "colour": "unknown"}
```

`load_versioned(Widget, '{"name": "w"}')` returns `Widget(title="w", colour="unknown", schema_version=3)`. A version 2 document goes through the second step only, and a version 3 document is validated unchanged.

## Hash-bearing documents

Rewriting a hash-bearing document would break its chain, so models such as `EgressRecord` set `MIGRATABLE: ClassVar[bool] = False`. The completeness check skips these models, and `load_versioned` raises `MigrationError` with an explanation when given an older version of one. When their format changes:

- keep the old class under a versioned name (for example `EgressRecordV1`);
- have the reader (E12 for the ledger) choose the class by each entry's `schema_version`;
- never rewrite an existing entry.

`SanitisedPayload` can be migrated only while a step leaves `text` unchanged. If a step changes `text`, normal validation of the result detects the `payload_hash` mismatch.

## Tests

Tests that need throw-away models register their steps inside `temporary_registry()`, which restores the registry on exit. See `tests/unit/core/models/test_migrate.py`.

## What the compatibility gate checks

`python -m codekavach.core.models.export --compat-base REF` compares every freshly built schema with the committed one at git revision `REF`. CI runs it on every push to `main`, against the commit `main` pointed at before the push, so that a push of several commits is judged as a whole. Each file is classified as `none`, `additive` or `breaking`, and the gate exits 1 when a file changes in a breaking way while its schema version (from `index.json`) stays the same.

| Observation (old to new) | Level |
|--------------------------|-------|
| Property removed | breaking |
| Property added and not required, or required with a `default` | additive |
| Property added and required, without a `default` | breaking |
| Property becomes required | breaking |
| Property becomes optional | additive |
| `type` changed, or a member removed from a `type` list or from `anyOf` | breaking |
| `enum` member removed | breaking |
| `enum` member added | additive |
| A bound (`minLength`, `maxLength`, `minimum`, `maximum`, `minItems`, `maxItems`) made stricter, or `pattern` changed | breaking |
| The same bounds loosened | additive |
| Only `description`, `title`, `examples` or `default` changed | none |
| A `$defs` entry renamed | none when the structure is the same, otherwise breaking ("definition renamed") |
| Any other keyword changed | breaking ("unrecognised change at `<pointer>`") |

The rules apply recursively through `properties`, `items`, `prefixItems`, `$defs` and `anyOf`/`oneOf`/`allOf` branches (matched by position). Every reason names a JSON pointer. In detail:

- A new schema file is `additive`.
- A deleted file is `breaking`, unless a commit message in the pushed range contains `[schema-remove]`.

**A heuristic.** When in doubt the gate reports `breaking`: a false alarm costs one version bump plus an identity migration, while a miss can corrupt stored experiment data. There is deliberately no skip flag. A false positive is resolved by raising `SCHEMA_VERSION` and registering an identity migration, which also records the boundary.

**Fail-safe edges:**

- If git is missing, or the base revision is not in the clone, the check prints a notice and exits 0, so that a source archive without git, such as the air-gapped bundle, is not blocked.
- A git call that takes longer than 10 seconds exits 2.
- `REF` must match `^[A-Za-z0-9._/~^-]{1,100}$` and must not start with `-`.

Tests: `tests/unit/core/models/test_compat.py`.
