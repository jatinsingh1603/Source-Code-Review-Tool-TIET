# JSON Schemas of the core models

These files are the language-neutral contract of `codekavach.core.models` (`docs/ARCHITECTURE.md` section 5). The dashboard derives TypeScript types from them, integrations validate against them, and the JSON report renderer refers to them. Because they are committed, a model change shows up as a diff in review.

**Do not edit these files by hand.** Re-create them from the models:

```bash
uv run python -m codekavach.core.models.export          # write docs/schemas/
uv run python -m codekavach.core.models.export --check  # report drift, exit 1 if any
```

The test suite runs the check too, so a plain `uv run pytest` catches a stale schema.

**After changing a model, run the export and commit the schema files in the same commit.** Three gates check this before and after a push:

- the `codekavach-schema-drift` pre-commit hook, which runs when files under `src/codekavach/core/models/` or `docs/schemas/` are staged;
- the "Schema drift check" step of the CI lint job;
- `make schemas-check`.

All three run `--check --check-migrations`. The second flag reports any versioned model whose `SCHEMA_VERSION` was raised without registering the upgrade step (see `docs/reference/model-versioning.md`). The hook never rewrites files; fix the drift with `make schemas` (or the command above) and stage the result.

## Files

| File | Contents |
|------|----------|
| `<model>.schema.json` | One self-contained JSON Schema (draft 2020-12) per exported model, in serialisation mode: it describes the documents CodeKavach writes |
| `llm_verdict.output.schema.json` | The provider-facing structured-output schema of `LLMVerdict` (no `$ref`, every object closed, every property required) |
| `index.json` | Name, file, schema version and SHA-256 of every schema file, sorted by name; the only place that records the version of the provider-facing schema |

Every schema carries `$schema`, an `$id` of the form `urn:codekavach:schema:<name>:<schema_version>` (version 0 for models that are not versioned documents), and `x-data-classification`: `raw` (client code, paths and names), `sanitised` (may be sent to an LLM), `untrusted` (produced by a model) or `metadata` (counts, hashes, ids). Consumers outside Python can use it to see which documents hold client data.

## Example documents

`examples/` holds one generated document per schema (`<model>.example.json`), plus two others:

- `llm_verdict.output.example.json`: the provider-facing verdict, without `schema_version`;
- `ledger_chain.example.jsonl`: three sealed ledger entries.

They are built from the deterministic test factories (`tests/support/factories.py`) and tell one story: the synthetic SQL injection in `src/bank/accounts.py`, line 88. They are built from that synthetic data only, not by running the tool on any code.

```bash
uv run python tools/schemas/build_examples.py          # write docs/schemas/examples/
uv run python tools/schemas/build_examples.py --check  # report drift, exit 1 if any
```

The CI step "Schema examples check" and the pre-commit hook `codekavach-schema-examples` run the check, and the tests validate every example against its schema and its model.

**What stays and what leaves.**

- The `candidate`, `code_slice`, `evidence` and `finding` examples show **raw** data: paths, names and code that stay on the client's machine.
- `sanitised_payload` is the only code-bearing document that may reach a provider.

Side by side, file lines 86 to 89 of the sample and the payload text built from them (hand-written here; the real pseudonymiser is E09):

| Original (`code_slice`, stays local) | Payload text (`sanitised_payload`, may be sent at L3) |
|---|---|
| `def find_by_owner(self, owner):` | `def fn_2(self, param_3):` |
| `cur = self.conn.cursor()` | `var_4 = self.field_5.fn_6()` |
| `cur.execute("SELECT * FROM accounts WHERE owner = '" + owner + "'")` | `var_4.execute("SELECT * FROM tbl_7 WHERE col_8 = '" + param_3 + "'")` |
| `return cur.fetchall()` | `return var_4.fetchall()` |

The names, the table and the column are gone. What is still disclosed is the control flow, the public API calls (`execute`, `fetchall`) and the shape of the SQL. A test checks that no identifier of four or more characters from the sample source appears in the payload example, apart from those public names and `self`.
