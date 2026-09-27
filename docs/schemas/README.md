# JSON Schemas of the core models

These files are the language-neutral contract of `codekavach.core.models` (`docs/ARCHITECTURE.md` section 5). The dashboard derives TypeScript types from them, integrations validate against them, and the JSON report renderer refers to them. Because they are committed, a model change shows up as a diff in review.

**Do not edit these files by hand.** Re-create them from the models:

```bash
uv run python -m codekavach.core.models.export          # write docs/schemas/
uv run python -m codekavach.core.models.export --check  # report drift, exit 1 if any
```

The test suite runs the check too, so a plain `uv run pytest` catches a stale schema.

## Files

| File | Contents |
|------|----------|
| `<model>.schema.json` | One self-contained JSON Schema (draft 2020-12) per exported model, in serialisation mode: it describes the documents CodeKavach writes |
| `llm_verdict.output.schema.json` | The provider-facing structured-output schema of `LLMVerdict` (no `$ref`, every object closed, every property required) |
| `index.json` | Name, file, schema version and SHA-256 of every schema file, sorted by name; the only place that records the version of the provider-facing schema |

Every schema carries `$schema`, an `$id` of the form `urn:codekavach:schema:<name>:<schema_version>` (version 0 for models that are not versioned documents), and `x-data-classification`: `raw` (client code, paths and names), `sanitised` (may be sent to an LLM), `untrusted` (produced by a model) or `metadata` (counts, hashes, ids). Consumers outside Python can use it to see which documents hold client data.
