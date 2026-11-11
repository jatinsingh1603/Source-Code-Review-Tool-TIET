# `rules/`

Native rule packs (YAML) for the rule engine. Owning epic: E16.

```
rules/<licence>/packs/<pack-id>/pack.yaml
rules/<licence>/packs/<pack-id>/<class>/<rule-id>.yaml
rules/<licence>/catalogues/<language>/<framework>.yaml
```

`rules/mit/` is bundled with CodeKavach. Any other top-level directory (named after its SPDX
licence) is user-installed and is never shipped: content whose terms forbid redistribution or use
in a service must not enter the MIT build. A rule's `metadata.licence` must equal the directory it
lives in (`CK-RULE-012`).

Check a tree with `codekavach rules validate rules/mit`. The rule format is described in
`docs/reference/rule-metadata.md`.

## How a rule matches, and how to test one

Patterns are snippets of the target language. `$X` captures one subtree, `$...X` a run of siblings,
`_` any one node and `...` any run of siblings or statements. A name used twice must bind the same
text (whitespace collapsed). A string `"..."` matches any string literal. A rule matches at an
anchor node, taken from the first `pattern`: `any` clauses are alternatives, every `all` clause
must also hold at that node and no `none` clause may hold there (not elsewhere in the file).

The matcher is built in this repository and compares tree-sitter trees; it is not an ast-grep
wrapper and compiles no tree-sitter queries. A query cannot say "any run of statements" or "any
argument list", and ast-grep would add a second pattern engine between the DSL and the trees the
parse stage already builds. The grammar version is part of the cache key, so a grammar bump is a
cache miss, not a silent change of behaviour. The `Matcher` interface hides the backend.

A fixture lives at `tests/fixtures/rules/<language>/<rule-id>.<ext>`. A comment line
`# ruleid: <rule-id>` asserts a match on the next code line, `# ok: <rule-id>` asserts none and
`# todoruleid: <rule-id>` records a known gap (counted, does not fail the test). The comment token follows
the language. A match that no annotation covers fails the test.

```text
codekavach rules test [--pack ID] [--rule ID] [--fixtures DIR] [--update]
```

`--update` rewrites annotations from what the rule does now and is refused when `CI` is set.
