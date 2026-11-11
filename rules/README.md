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

## Catalogues and the default pack (E16-03)

`catalogues/<language>/<framework>.yaml` names, per language and framework, the symbols that are
sources of untrusted data, dangerous sinks and sanitisers. A `symbol` is a fully qualified dotted
name (`os.system`, `flask.request.args`) matched through the file's imports, so `import os as o`
and `from os import system` still resolve while a local variable called `os` does not; an
unresolved receiver falls back to the last two segments and gives a *partial* match, which lowers
the candidate's confidence by one step and sets `rule.resolution=partial`. An entry may use a
`pattern` instead of a `symbol`. `context` (sinks) and `covers` (sanitisers) draw on one closed
vocabulary: `html`, `html_attr`, `js`, `css`, `url`, `sql`, `shell`, `path`, `ldap`, `xpath`,
`xml`, `header`, `log`, `template`, `deserialisation`. A `where` item
`{metavariable: $X, inadequate_for: html_attr}` holds when `$X` is a call of a catalogued
sanitiser that does *not* cover that context; the candidate then carries
`sanitiser.inadequate` and `sanitiser.required_context`.

Authoring helpers beyond E16-02: a catalogue id ending in `.*` selects every entry with that
prefix (`python.sink.shell.*`); the kinds `parameter`, `request_derived`, `dynamic_string` and
`constant_binding` (a literal, or a name assigned exactly one literal); `function_regex` on a
clause requires its regular expression to match the text of the enclosing function including its
decorators, which is how a `none` clause says "this handler already checks"; `regex` and
`not_regex` also test the value a lone local name was assigned. A rule with `kind: hotspot` yields
a `CandidateKind.HOTSPOT` candidate: an observation for the reasoning step, not a finding.

The `default` pack (`packs/default/`, one directory per weakness class) is original CodeKavach
work under the MIT licence; every rule says so in `metadata.source`. `docs/reference/rule-coverage.md`
is generated from it (`uv run python -m codekavach.analysis.rules.coverage`) and lists what each
language covers and what it does not. `public_names()` returns every catalogue symbol: these are
the names the pseudonymiser's public allow-list keeps in clear (ARCHITECTURE section 6.2 step 4)
so that sources, sinks and sanitisers stay recognisable in a sanitised payload; an operator who
adds a private catalogue adds the same names through `privacy.public_allowlist_extra`.
