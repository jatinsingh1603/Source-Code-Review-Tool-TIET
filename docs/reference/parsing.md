# Parsing: languages and what analyses them

The parse stage (epic E07) reads each source file with a tree-sitter grammar and the language's own rules (a `LanguageSpec`): which nodes are identifiers, string literals and comments, how names are scoped, which functions a file defines, and which imports it makes. The privacy layer depends on these results, so a language is added only with a conformance corpus and an identifier-exhaustiveness test.

## Supported languages

| Language | Extensions | Spec | Deep engine named in `docs/research/INSIGHTS.md` section 5.2 | Integrated in this build |
|---|---|---|---|---|
| Python | `.py`, `.pyi` | `specs/python.py` | Pysa | no |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `specs/javascript.py` | atom / Joern JS frontend | no |
| TypeScript | `.ts` | `specs/javascript.py` (shared walker) | atom / Joern JS frontend | no |
| Java | `.java` | `specs/java.py` | SpotBugs with Find Security Bugs, Infer | no |
| Go | `.go` | `specs/go.py` | gosec, govulncheck | no |

"Deep engine" means an analyser that follows data across functions and needs the project to build. Where the last column says no, a file of that language is parsed and sliced by CodeKavach's own tree-sitter rules only, and a report must say that no deep engine looked at it. A language that has no spec is not parsed at all; the stage records `no_language_spec` for each of its files and the coverage artefact lists them.

`codekavach doctor` lists one `parsing:grammar:<language>` check per supported language, with the pinned grammar version. All grammars come from one pinned `tree-sitter-language-pack` release (`PINNED_PACK_VERSION` in `codekavach.parsing.loader`). The parse cache key contains the language and its grammar version, so bumping the pin of one language invalidates the cached results of that language only; a change of the pack release itself invalidates every entry.

## Scoping rules

The symbol table attributes every identifier to a binding scope or to `external` (a name the file does not declare). The rules differ by language and each has a test in `tests/unit/parsing/`.

| Language | Rules that matter for renaming |
|---|---|
| Java | A field is visible in every method of its class by its bare name; a local or parameter of the same name shadows it, and `this.x` names the field. Blocks, `for` headers, `catch` clauses, `try`-with-resources and lambdas open scopes. An anonymous class opens a class scope whose parent is the enclosing method. Pattern variables bind in the enclosing scope. Annotation names are identifiers; names after a dot and method-call names that no declaration binds are external. |
| Go | `:=` in an `if`, `switch` or `for` header binds for the whole statement including the `else` chain. A receiver and named results are parameters. A function literal is a function scope. Field and method names are declared in the type's scope, which a bare name in another function does not reach. A name after a selector, a label and the blank identifier are external or unbound. Exported and unexported names are declared alike. |

## Import classification

Each import is classified as `stdlib`, `internal` or `third_party`, and an import that cannot be resolved is `internal` so that it is renamed rather than kept.

| Language | `stdlib` | `internal` | `third_party` |
|---|---|---|---|
| Java | `java.*`, `javax.*`, `jdk.*` | a package whose directory exists under the project root or a conventional source root (`src/main/java`, `src/test/java`, `src`, `app/src/main/java`) | any other package |
| Go | a path whose first element has no dot | a path under the `module` line of `go.mod`, a relative path, or a first element that names a project directory | any other path |

`go.mod` is read as untrusted text: at most 256 KiB, only the `module` line is used, and nothing in it is executed.
