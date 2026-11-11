# Rule metadata

Generated from the rule models by `python -m codekavach.analysis.rules.schema`; do not edit.
A rule file is YAML. Validate it with `codekavach rules validate`. The JSON Schemas are in
`docs/schemas/rules/`.

## RuleDef

One rule: where it applies, what it matches and what a match means.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | `str` | yes | Unique id, `<language>.<class>.<specific>`, for example `python.sqli.cursor-execute-concat`. |
| `languages` | `tuple[str, ...]` | no | Languages the rule applies to (names of the `Language` enum). |
| `message` | `str` | yes | One-line statement of the problem, shown in the report. |
| `severity` | `Severity` | yes | `info`, `low`, `medium`, `high` or `critical`. |
| `confidence` | `Confidence` | yes | `low`, `medium` or `high`: how often a match is a real weakness. |
| `kind` | `Literal[vulnerability, hotspot]` | no | `vulnerability` (default) or `hotspot`: a hotspot marks code for review and asserts no weakness. |
| `metadata` | `RuleMeta` | no | What a report says about the weakness (see `RuleMeta`). |
| `match` | `MatchBlock` | no | The match block (see `MatchBlock`). |
| `taint` | `TaintSpec | None` | no | Optional taint spec: catalogue entry ids for sources, sinks and sanitisers. |
| `fixtures` | `tuple[str, ...]` | no | Paths of the positive and negative test files, relative to the pack. |

## RuleMeta

What a report says about the weakness a rule looks for.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `cwe` | `tuple[int, ...]` | no | At least one CWE number; never a Pillar and never CWE-20. |
| `owasp` | `tuple[str, ...]` | no | OWASP Top 10 ids such as `A03:2021`. |
| `asvs` | `tuple[str, ...]` | no | OWASP ASVS requirement ids such as `5.3.4`. |
| `capec` | `tuple[int, ...]` | no | CAPEC attack pattern numbers. |
| `references` | `tuple[str, ...]` | no | URLs that explain the weakness. |
| `remediation` | `str` | no | How to fix it, at most 2,000 characters. |
| `licence` | `str` | no | SPDX id of the rule's licence; `MIT` for everything under `rules/mit/`. |
| `source` | `str | None` | no | Provenance when the rule was adapted from another MIT-licensed pack. |
| `added_in` | `str` | no | Pack version that introduced the rule. |

## MatchBlock

``any`` clauses are alternatives, ``all`` must all hold and ``none`` must not hold.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `any` | `tuple[PatternClause, ...]` | no | Alternatives: at least one clause must hold. |
| `all` | `tuple[PatternClause, ...]` | no | Every clause must hold. |
| `none` | `tuple[PatternClause, ...]` | no | No clause may hold. |

## PatternClause

One clause of a match block: a pattern of one kind, with optional constraints.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `pattern` | `str | None` | no | Code pattern with metavariables. |
| `pattern_inside` | `str | None` | no | The match must lie inside code matching this pattern. |
| `pattern_not_inside` | `str | None` | no | The match must not lie inside code matching this pattern. |
| `pattern_regex` | `str | None` | no | Regular expression over the matched text (at most 512 characters). |
| `ref` | `str | None` | no | Id of another rule in the same pack, for reuse. |
| `function_regex` | `str | None` | no | Regular expression the text of the enclosing function, with its decorators, must match (at most 512 characters); combine with `none` to exclude handlers that already check. |
| `where` | `tuple[Constraint, ...]` | no | Constraints on the clause's metavariables. |

## Constraint

A condition on one metavariable: exactly one of the condition keys is expected.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `metavariable` | `str` | yes | The metavariable the condition applies to, such as `$Q`. |
| `regex` | `str | None` | no | The bound text must match this expression. |
| `not_regex` | `str | None` | no | The bound text must not match this expression. |
| `kind` | `str | None` | no | Node kind: concatenation, call, literal, identifier, attribute, interpolation or argument. |
| `is_constant` | `bool | None` | no | True when the bound node must be a compile-time constant. |
| `min_length` | `int | None` | no | Minimum length of the bound text. |
| `equals` | `str | None` | no | The bound text must equal this value. |
| `one_of` | `tuple[str, ...] | None` | no | The bound text must equal one of these values. |
| `catalogue` | `str | None` | no | The bound node must match this catalogue entry id (by symbol or pattern). |
| `inadequate_for` | `str | None` | no | The bound node must be a call to a catalogued sanitiser that does not cover this context. |

## TaintSpec

Catalogue entry ids for a taint rule; stored here, handed to the taint engine by E16-02.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `sources` | `tuple[str, ...]` | no | Catalogue entry ids of taint sources. |
| `sinks` | `tuple[str, ...]` | no | Catalogue entry ids of taint sinks. |
| `sanitisers` | `tuple[str, ...]` | no | Catalogue entry ids of sanitisers. |
| `require_path` | `bool` | no | True when a match needs a proven source-to-sink path. |

## PackManifest

The ``pack.yaml`` file of a pack.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | `str` | yes | Pack id, lower-case words joined by hyphens. |
| `version` | `str` | yes | Semantic version; part of the finding provenance. |
| `licence` | `str` | yes | SPDX id; must equal the licence directory the pack lives in. |
| `description` | `str` | no | What the pack covers. |
| `languages` | `tuple[str, ...]` | no | Languages the pack has rules for. |

## Catalogue

A ``catalogues/<language>/<framework>.yaml`` file.

    Entries are listed under ``entry_points``, ``sources``, ``sinks`` and ``sanitisers``; the
    older flat ``entries`` list with an explicit ``kind`` is accepted too. :meth:`items` returns
    every entry with its ``kind`` filled in.


| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | `str | None` | no | Optional id of the catalogue. |
| `language` | `str` | yes | Language the entries apply to. |
| `framework` | `str` | yes | Framework or library the entries describe. |
| `entry_points` | `tuple[CatalogueEntry, ...]` | no | Handlers and other places where outside data enters. |
| `sources` | `tuple[CatalogueEntry, ...]` | no | Symbols that return untrusted data. |
| `sinks` | `tuple[CatalogueEntry, ...]` | no | Symbols that are dangerous with untrusted data. |
| `sanitisers` | `tuple[CatalogueEntry, ...]` | no | Symbols that neutralise data, with the contexts they cover. |
| `entries` | `tuple[CatalogueEntry, ...]` | no | Flat list of entries that each give their own `kind`. |

## CatalogueEntry

One entry point, source, sink or sanitiser, referred to by id from rules and taint specs.

    An entry names code either by ``symbol`` (a fully qualified dotted name, matched against the
    imports of the file) or by a ``pattern`` (a rule pattern). ``context`` is the output context
    of a sink and ``covers`` the contexts a sanitiser is adequate for; both draw on ``CONTEXTS``.
    ``kind`` is taken from the section of the catalogue file the entry is listed in.


| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | `str` | yes | Entry id, referenced from rules and taint specs. |
| `kind` | `CatalogueKind | None` | no | `entry_point`, `source`, `sink` or `sanitiser`; set by the section the entry is listed in. |
| `type` | `str` | no | What kind of source or entry point, such as `http_param`. |
| `symbol` | `str | None` | no | Fully qualified dotted name, matched against the imports of the file. |
| `pattern` | `str | None` | no | Code pattern that identifies the entry; use instead of `symbol`. |
| `arg` | `int | None` | no | Index of the dangerous argument of a sink. |
| `context` | `str | None` | no | Output context of a sink: html, html_attr, js, css, url, sql, shell, path, ldap, xpath, xml, header, log, template or deserialisation. |
| `covers` | `tuple[str, ...]` | no | Contexts a sanitiser is adequate for; a sanitiser covers a sink only when the sink context is listed. |
| `description` | `str` | no | What the entry is. |

## Example

```yaml
id: python.sqli.cursor-execute-concat
languages: [python]
message: SQL query built by string concatenation
severity: high
confidence: medium
metadata:
  cwe: [89]
  owasp: ["A03:2021"]
  asvs: ["5.3.4"]
  capec: [66]
  licence: MIT
  remediation: Use a parameterised query and pass values as parameters.
  references: ["https://cwe.mitre.org/data/definitions/89.html"]
  added_in: "1.0.0"
match:
  any:
    - pattern: $CUR.execute($Q)
      where:
        - metavariable: $Q
          kind: concatenation
  none:
    - pattern: $CUR.execute($Q, $PARAMS)
```
