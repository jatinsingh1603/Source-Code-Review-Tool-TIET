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
