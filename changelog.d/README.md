# Changelog fragments

Every user-visible change adds one small file here. At release time the files are collected into `CHANGELOG.md` and removed (ADR-0004). This avoids merge conflicts in one shared file when several contributors work in parallel.

## File name

`<issue-number>.<type>.md`, for example `169.added.md`.

- Without an issue: `+<short-slug>.<type>.md`, for example `+scaffolding.added.md`. The slug uses lower-case letters, digits and hyphens.
- Several fragments of one type for one issue: `169.added.1.md`, `169.added.2.md`.

`make changelog-check` verifies the names; it runs in CI.

## Types

The types are the categories of Keep a Changelog.

| Type | For |
|------|-----|
| `added` | New features |
| `changed` | Changes in existing behaviour |
| `deprecated` | Features that will be removed |
| `removed` | Features that were removed |
| `fixed` | Bug fixes |
| `security` | Vulnerabilities, and every change to what leaves the client's machine (privacy levels, redaction, egress behaviour). Such a fragment starts with the word "Privacy:". |

## Content

- One or two sentences, written for a user of the tool, not for a developer. British spelling.
- No issue number in the text; it is appended from the file name.
- No tool attribution lines.
- Do not describe an unfixed vulnerability in detail (see `SECURITY.md`), and do not mention client names or data.

## What needs a fragment

Anything a user, operator or integrator can observe: CLI flags, configuration keys, output formats, privacy behaviour, supported engines or providers, fixed bugs.

Refactoring, tests, CI and internal documentation need none.

## Commands

```bash
make changelog-draft   # print the upcoming section; changes no file
make changelog-check   # verify the fragment file names
```

`towncrier build` without `--draft` consumes the fragments and is run only when a release is cut (E39).
