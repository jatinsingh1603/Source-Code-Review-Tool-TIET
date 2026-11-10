# Hostile archives and repositories

The hostile corpus for the ingest sources (E06-03) is built when the tests run, by `tests/support/hostile.py`, into `tmp_path`. Nothing in it is stored here, so no file in this repository can harm a checkout, a scanner or an unpacking tool that is pointed at the directory.

Each builder makes one named attack; the tests that use it say what must happen:

| Builder | Shape | Expected result |
|---------|-------|-----------------|
| `zip_bomb`, `tar_gz_bomb` | A highly compressible entry far larger than its archive | `LimitExceededError` with kind `archive_ratio` (or `file_size`), nothing left behind |
| `many_entries_tar` | More entries than the entry budget | `LimitExceededError` with kind `archive_entries` |
| `tar_of` with `../` names | Zip Slip style traversal | `UnsafeArchiveEntry`, no file outside the working root |
| `zip_with_symlink`, `member` | Link members, absolute paths, device nodes | Skipped or refused; no link is ever created |
| `add_gitlink` | A repository whose tree holds a submodule entry | Cloned without the submodule; recorded in the coverage artefact |

Sources: the extraction limits follow Fifield, "A better zip bomb" (WOOT 2019); the entry-name rules follow Snyk's Zip Slip research; the clone hardening follows git advisory GHSA-8h77-4q3w-gfgv (CVE-2024-32002). All three are listed in `RESOURCE.md`.
