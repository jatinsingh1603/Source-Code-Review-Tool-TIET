# Developer scripts

Stand-alone scripts for contributors. They are not part of the shipped package and use only the standard library unless stated. Every issue that adds a script here appends a row.

| Script | Purpose | Makefile target | Owning issue |
|--------|---------|-----------------|--------------|
| `new_adr.py` | Create the next numbered ADR from the template and register it in `docs/adr/README.md`; `--check` verifies the index against the record files | `make adr title="..."` (added by E01-16) | #20 (E01-09) |
