# `data/`

Taxonomy, risk and compliance tables used by the `rate` stage (owning epic: E29). Every table
records its sources in [`SOURCES.yaml`](SOURCES.yaml); rows that are CodeKavach's interpretation
rather than a copy of a published document are marked `derived`.

| File | Contents |
|------|----------|
| `cwe/catalogue.yaml` | CWE knowledge base: name, abstraction, 2024 Top 25 rank, OWASP Top 10 2021 category, ASVS 4.0.3 requirements, CAPEC ids, weakness family |
| `cwe/families.yaml` | Per weakness family: default CVSS v4.0 and v3.1 Base vectors, OWASP Risk Rating threat factors, remediation guidance, references, compliance control groups |
| `taxonomy/owasp-top10-2021.yaml` | OWASP Top 10 2021 category titles and links |
| `compliance/controls.yaml` | Control groups mapped to PCI DSS 4.0.1, ISO/IEC 27001:2022 Annex A, NIST SSDF 1.1, RBI CSF 2016 and IT Governance Master Direction 2023, SEBI CSCRF 2024 and CERT-In Directions 2022 |
| `SOURCES.yaml` | The documents each table draws on, with version, URL and basis |

The loader is `codekavach.risk.taxonomy.loader`. It looks for this directory at
`$CODEKAVACH_DATA_DIR`, then next to the source checkout (also the Docker image layout). A finding
mapped to a framework clause is evidence for an auditor to consider, not a compliance opinion.
