# Known limitations

Issues found in pre-demo audits and deliberately not fixed, because the fix would change
demo-visible output or was too large to make safely before the code freeze. Each section is one
audit angle.

## Risk data accuracy (CWE, OWASP, compliance, CVSS), 2026-11-15

Checked: all 88 entries of `data/cwe/catalogue.yaml` (names, abstraction, 2024 Top 25 ranks, OWASP
Top 10 2021 official or derived basis), `data/cwe/families.yaml`, `data/compliance/controls.yaml`,
and CVSS scoring against the Red Hat `cvss` library (all 2,592 CVSS v3.1 base vectors and 40,000
random CVSS v4.0 vectors with threat and environmental metrics: no difference).

Not fixed:

- **Remediation is per family, so it is generic for some weaknesses (low).** A CWE without its own
  `remediation` gets its family's text. It still does not address the weakness for CWE-252
  (unchecked return value, gets input-validation advice), CWE-522 (insufficiently protected
  credentials, gets authentication advice), and CWE-134, CWE-476 and CWE-416 share one
  memory-safety paragraph about bounds checks. CWE-522 was left alone because it appears in the
  sample and golden reports.
- **Default CVSS vectors are per family, not per CWE (low).** Open redirect (CWE-601) shares the
  CSRF vector (v3.1 `UI:R/S:U/C:N/I:H/A:N`, 6.5) where `S:C/C:L/I:L` (6.1) is the usual scoring;
  LDAP and XPath injection share the SQL injection vector; CWE-208 (timing) and CWE-295
  (certificate validation) share the weak-cryptography vector. The vectors are labelled "derived"
  and the rate stage adjusts them with code evidence, but they are defaults, not NVD scores.
  Changing them would change severities in the seeded demo.
- **NIST SSDF PW.7.2 carries the title of practice PW.7 (low).** `controls.yaml` titles PW.7.2
  "Review and/or analyze human-readable code to identify vulnerabilities", which is the PW.7
  practice title; task PW.7.2 reads "Perform the code review and/or code analysis based on the
  organization's secure coding standards, and record and triage all discovered issues". The id is
  the right task. Not changed because the baseline row is printed for every finding in the golden
  and sample reports.
- **SEBI CSCRF, RBI and CERT-In rows are cited at category or section level (low).** The SEBI rows
  use function.category codes (ID.RA, PR.AA, PR.DS, PR.PS, DE.CM) and the RBI rows name Annex 1
  sections, as the titles say; they are not numbered requirements, and the SEBI category codes were
  not re-verified against the circular text in this audit. CERT-In is mapped only for the logging
  family (Directions of 28 April 2022, item iv, 180-day log retention); other families have no
  CERT-In row.
- **Several Top 25 and availability CWEs have no OWASP Top 10 2021 category (informational).**
  Memory-safety CWEs, CWE-400, CWE-770, CWE-1333, CWE-367 and CWE-252 are not in any category's
  list of mapped CWEs, so their findings show no OWASP category. This is correct, not a gap.
- **The CVSS parser is strict (informational).** It accepts only `CVSS:3.1/` and `CVSS:4.0/`
  prefixes; a `CVSS:3.0/` vector, a lower-case prefix or v4.0 metrics out of the specification
  order are rejected rather than normalised. v3.1 temporal metrics are accepted and ignored: the
  score shown is the base score.
