# Risk rating method

Owning epic: E29 (issues #259, #260). Code: `src/codekavach/risk/`. Data: `data/` (sources in
`data/SOURCES.yaml`). This page is the rating method a report refers to.

Every finding produced by the `rate` stage carries:

| Field | Meaning |
|-------|---------|
| `cvss4_vector`, `cvss4_score` | CVSS v4.0 Base vector and score (nomenclature in `risk.cvss4_nomenclature`, normally `CVSS-B`; `CVSS-BT` when a CISA KEV listing sets `E:A`) |
| `cvss31_vector`, `cvss31_score` | CVSS v3.1 Base vector and score, for tools that still expect v3.1 |
| `severity` | Qualitative severity under the severity policy (below) |
| `likelihood.level`, `impact.level` | Cell on the five-by-five risk matrix, with a rationale and narrative |
| `risk` | How the rating was reached: OWASP factors and bands, matrix label, per-metric rationale, adjustments, weakness family, CWE name, Top 25 rank, knowledge-base version |
| `owasp` | OWASP Top 10 2021 category (`basis: official` when OWASP lists the CWE, else `derived`) |
| `taxonomy` | ASVS 4.0.3 requirements, CAPEC attack patterns, CWE Top 25 2024 rank |
| `compliance` | PCI DSS 4.0.1, ISO/IEC 27001:2022 Annex A, NIST SSDF 1.1, RBI CSF 2016 and IT Governance Master Direction 2023, SEBI CSCRF 2024, CERT-In Directions 2022 (all `basis: derived`) |
| `references`, `remediation` | MITRE CWE page, OWASP cheat sheets; family remediation text when the model gave none |

## CVSS scoring

Scores are computed locally from the FIRST specifications; nothing is fetched at scan time.

- **v4.0** (`risk/cvss/v4.py`): macrovector (EQ1 to EQ6), lookup in the published score table
  (`risk/cvss/_v4_tables.py`, transcribed from the FIRST reference calculator), severity distance
  to the maximal vectors, mean proportional distance, clamp and round half up to one decimal.
- **v3.1** (`risk/cvss/v31.py`): the Base equations with the specification's Roundup.

Both were cross-checked against an independent implementation (the Red Hat `cvss` library) on
100,000 random vectors with no difference; `tests/unit/risk/golden/` holds the regression set.

## Proposing a vector

The vector comes, in order of precedence, from:

1. a vector the reporting engine supplied (SARIF property `cvss4_vector` / `cvss31_vector`);
2. for dependency and misconfiguration findings, whose engines rate each instance, a
   representative vector for the engine's severity (`SEVERITY_LADDER` in `risk/templates.py`);
3. the default vector of the CWE's weakness family (`data/cwe/families.yaml`), adjusted with
   deterministic code evidence only:
   - untrusted data enters from a local source (argv, environment, files): `AV:L`;
   - the handler sits behind an authentication guard (`login_required`, `Depends(get_current_user)`,
     `@PreAuthorize`, ...): `PR:L`;
   - the code is test code: `AT:P` (v3.1 `AC:H`).

Model answers do not change the vector (`tests/unit/risk/test_rate.py`).

## OWASP Risk Rating

`risk/owasp.py` follows the OWASP Risk Rating Methodology: eight likelihood factors (threat agent
and vulnerability, 0 to 9) pre-filled per weakness family and adjusted for reachability
(anonymous network: opportunity and size 9; authenticated: 7 and 6; local: 4 and 4), four
technical impact factors derived from the CVSS impact metrics, and four business impact factors
from the asset criticality. Means below 3 are LOW, below 6 MEDIUM, otherwise HIGH; the overall
rating (note, low, medium, high, critical) comes from the methodology's 3x3 table. Technical
impact is used unless a business context was configured.

## Five-by-five matrix

`risk/matrix.py`. Impact level from the CVSS v4.0 score (0 → 1, below 4 → 2, below 7 → 3, below
9 → 4, else 5). Likelihood level from the OWASP likelihood score in five equal steps, one step
lower when detection confidence is low (for example after the model answered "not vulnerable").
Cell label from the product: up to 4 low, up to 9 medium, up to 16 high, 20 and 25 critical.

## Severity policy

`risk/severity.py`, `SeverityPolicy`:

| Setting | Default | Effect |
|---------|---------|--------|
| `source` | `cvss4` | `cvss4`, `owasp` or `strictest` (the higher of the two) |
| `bands` | FIRST: 9.0 critical, 7.0 high, 4.0 medium, 0.1 low, 0.0 info | Score thresholds |
| `engine_authoritative_kinds` | `dependency`, `misconfiguration` | Use the engine's per-instance severity for these kinds |
| `downgrade_test_code` / `downgrade_vendored` | true / true | One step lower in test or vendored code |
| `engine_floor` | false | Do not rate below the engine's severity |
| `model_downgrade` | false | Lower one step when the model says "not vulnerable" with at least `model_downgrade_min_confidence` (high) |

By default the model's verdict does not move the severity: it lowers confidence, which ranks the
finding lower and lowers its matrix likelihood. A deployment overrides the policy with a YAML file
named by `CODEKAVACH_RISK_POLICY`:

```yaml
severity:
  source: strictest
  engine_floor: true
  model_downgrade: false
```

Every policy step applied is listed in `risk.adjustments` (`policy:test_code_downgrade`,
`policy:engine_severity`, `policy:model_downgrade`, ...).

## Compliance mapping

`data/compliance/controls.yaml` maps control groups to framework clauses; each weakness family
lists its groups, and a `baseline` group (the code review itself: PCI DSS 6.2.3 and 6.3.1, ISO
A.8.28 and A.8.29, SSDF PW.7.2 and RV.2.2, RBI ASLC, SEBI ID.RA) applies to every finding. RBI
Annex 1, the RBI Master Direction and SEBI CSCRF are cited at section, framework or category level
only. All placements are CodeKavach's interpretation (`basis: derived`). A mapped clause is
evidence for an auditor to consider, not a compliance opinion.

## Not implemented yet

EPSS, LEV and SSVC signals beyond the KEV flag, the overall risk posture score, the per-path asset
profile (`[risk]` settings section), the MITRE XML catalogue build tool and the OpenCRE snapshot
from the issue texts; the knowledge base is curated by hand for the CWEs we emit, the 2024 Top 25
and the OWASP Top 10 2021 categories.
