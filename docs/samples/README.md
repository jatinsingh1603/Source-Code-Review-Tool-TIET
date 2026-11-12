# `docs/samples/`

Sample audit reports produced by CodeKavach. Owning epic: E31.

## `kavachbank/`

Every report format from one scan of the KavachBank fixture (`fixtures/kavachbank`), a deliberately
vulnerable banking sample. The scan ran at privacy level L3 with the `agentrouter` provider
(`gpt-5.6-sol`), so the model assessments in the reports are real answers to the sanitised
payloads recorded in the egress ledger. The fixture's credentials are synthetic and appear in the
reports only as masked values or typed placeholders.

| File | Format |
|------|--------|
| `report.html` | Interactive single-file report: search, filters, sort, dark mode, print styles |
| `report.pdf` | Paginated A4 report with cover, linked contents and classification headers |
| `report.docx` | Word report with the same sections; press F9 in Word to build the contents |
| `report.sarif` | SARIF 2.1.0 for GitHub code scanning and other SARIF consumers |
| `report.json` | Versioned JSON (`codekavach.report/v1`) |
| `report.csv` | One row per finding |
| `report.xlsx` | Tracker workbook: summary, findings with owner and due date, roadmap, compliance, privacy |
| `report.md` | Size-capped Markdown summary for pull requests |
| `report.compliance.html` | Compliance annex: controls against the findings that are evidence for them |
| `manifest.json`, `SHA256SUMS` | Integrity manifest over every file above |

Check the files against the manifest with `sha256sum -c SHA256SUMS` in this directory.

## Regenerating

```bash
cp -r fixtures/kavachbank /tmp/kb && cd /tmp/kb
codekavach scan . --provider agentrouter --accept-egress   # or --provider mock, offline
codekavach report . --format html,pdf,sarif,json,csv,xlsx,docx,markdown,compliance \
  --output-dir <repo>/docs/samples/kavachbank
```

`codekavach demo --out <dir>` produces the same set offline with the mock provider.
`tests/unit/report/test_samples.py` checks the committed files against the manifest and for planted
secrets.
