# `fixtures/kavachbank/`

KavachBank is a small retail-banking application used as the sample for Demo 1. It is
**deliberately vulnerable. Never deploy it.** It carries **synthetic credentials and identifiers
only**: every secret is a vendor-documented example or a value that matches a detector's pattern
and fails its structural check, every identity number is built rather than issued, every email is
on the reserved `.test` domain and every phone number is in a reserved range. Each planted item is
listed below, in `ground-truth/manifest.yaml`, and resolved against `tests/support/synthetic.py`.

The application exists to be scanned. Its business logic (tiered interest with a festival bonus, a
fee schedule with waivers, a loan eligibility score and fraud thresholds by channel) is written to
read like a bank's code, because the demonstration shows what the privacy layer hides from the
model as much as what the scanner finds. Nothing here is installable or imported by CodeKavach, and
the wheel does not contain it.

```text
services/api/            Python service (Flask style): handlers, accounts, interest_engine,
                         fee_schedule, loan_scoring, fraud_rules, config, db, serialisation,
                         security, reports, webhooks
services/web/            Node service (Express style): routes, session, renderer, payments,
                         exporter, config
fixtures/seed/           customers.json: synthetic customer records
ground-truth/            manifest.yaml, negative_controls.yaml, terms.txt, and this fixture's loader
                         lives in tests/support/kavachbank.py
```

## Planted vulnerabilities

| Id | CWE | Class | Where | Demo 1 |
| --- | --- | --- | --- | --- |
| KB-VULN-001 | 89 | SQL injection | `services/api/accounts.py` | yes |
| KB-VULN-002 | 78 | Command injection | `services/api/reports.py` | yes |
| KB-VULN-003 | 22 | Path traversal | `services/web/exporter.js` | yes |
| KB-VULN-004 | 918 | Server-side request forgery | `services/web/payments.js` | yes |
| KB-VULN-005 | 502 | Insecure deserialisation | `services/api/serialisation.py` | yes |
| KB-VULN-006 | 327 | Weak password hash (MD5) | `services/api/security.py` | yes |
| KB-VULN-007 | 329 | Hard-coded initialisation vector | `services/api/security.py` | yes |
| KB-VULN-008 | 862 | Missing authorisation on an account-scoped handler | `services/api/handlers.py` | yes |
| KB-VULN-009 | 639 | Insecure direct object reference | `services/api/handlers.py` | yes |
| KB-VULN-010 | 79 | Reflected cross-site scripting | `services/web/renderer.js` | yes |

Each class has a safe counterpart next to it, so precision is measured rather than assumed
(`KB-SAFE-001` to `KB-SAFE-010` in `ground-truth/negative_controls.yaml`): a parameterised query, a
quoted shell command, a containment-checked export, an allow-listed fetch, `json.loads`, an scrypt
hash, a random IV, an authorised and ownership-checked handler, and an escaped response.

## Planted secrets

| Id | Kind | Where |
| --- | --- | --- |
| KB-SEC-001 | Connection string with an embedded password | `services/api/config.py` |
| KB-SEC-002 | AWS documentation access key id | `services/api/config.py` |
| KB-SEC-003 | AWS documentation secret access key | `services/api/config.py` |
| KB-SEC-004 | Payment gateway secret key (pattern-valid, never issued) | `services/api/config.py` |
| KB-SEC-005 | Signing secret | `services/api/config.py` |
| KB-SEC-006 | Private key block (fails its structural check) | `services/api/config.py` |
| KB-SEC-007 | Razorpay key id (synthetic) | `services/web/config.js` |
| KB-SEC-008 | Razorpay key secret (synthetic) | `services/web/config.js` |

## Planted personal data

`fixtures/seed/customers.json` holds two synthetic customers: an email, an international phone
number, a PAN, an Aadhaar number, a date of birth, an Indian mobile number, a GSTIN, an IFSC code, a
UPI handle and a card number (`KB-PII-001` to `KB-PII-010`).

## Regenerating the terms file

`ground-truth/terms.txt` is generated from the manifest (the planted secrets plus the business
domain dictionary) and a hook fails when it is stale:

```text
uv run python tools/gen_terms.py          # rewrite
uv run python tools/gen_terms.py --check  # fail if it is stale
```
