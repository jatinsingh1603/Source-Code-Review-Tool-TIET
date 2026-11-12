# REST API additions for the dashboard design

This page lists every route and field added to the REST API (`codekavach serve`, paths below
`/api/v1`) so that the dashboard client (`ui/src/api/types.ts`) can be wired to them. It follows
the "API gaps" section of [`ui/design/SCREENS.md`](../../ui/design/SCREENS.md). The base contract,
roles and error format are in [rest-api.md](rest-api.md); the machine-readable schema is served at
`/api/openapi.json` and printed by `codekavach serve --print-openapi`.

Every figure comes from data the server holds: the pipeline's artefacts and egress ledger, the
triage history, the configuration and the doctor checks. A field whose source is absent is `null`;
nothing is estimated unless the field says so. Features with no real backing answer
`501 not_implemented` (see [Not implemented](#not-implemented)).

Roles below: **R** any signed-in role (`read`), **L** admin, auditor, developer
(`privacy:read_ledger`), **O** admin, auditor (`privacy:read_original`), **A** admin
(`users:admin` or `settings:write`), **U** auditor and admin (`audit:read`), **S** any signed-in
user acting on their own data.

## Scans and the progress stream

New fields on every scan object (`GET /scans`, `GET /scans/{id}`, `last_scan` in `/stats` and
`/projects`):

| Field | Type | Source |
|-------|------|--------|
| `mode` | `"branch"` \| `"full"` | `branch` for a git project, `full` otherwise. The server has no diff mode. |
| `ref` | string \| null | The project's git ref, else the branch the scan record names. |
| `commit` | string \| null | Git commit of the scanned tree, when known. |
| `payloads` | int \| null | Sanitised payloads prepared (privacy summary). |
| `engines` | `[{id, status}]` | The analysers the pipeline ran (its `analyse-*` stages): `rules`, `taint`, `secrets`, `iac`, `sca`, `engines` (external engines), with `succeeded`, `failed` or `skipped`. |
| `eta_seconds` | int \| null | Running scans only: elapsed time scaled by the remaining progress. |
| `duration_seconds` | int \| null | Finished scans. |
| `privacy_summary.bytes_sent`, `.lines_sent`, `.privacy_score` | int \| null | See the privacy summary. |

Server-sent events (`GET /scans/{id}/events`, `GET /scans/{id}/log`):

- Every event's data carries `at` (ISO 8601, UTC), so `log` lines have timestamps.
- `stage` events carry `count` and `total` (items the stage reported; `null` when it reports
  none). `privacy-check` reports ledger entries, `report` the formats rendered.
- `progress` events add `stage`, `count`, `total` and `unit`.
- New event type `egress`. During the LLM review: `{payloads, total, final: false}` (candidates
  reviewed so far). After the ledger check: `{payloads, total, sent, recorded, blocked, bytes,
  bytes_sent, secrets_checked, terms_checked, terms_found, chain_ok, final: true}`. Clients that
  do not listen for `egress` are unaffected.

## Findings

`GET /findings` (R): the paged list across the latest completed scan of every project, or one
scan.

| Parameter | Meaning |
|-----------|---------|
| `scan_id`, `project_id` | Scope (default: the latest completed scan of every project). |
| `severity`, `status`, `language`, `engine`, `verdict`, `level`, `baseline_state` | Comma-separated lists. `engine` matches any engine that reported the finding; `verdict` is `vulnerable`, `not_vulnerable`, `uncertain` or `unreviewed`; `level` is the privacy level the finding's payload was reviewed at (the scan's level when it was not reviewed). |
| `cwe`, `owasp`, `q`, `path`, `assignee` | `owasp` matches a category prefix (`A03`); `assignee=me` is the caller. |
| `baseline` | Scan id to compare with (default: the previous completed scan of the project). |
| `view` | A built-in or saved view id; explicit parameters override its filters. |
| `offset`, `limit` | Paging (`limit` default 50, at most 1000). |

Response: `{items, total, offset, limit, baseline_scan_id, filters}`.
`GET /scans/{id}/findings` takes the same filters plus `offset` and `limit`, still returns a bare
list, and puts the total in the `X-Total-Count` header (`X-Offset`, `X-Limit` too).

New fields on every finding in a list and on the detail:

| Field | Type | Source |
|-------|------|--------|
| `engines` | `[{engine, rule_id, merged}]` | The finding's engines, then those folded into it by correlation (`aggregate.also_reported_by` on its candidate); `merged` is true for folded ones. |
| `merged_from` | int | Length of `engines`. |
| `verdict` | string | From the last LLM review (see above). |
| `privacy_level` | string \| null | Level of the last review, else the scan's level. |
| `language` | string \| null | From the finding. |
| `baseline_state` | `"new"` \| `"unchanged"` \| `"fixed"` \| null | Fingerprint delta (`codekavach.analysis.aggregate.delta.compute_delta`) against the baseline scan; `null` without one. `baseline_state=fixed` returns the baseline's findings that disappeared. |
| `sla_days`, `due_at`, `sla_state` | int \| null, datetime \| null, `"on_track"` \| `"due_soon"` \| `"overdue"` \| null | First seen plus the severity policy (`sla_days` in the server settings; defaults critical 7, high 30, medium 90, low 180, info none). `sla_state` is `null` once the finding is fixed, a false positive or an accepted risk. |

Extra fields on `GET /findings/{id}`:

| Field | Source |
|-------|--------|
| `baseline_scan_id` | The scan compared with. |
| `llm.runs[]` | `{source, task, provider, model, level, verdict, is_vulnerable, confidence, ledger_seq, outcome?}`: one row per review the finding records, then (for L roles) the other ledger calls of its candidates. |
| `llm.consensus` | `{samples, votes_vulnerable, votes_safe, abstained, agreement}` over the reviews. |
| `llm.temperature` | Always `null`: the ledger does not record it. |
| `llm.exploit_scenario`, `exploit_scenario` | The "Attack scenario" the explain task wrote, when it ran. |
| `llm.remediation_example`, `remediation_example` | `{language, code}`: the secure example the remediate task wrote, when it ran. |
| `remediation_diff` | Always `null`: no task produces a patch. |

Saved views (R, each user sees their own):

- `GET /views?scan_id=&project_id=` returns built-in views (`all`, `open`, `critical-high`,
  `mine`, `llm-confirmed`, `new`, `suppressed`) and the caller's saved views as
  `{id, name, filters, builtin, created_at, count}`.
- `POST /views {name, filters}` saves one (unknown filter keys are dropped); `DELETE /views/{id}`.

`POST /scans/{id}/sync/github` accepts `finding_ids: [..]` to sync only those findings; an id that
is not in the scan answers `404 finding_not_in_scan`.

## Privacy summary, ledger and attestation

`GET /scans/{id}/privacy` (L) adds:

| Field | Source |
|-------|--------|
| `bytes_sent`, `lines_sent` | UTF-8 size and line count of the payloads with outcome `sent`. |
| `bytes_recorded`, `lines_recorded` | The same for payloads recorded but not sent (dry run). |
| `repo_bytes`, `lines_total` | Size of the scanned copy of the code; lines scanned. |
| `score_parts[]` | `{label, value, kind}` from the privacy score components (`kind` is `measured`, `indicative` or `not_computed`). |

`GET /scans/{id}/ledger` (L): parameters `q` (seq, hashes, candidate, finding, provider, model,
task, outcome, block code), `outcome` (comma list), `provider`, `finding_id`, `offset`, `limit`,
`format=jsonl`. Response adds `total`, `offset`, `limit`, `bytes_total`; each entry adds `bytes`,
`lines_sent` and `policy_rule_key`. `format=jsonl` downloads the matching entries as JSON Lines
(metadata and hashes only, never payload text); the export is audited.

`GET /scans/{id}/ledger/{seq}` (O) adds `path`, `start_line`, `slice_lines[]`, `source_line`
(first taint step), `sink_line` (primary segment), `bytes`, `lines_sent`, `lines_original`,
`lines_total` (lines of the file) and `replacements` (counts by kind from `markup`).

`POST /scans/{id}/ledger/verify` (L) now also searches the payloads for the listed terms and adds
`hashes_ok`, `hashes_mismatched`, `payloads_missing`, `blocked`, `terms_checked`, `terms_found`
and `head_hash`.

`GET /scans/{id}/ledger-verification?format=json|txt` (L): the same verification as a download.

`GET /scans/{id}/privacy/attestation.json` (R, `report:read`): `{attestation, scan_id,
core_scan_id, levels_used, bytes_sent, lines_sent, ledger_head_hash, generated_at, digest,
digest_algorithm, signature, signature_note}`, built by
`codekavach.privacy.attestation.build_attestation`. `signature` is `null`: the server has no
signing key; the digest and the ledger head hash are the verifiable parts.
`attestation.pdf` returns the PDF report, which carries the attestation (needs the PDF renderer).

## Statistics

`GET /stats` (R) adds, over the latest completed scan of every project:

| Field | Source |
|-------|--------|
| `findings_by_status` | Counts by triage status. |
| `mttr_days`, `mttr_delta_days`, `mttr_samples` | Mean days from first seen to the first change to `fixed` in the triage history; the delta compares fixes in the last 30 days with the 30 before (`null` without both). |
| `trend[].info` | Already present: each trend point has all five severities. |
| `risk_matrix[]` | `{likelihood, impact, count}` with the finding's likelihood and impact levels (1 to 5). |
| `risk_matrix_bands[]` | `{likelihood, impact, count}` with the OWASP Risk Rating bands (`low`, `medium`, `high`). |
| `owasp_by_engine[]` | `{owasp, title, engine, count}`, every engine that reported the finding. |
| `top_cwes[]` | `{cwe, name, count}`, ten most frequent primary CWEs. |
| `scope.scan_ids` | The scans counted. |

`GET /providers/usage?month=YYYY-MM` (L): `{month, source, usage: [{provider, month, models,
requests, input_tokens, output_tokens, blocked, recorded, scans}]}` summed from the egress
ledgers of completed scans (cached per scan in its workspace). Token counts are the ledger's,
estimated where the provider reported none.

## Engines, inventory, health and invariants

`GET /engines` (R): `[{id, name, kind: builtin|external, installed, status, summary, version,
remediation, languages, licence, homepage, default_enabled}]`. Built-ins are always installed;
external engines carry the result of the `codekavach doctor` engine probe (version only, no scan,
no network): `installed`, `not_installed`, `missing` (enabled but absent), `disabled` or `error`.
Cached for 60 seconds.

`GET /projects/{id}/inventory` (R): `{project_id, scan_id, scanned_at, languages: [{language,
files, lines, bytes, generated, support, features}], totals}` from the ingest inventory of the
project's latest completed scan. `support` is `full` (taint, rules and slicing), `partial`
(parsed) or `basic` (secrets only); `features` lists each capability.

`GET /health` (public) adds `network`: `online` when the default provider is remote and enabled,
otherwise `offline`. It says whether a default scan would send payloads, not whether the host is
connected.

`GET /system/health` (A): `{status, totals, checks: [{name, status, summary, details}],
invariants, uptime_seconds}`. Checks: database, data directory, disk space, workers, vault
passphrase, dashboard build, Python, the doctor's report checks and every external engine.

`GET /privacy/invariants` (R): `{recorded, run_at, source, how_to_record, invariants: [{id,
title, status, passed, tests: {passed, failed, skipped, modules}, guard}]}`. The server does not
run tests. It reads the JUnit XML of a recorded run of the privacy suite at
`<data-dir>/invariants/junit.xml` (or `$CODEKAVACH_SERVER_INVARIANTS_REPORT`), written with

```bash
uv run pytest -m privacy --junitxml=<data-dir>/invariants/junit.xml
```

and maps each test module to its invariant. `status` is `passed`, `failed` or `not_recorded`.
`guard` adds the latest scan's evidence for I4 (blocked payloads, chain state) and I6 (listed
terms checked and found); a failing guard marks the invariant `failed`.

## Policy and budgets

`GET /policy/explain?path=&project_id=&provider=&language=&rule_id=&cwe=` (L): runs
`PolicyEngine` over the server's policy for one relative path. Response: `{path, level,
never_send, classifications, rule_key, policy_hash, decided_by, contributions: [{axis, key, level,
source, winner}], explanation, language, provider, provider_tier, in_inventory}`.

`PUT /policy {toml}` (A) saves (unchanged). `POST /policy/validate {toml, project_id?}` (R) is a
dry run: `{valid, schema, hash, errors: [{code, message, line}], notes, rules, matches:
{"path[0]": n, "classification[0]": n, "language[0]": n}, files_resolved, levels: {L3: n,
never_send: n}, provider_tier, preview: [{path, level, decided_by}]}` over the files of the
project's latest scan (first 200 in `preview`). Nothing is saved or sent.

`GET /policy/templates` (R): `[{id, name, kind: project|organisation, editor, toml, source}]`,
the built-in default and every `docs/examples/*policy*.toml`. `editor` is true when the document
loads as a project policy; the `policy.*.toml` examples are organisation policies.

`GET /privacy/budgets?scan_id=` (L): `{scan_id, bytes_sent, budgets: [{id, label, unit, limit,
used, usage_pct, source, note?}]}` for `privacy.egress.aggregation_budget_pct` (used: the
repository share disclosed), `lifetime_budget_pct` (used: `null`, the server keeps no cross-scan
exposure account), `max_payload_bytes`, `rate_per_minute`, `llm.budget.max_requests` and
`max_total_input_tokens` (used: the scan's requests and tokens). A `null` limit means unset.

## Providers

`GET /providers` (R) adds per provider: `wire` (request protocol, for example `OpenAI Responses
API`), `endpoint` (base URL), `preset`, and `key_ref_status: [{ref, state, present}]` where
`state` is `set`, `not-set`, `backend-unavailable` or `error`; only references and their state
are returned, not key values.

## Evaluation

`GET /evaluation` (R): `{available, sample: false, benchmarks: [{dataset, arm, level, provider,
findings, precision, recall, f1, f1_ci, tp, fp, fn, skipped_reason}], frontier: [{level,
privacy_score, leakage_score, f1}], attacks: [{experiment, description, by_level}], zero_leak,
ablations, detection, leakage, job}` from the newest `results.json` of each kind below
`<data-dir>/evaluation` (written by a run, or by `codekavach eval ... --out` into that folder).

`POST /evaluation/run {levels?, limit?}` (A, 202): starts `codekavach eval detection` and then
`codekavach eval leakage` on the bundled sample with the mock provider, as child processes with
their own home directory, one run at a time (`409 evaluation_running`). Returns the job
`{id, status, steps: [{kind, status, exit_code?, error?}], ...}`; `GET /evaluation/runs/{id}` (R)
polls it. Nothing is sent to a model.

## Administration

| Route | Role | Purpose |
|-------|------|---------|
| `PUT /users/{id}/role {role}` | A | Change a role; the user's sessions and tokens are revoked. |
| `POST /users/{id}/revoke?disable=true` | A | Revoke every session and token and disable the account. |
| `GET /tokens?include_revoked=` | A | Every personal token: `{id, name, prefix, user_id, username, created_at, expires_at, last_used_at, revoked}`. |
| `DELETE /tokens/{id}` | A | Revoke any token. |
| `GET /audit?limit=&offset=&actor=&action=&outcome=&resource=` | U | Adds `total`, `offset`, `limit`; `action` matches a prefix (`user.`). |
| `GET /vault` | A | `{vaults: [{scan_id, project_id, format_version, key_source, records, created_at, last_write_at, rotated_at, rotations, size_bytes}], count, records, retention_days, key_source, note}` from `vault_info` with the key probe off: header, row counts and file times only (I3). |
| `GET /retention` | A | `{scans, oldest_scan_at, newest_scan_at, scans_bytes, uploads_bytes, database_bytes, vault_retention_days, ledger_payloads, automatic_purge: false, how_to_purge}`. |

Personal API tokens start with `ck_pat_`, are shown once, are stored as SHA-256 and work as bearer
tokens with the owner's role.

## The caller's own settings

| Route | Purpose |
|-------|---------|
| `GET /me`, `PATCH /me {display_name?, email?}` | Profile with preferences; change name or e-mail (audited). |
| `GET/PATCH /me/preferences` | `{theme, density, reduce_motion, language, time_zone, date_format}`; unknown keys are refused, the time zone must exist. |
| `GET/PATCH /me/notifications` | `{events: {scan_completed, scan_failed, finding_assigned, critical_finding, ledger_verification_failed: {in_app, email}}, delivery}`. Stored only: the server sends no e-mail. |
| `GET/POST /me/tokens`, `DELETE /me/tokens/{id}` | Personal tokens: `POST {name, expires_in_days?}` (default 90, at most 730; 20 active per user) returns the value once in `token`. |
| `GET /notifications?limit=`, `POST /notifications/read` | Feed `{items: [{id, event, at, title, link, read}], unread}` built from finished scans and findings assigned to the caller; `read` compares with the stored read marker. |

## Not implemented

These answer `501` with `{"error": {"code": "not_implemented"}}`:

- `GET /orgs`: organisations (tenants). The server has one organisation.
- `GET /auth/sso`: SAML or OIDC sign-in. Accounts are local.

Not provided at all (no route): an anonymous demo session (the demo signs in with a local
account), finding statuses beyond the five triage statuses ("In progress", "Triage"), SARIF
import, a payload preview at other privacy levels, report history and the report builder, GitHub
integration status and switches, VS Code and MCP status, adding a provider from the dashboard,
provider auto-selection rules, conformance results and rate cards, vault rotation and purge from
the dashboard, and `llm.temperature`.
