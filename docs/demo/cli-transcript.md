# Terminal demo transcript (mock provider)

A recorded run of [`scripts/demo-cli.sh`](../../scripts/demo-cli.sh) on the mock provider, all twelve steps passing. It holds no key and no code beyond what the synthetic `fixtures/kavachbank` project shows: the payload previews are the pseudonymised slices the tool prepares for a model.

Reproduce it:

```console
$ NO_COLOR=1 scripts/demo-cli.sh --auto --provider mock --out /tmp/codekavach-demo
```

Scan ids, timings, file sizes and counts differ from run to run and between versions of the tool. A full run takes a few minutes on a busy machine.

```text
   ____          _      _  __                _
  / ___|___   __| | ___| |/ /__ ___   ____ _| |__
 | |   / _ \ / _` |/ _ \ ' // _` \ \ / / _` | '_ \
 | |__| (_) | (_| |  __/ . \ (_| |\ V / (_| | | | |
  \____\___/ \__,_|\___|_|\_\__,_| \_/ \__,_|_| |_|
  privacy-preserving, LLM-assisted secure code review   (terminal walkthrough)
  provider: mock
  the mock answers on this machine: no key, no network.

== Step 1: Version ==
Start with what is installed.
$ codekavach --version
codekavach 0.1.0.dev0
  proves: the CLI is installed and versioned

== Step 2: Doctor: is this machine ready? ==
One command checks runtime, parsers, storage, engines and providers.
$ codekavach doctor
PASS  runtime:python              3.12.16
PASS  runtime:package             0.1.0.dev0
PASS  runtime:platform            Linux x86_64, stdout utf-8
PASS  config:valid                profile none, 0 warning(s)
PASS  storage:state-dir           does not exist yet and can be created
SKIP  storage:artefacts           not available in this build
PASS  storage:database            no database yet; the first scan creates it
PASS  parsing:grammar:python      grammar loads, version 0.9.0
PASS  parsing:grammar:javascript  grammar loads, version 0.9.0
PASS  parsing:grammar:typescript  grammar loads, version 0.9.0
PASS  parsing:grammar:java        grammar loads, version 0.9.0
PASS  parsing:grammar:go          grammar loads, version 0.9.0
WARN  privacy:ner-model           name recognition is off: library missing
WARN  secrets:keyring             the keyring backend is insecure and is refused
PASS  plugins:load                every allowed plugin loads
PASS  plugins:pipeline            13 stage(s) resolve into a valid order
SKIP  engine:bandit               not installed
SKIP  engine:brakeman             not installed
SKIP  engine:cppcheck             not installed
SKIP  engine:detekt               not installed
SKIP  engine:devskim              not installed
SKIP  engine:eslint-security      not installed
SKIP  engine:flawfinder           not installed
SKIP  engine:gosec                not installed
SKIP  engine:njsscan              not installed
SKIP  engine:opengrep             not installed
SKIP  engine:psalm-taint          not installed
SKIP  engine:semgrep-ce           not installed
PASS  provider:mock:configured    kind mock
SKIP  provider:mock:reachable     use --probe-providers
hint  privacy:ner-model           optional: install spaCy and a model such as en_core_web_sm offline
hint  secrets:keyring             install a keyring backend or use passphrase mode
14 passed, 2 warnings, 0 failed, 14 skipped
  proves: every prerequisite is verified up front; optional parts are warnings with an install hint, never silent gaps

== Step 3: Providers: who could review the code ==
Each provider has a locality and a minimum privacy level.
$ codekavach providers list
   id    kind  model  enabled  locality  host  tier   min level  credential    adapter
*  mock  mock  -      yes      local     -     local  L1         not-required  available
default: mock (llm.default_provider = "auto")
  proves: providers are an explicit, inspectable list; local ones never leave the machine

== Step 4: Providers: does the chosen one answer? ==
A constant probe; no code is involved.
$ codekavach providers test mock
provider mock (mock, mock-1): OK in 899 ms
local test double: no network request was made
recorded in ledger as seq 1
  proves: the mock provider answers before any code is prepared

== Step 5: Scan the sample bank ==
A synthetic bank with planted vulnerabilities and secrets. Exit 1 only means findings at or above the threshold.
$ codekavach scan . --provider mock
[ingest] started
[ingest] 29/29
[ingest] finished 0.1s
[parse] started
[analyse-iac] started
[analyse-engines] started
[analyse-secrets] started
[analyse-sca] started
[analyse-secrets] 29/29
[analyse-iac] finished 0.6s
[analyse-sca] finished 0.7s
[analyse-secrets] finished 0.8s
[parse] 29/29
[parse] finished 1.8s
[analyse-engines] finished 1.9s
[analyse-rules] started
[analyse-taint] started
[analyse-taint] 18/18
[analyse-taint] finished 3.0s
[analyse-rules] 18/18
[analyse-rules] finished 3.9s
[aggregate] started
[aggregate] finished 0.3s
[privacy-prepare] started
[privacy-prepare] 50/59
[privacy-prepare] finished 6.4s
[llm-review] started
[llm-review] 16/16
[llm-review] finished 7.7s
[restore] started
[restore] finished 0.8s
[rate] started
[rate] finished 1.9s
warning[egress_blocked]: the egress guard blocked 2 payload(s); those candidates
are reported from deterministic evidence
         Scan
scan_01M78KC0DK409S6AJJ
       8QDRRMF1
┌──────────┬──────────┐
│ Severity │ Findings │
├──────────┼──────────┤
│ critical │       15 │
│ high     │       27 │
│ medium   │       12 │
│ low      │        5 │
│ info     │        0 │
└──────────┴──────────┘
findings: 59
threshold: high; 42 finding(s) at or above it: failing (exit 1)
LLM provider: mock (local), level L3, payloads recorded: 40, blocked by guard: 2
provider is local/mock: payloads were recorded but not transmitted
next: codekavach privacy inspect --scan scan_01M78KC0DK409S6AJJ8QDRRMF1
next: codekavach report --scan scan_01M78KC0DK409S6AJJ8QDRRMF1
error[threshold_exceeded]: 42 finding(s) at or above high
  proves: engines and the model find the planted issues; the summary names the provider and what was recorded

== Step 6: Privacy: what would the model see? ==
The exact payloads prepared for the provider.
$ codekavach privacy inspect . --list
┌────────────────────────────────┬────┬────┬────┬────┬────┬────┬────┬─────┬────┐
│                                │    │    │    │    │    │    │ Ps │     │    │
│                                │    │    │ Lo │    │ Pa │    │ eu │ Pla │    │
│                                │    │    │ ca │ Le │ yl │ To │ do │ ceh │    │
│                                │ Ru │ CW │ ti │ ve │ oa │ ke │ ny │ old │ Led│
│Candidate                       │ le │ E  │ on │ l  │ d  │ ns │ ms │ ers │ ger│
├────────────────────────────────┼────┼────┼────┼────┼────┼────┼────┼─────┼────┤
│cand_01M78KC6AH89G8W60QD4MBQGRP │ py │ CW │ se │ L3 │ 2a │ 70 │ 4  │     │ sen│
│                                │ .c │ E- │ rv │    │ 8f │    │    │     │ t  │
│                                │ om │ 78 │ ic │    │ 8c │    │    │     │    │
│                                │ ma │    │ es │    │ 4f │    │    │     │    │
│                                │ nd │    │ /a │    │ bc │    │    │     │    │
│                                │ -i │    │ pi │    │ b6 │    │    │     │    │
│                                │ nj │    │ /r │    │    │    │    │     │    │
│                                │ ec │    │ ep │    │    │    │    │     │    │
│                                │ ti │    │ or │    │    │    │    │     │    │
│                                │ on │    │ ts │    │    │    │    │     │    │
│                                │    │    │ .p │    │    │    │    │     │    │
│                                │    │    │ y: │    │    │    │    │     │    │
│                                │    │    │ 9  │    │    │    │    │     │    │
│cand_01M78KC6WMMZ668DAH1TFK2PGB │ ta │ CW │ se │ L3 │ 18 │ 66 │ 5  │     │ sen│
│                                │ in │ E- │ rv │    │ 96 │    │    │     │ t  │
│                                │ t. │ 89 │ ic │    │ 6e │    │    │     │    │
│                                │ ht │    │ es │    │ 0a │    │    │     │    │
│                                │ tp │    │ /a │    │ 90 │    │    │     │    │
│                                │ _p │    │ pi │    │ c1 │    │    │     │    │
│                                │ ar │    │ /a │    │    │    │    │     │    │
│                                │ am │    │ cc │    │    │    │    │     │    │
│                                │ .s │    │ ou │    │    │    │    │     │    │
│                                │ ql │    │ nt │    │    │    │    │     │    │
│                                │    │    │ s. │    │    │    │    │     │    │
│                                │    │    │ py │    │    │    │    │     │    │
│                                │    │    │ :1 │    │    │    │    │     │    │
│                                │    │    │ 1  │    │    │    │    │     │    │
│cand_01M78KC5JYW9E95EZCH8VES7HF │ py │ CW │ se │ L3 │ 8f │ 17 │ 17 │     │ blo│
│                                │ .i │ E- │ rv │    │ 4d │ 2  │    │     │ cke│
│                                │ ns │ 63 │ ic │    │ 52 │    │    │     │ d: │
│                                │ ec │ 9  │ es │    │ f3 │    │    │     │ vau│
│                                │ ur │    │ /a │    │ 2e │    │    │     │ lt_│
│                                │ e- │    │ pi │    │ fc │    │    │     │ ide│
│                                │ di │    │ /h │    │    │    │    │     │ nti│
│                                │ re │    │ an │    │    │    │    │     │ fie│
│                                │ ct │    │ dl │    │    │    │    │     │ r  │
│                                │ -o │    │ er │    │    │    │    │     │    │
│                                │ bj │    │ s. │    │    │    │    │     │    │
│                                │ ec │    │ py │    │    │    │    │     │    │
│                                │ t- │    │ :3 │    │    │    │    │     │    │
│                                │ re │    │ 4  │    │    │    │    │     │    │
│                                │ fe │    │    │    │    │    │    │     │    │
│                                │ re │    │    │    │    │    │    │     │    │
│                                │ nc │    │    │    │    │    │    │     │    │
│                                │ e  │    │    │    │    │    │    │     │    │
│cand_01M78KC5KNZE0JR8M85D6ZRFNF │ py │ CW │ se │ L3 │ 7c │ 85 │ 10 │     │ sen│
│                                │ .m │ E- │ rv │    │ 2e │    │    │     │ t  │
│                                │ is │ 86 │ ic │    │ d2 │    │    │     │    │
│                                │ si │ 2  │ es │    │ 2a │    │    │     │    │
│                                │ ng │    │ /a │    │ fe │    │    │     │    │
│                                │ -a │    │ pi │    │ d9 │    │    │     │    │
│                                │ ut │    │ /h │    │    │    │    │     │    │
│                                │ ho │    │ an │    │    │    │    │     │    │
│                                │ ri │    │ dl │    │    │    │    │     │    │
│                                │ za │    │ er │    │    │    │    │     │    │
│                                │ ti │    │ s. │    │    │    │    │     │    │
│                                │ on │    │ py │    │    │    │    │     │    │
│                                │    │    │ :3 │    │    │    │    │     │    │
│                                │    │    │ 9  │    │    │    │    │     │    │
│cand_01M78KC6CK6C22EVCM2GW3F778 │ py │ CW │ se │ L3 │ 39 │ 52 │ 3  │     │ sen│
│                                │ .w │ E- │ rv │    │ 47 │    │    │     │ t  │
│                                │ ea │ 32 │ ic │    │ 72 │    │    │     │    │
│                                │ k- │ 7  │ es │    │ a2 │    │    │     │    │
│                                │ pa │    │ /a │    │ 64 │    │    │     │    │
│                                │ ss │    │ pi │    │ 09 │    │    │     │    │
│                                │ wo │    │ /s │    │    │    │    │     │    │
│                                │ rd │    │ ec │    │    │    │    │     │    │
│                                │ -h │    │ ur │    │    │    │    │     │    │
│                                │ as │    │ it │    │    │    │    │     │    │
│                                │ h  │    │ y. │    │    │    │    │     │    │
│                                │    │    │ py │    │    │    │    │     │    │
│                                │    │    │ :1 │    │    │    │    │     │    │
│                                │    │    │ 5  │    │    │    │    │     │    │
└────────────────────────────────┴────┴────┴────┴────┴────┴────┴────┴─────┴────┘
11 more payload(s); use --limit 0 to show all
  proves: a payload is a slice with pseudonyms, not the file

== Step 7: Privacy: side by side ==
Original code left, exact payload right.
$ codekavach privacy inspect . --html /tmp/codekavach-demo/inspect.html
candidate cand_01M78KC6AH89G8W60QD4MBQGRP rule py.command-injection CWE-78  services/api/reports.py:9  level L3
payload 2a8f8c4fbcb6  ~70 tokens  pseudonyms 4  placeholders none  ledger: sent
Original (stays on this machine)
services/api/reports.py
   4 import subprocess
   5
   6
   7 def archive_statements(folder, archive_name):
   8     """Pack a folder of statements into an archive for download."""
   9     subprocess.run(f"zip -r {archive_name} {folder}", shell=True,
     check=True)
  10     return archive_name
Payload (what the provider receives)
  1 # codekavach payload L3
  2 # file_9
  3 import subprocess
  4
  5
  6 def fn_7(param_4, param_5):
  7     """xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"""
  8     subprocess.run(f"zip -x {param_5} {param_4}", shell=True, check=True)
  9     return param_5

candidate cand_01M78KC6WMMZ668DAH1TFK2PGB rule taint.http_param.sql CWE-89  services/api/accounts.py:11  level L3
payload 18966e0a90c1  ~66 tokens  pseudonyms 5  placeholders none  ledger: sent
Original (stays on this machine)
services/api/accounts.py
   8 def find_premium_account(conn, account_id):
   9     """The premium-tier account with this id."""
  10     cur = conn.cursor()
  11     cur.execute("SELECT * FROM premium_accounts WHERE id = '%s'" %
     account_id)
  12     return cur.fetchone()
Payload (what the provider receives)
  1 # codekavach payload L3
  2 # file_1
  3 def fn_1(param_2, param_1):
  4     """xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"""
  5     var_1 = param_2.cursor()
  6     var_1.execute("SELECT * FROM tbl_2 WHERE id = '%s'" % param_1)
  7     return var_1.fetchone()

candidate cand_01M78KC5JYW9E95EZCH8VES7HF rule py.insecure-direct-object-reference CWE-639  services/api/handlers.py:34  level L3
payload 8f4d52f32efc  ~172 tokens  pseudonyms 17  placeholders none  ledger: blocked: vault_identifier
Original (stays on this machine)
services/api/handlers.py
  5 from flask import Flask, abort, g, jsonify, request
  6
  7 import accounts
  8 import db
services/api/handlers.py
  12 import serialisation
  13 from security import require_auth
services/api/handlers.py
  30 @app.route("/api/accounts/<account_id>/statement")
  31 @require_auth
  32 def account_statement(account_id):
  33     conn = db.connect()
  34     statement = accounts.get_statement(conn, account_id)
  35     return jsonify(serialisation.dump_statement(statement))
Payload (what the provider receives)
   1 # codekavach payload L3
   2 # file_2
   3 from flask import Flask, abort, g, jsonify, request
   4
   5 import mod_3
   6 import mod_1
   7 # ... elided ...
   8 import mod_5
   9 from mod_2 import mod_4
  10 # ... elided ...
  11 @app.route("/file_3/file_4/file_5/file_6")
  12 @mod_4
  13 def fn_2(param_1):
  14     var_3 = mod_1.connect()
  15     var_4 = mod_3.fn_4(var_3, param_1)
  16     return jsonify(mod_5.fn_3(var_4))
  17
  18 # unresolved
  19 def fn_3(*args, **param_3): ...
  20 # effects unknown; derived: syntactic
  21 # unresolved
  22 def fn_4(*args, **param_3): ...
  23 # effects unknown; derived: syntactic

candidate cand_01M78KC5KNZE0JR8M85D6ZRFNF rule py.missing-authorization CWE-862  services/api/handlers.py:39  level L3
payload 7c2ed22afed9  ~85 tokens  pseudonyms 10  placeholders none  ledger: sent
Original (stays on this machine)
services/api/handlers.py
  5 from flask import Flask, abort, g, jsonify, request
  6
  7 import accounts
  8 import db
services/api/handlers.py
  38 @app.route("/api/accounts/<account_id>/close", methods=["POST"])
  39 def close_account(account_id):
  40     conn = db.connect()
  41     accounts.close(conn, account_id)
  42     return jsonify(status="closed")
Payload (what the provider receives)
   1 # codekavach payload L3
   2 # file_2
   3 from flask import Flask, abort, g, jsonify, request
   4
   5 import mod_3
   6 import mod_1
   7 # ... elided ...
   8 @app.route("/file_3/file_4/file_5/file_7", methods=["POST"])
   9 def fn_5(param_1):
  10     var_3 = mod_1.connect()
  11     mod_3.close(var_3, param_1)
  12     return jsonify(status="xxxxxx")

candidate cand_01M78KC6CK6C22EVCM2GW3F778 rule py.weak-password-hash CWE-327  services/api/security.py:15  level L3
payload 394772a26409  ~52 tokens  pseudonyms 3  placeholders none  ledger: sent
Original (stays on this machine)
services/api/security.py
  3 import hashlib
services/api/security.py
  13 def hash_password(password):
  14     """The stored form of a customer password."""
  15     return hashlib.md5(password.encode("utf-8")).hexdigest()
Payload (what the provider receives)
  1 # codekavach payload L3
  2 # file_10
  3 import hashlib
  4 # ... elided ...
  5 def fn_8(param_6):
  6     """xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"""
  7     return hashlib.md5(param_6.encode("xxx-x")).hexdigest()

11 more payload(s); use --limit 0 to show all
  proves: secrets are typed placeholders and identifiers are renamed, on one page that loads nothing from the network

== Step 8: Privacy: audit the ledger ==
Hash chain, payload hashes, and a search for every planted term in every payload.
$ codekavach privacy ledger verify . --check-terms <repo>/fixtures/kavachbank/ground-truth/terms.txt --include-blocked
chain intact: 84 records
payloads: 15 checked, 0 mismatches
terms: 31 checked, 0 skipped (too short), 0 occurrence(s)
verbatim check only; structural leakage is measured by 'codekavach eval leakage'
  proves: no listed secret or domain term occurs verbatim in anything prepared for a model, and the log cannot be edited unnoticed

== Step 9: Privacy: explain a decision ==
Why was a value redacted or renamed?
$ codekavach privacy explain services/api/interest_engine.py
services/api/interest_engine.py: effective level L3 (provider tier local)
decided by base: privacy.level and privacy.min_level
 * base           L3         privacy.level and privacy.min_level
   provider_tier  L1         trust tier local
policy hash da6286396643354a  rule key base:
  proves: the privacy level of any file is explained axis by axis (path, language, rule, classification)

== Step 10: Reports in every format ==
One scan, rendered for different readers.
$ codekavach report . --format html,pdf,docx --output-dir /tmp/codekavach-demo/reports
scan scan_01M78KC0DK409S6AJJ8QDRRMF1 (2026-11-12 19:22 UTC, 59 findings)
┌───────┬──────────────────────────────────────────────────────┬───────┐
│format │ path                                                 │ size  │
├───────┼──────────────────────────────────────────────────────┼───────┤
│html   │ /tmp/codekavach-demo/reports/report.html │ 560 kB│
│pdf    │ /tmp/codekavach-demo/reports/report.pdf  │ 979 kB│
│docx   │ /tmp/codekavach-demo/reports/report.docx │ 99 kB │
└───────┴──────────────────────────────────────────────────────┴───────┘
  proves: one scan yields html,pdf,docx (SARIF is for code scanning, XLSX for triage, DOCX for the client)
    manifest.json
    report.docx
    report.html
    report.pdf
    SHA256SUMS

== Step 11: Send findings to GitHub (dry run) ==
Issues and a project board; here only what would change.
$ codekavach sync github . --repo example-org/kavachbank --dry-run
example-org/kavachbank: 50 to create, 0 to update, 0 to close (dry run: nothing
was changed)
┌───────┬──────────┬───────┬───────────────────────────────────────────────────┐
│action │ severity │ issue │ title                                             │
├───────┼──────────┼───────┼───────────────────────────────────────────────────┤
│create │ critical │ -     │ [CRITICAL] A pull_request_target workflow checks  │
│       │          │       │ out the pull request head, running untrusted code │
│       │          │       │ with repository secrets and a write token.        │
│create │ critical │ -     │ [CRITICAL] Container 'api' is privileged.         │
│create │ critical │ -     │ [CRITICAL] Data from a http_param source reaches a│
│       │          │       │ sql sink (cur.execute)                            │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ connection_string (masked preview po****** (51    │
│       │          │       │ chars), entropy 4.91 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ aws_access_key (masked preview AK****** (20       │
│       │          │       │ chars), entropy 3.68 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ private_key_block (masked preview --****** (313   │
│       │          │       │ chars), entropy 5.97 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ razorpay_key_id (masked preview rz****** (23      │
│       │          │       │ chars), entropy 4.26 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ generic_credential (masked preview ad****** (12   │
│       │          │       │ chars), entropy 3.08 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ aws_secret_key (masked preview wJ****** (40       │
│       │          │       │ chars), entropy 4.66 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ razorpay_key_secret (masked preview ab****** (24  │
│       │          │       │ chars), entropy 4.58 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ generic_credential (masked preview hu****** (14   │
│       │          │       │ chars), entropy 2.81 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] A shell command is built from variable │
│       │          │       │ parts that are not quoted.                        │
│create │ critical │ -     │ [CRITICAL] Data is deserialised with a loader that│
│       │          │       │ can construct arbitrary objects.                  │
│create │ critical │ -     │ [CRITICAL] Hard-coded credential of type          │
│       │          │       │ razorpay_key_secret (masked preview ab****** (24  │
│       │          │       │ chars), entropy 4.58 bits/char).                  │
│create │ critical │ -     │ [CRITICAL] Vulnerable dependency: PyYAML 5.3      │
│       │          │       │ (CVE-2020-14343)                                  │
│create │ high     │ -     │ [HIGH] A run step in job 'build' interpolates     │
│       │          │       │ attacker-controlled event data into a shell       │
│       │          │       │ script; pass it through an environment variable   │
│       │          │       │ instead.                                          │
│create │ high     │ -     │ [HIGH] ENV KB_DB_PASSWORD bakes a credential into │
│       │          │       │ the image layers; use a build secret or runtime   │
│       │          │       │ injection.                                        │
│create │ high     │ -     │ [HIGH] Service 'api' runs privileged, giving it   │
│       │          │       │ nearly full host access.                          │
│create │ high     │ -     │ [HIGH] Service 'api' mounts the Docker socket,    │
│       │          │       │ which is root on the host.                        │
│create │ high     │ -     │ [HIGH] Service 'api' sets KB_ADMIN_PASSWORD to a  │
│       │          │       │ literal in the compose file; use an env file or   │
│       │          │       │ secret store.                                     │
│create │ high     │ -     │ [HIGH] Pod shares the host network namespace.     │
│create │ high     │ -     │ [HIGH] Pod mounts a hostPath volume, exposing the │
│       │          │       │ node filesystem.                                  │
│create │ high     │ -     │ [HIGH] S3 bucket 'statements' uses a public ACL.  │
│create │ high     │ -     │ [HIGH] Security group 'admin' allows ingress from │
│       │          │       │ the whole internet on an administrative or        │
│       │          │       │ database port.                                    │
│create │ high     │ -     │ [HIGH] Database 'ledger' is publicly accessible.  │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: Flask 2.2.3         │
│       │          │       │ (CVE-2023-30861)                                  │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: requests 2.19.1     │
│       │          │       │ (CVE-2018-18074, CVE-2023-32681)                  │
│create │ high     │ -     │ [HIGH] TLS certificate verification is disabled,  │
│       │          │       │ enabling man-in-the-middle attacks.               │
│create │ high     │ -     │ [HIGH] A deprecated protocol version (SSLv2/3, TLS│
│       │          │       │ 1.0 or 1.1) is allowed.                           │
│create │ high     │ -     │ [HIGH] Data from a http_param source reaches a    │
│       │          │       │ path sink (fs.createReadStream)                   │
│create │ high     │ -     │ [HIGH] A record is fetched by an identifier from  │
│       │          │       │ the caller with no ownership check.               │
│create │ high     │ -     │ [HIGH] An account-scoped route has no             │
│       │          │       │ authentication or authorisation check.            │
│create │ high     │ -     │ [HIGH] A password is hashed with an algorithm that│
│       │          │       │ is broken or far too fast.                        │
│create │ high     │ -     │ [HIGH] A block cipher is given a fixed            │
│       │          │       │ initialisation vector instead of a random one.    │
│create │ high     │ -     │ [HIGH] Data from a http_param source reaches a    │
│       │          │       │ path sink (fs.createReadStream)                   │
│create │ high     │ -     │ [HIGH] Handler takes an object id from the path:  │
│       │          │       │ worth checking the caller owns it                 │
│create │ high     │ -     │ [HIGH] Handler takes an object id from the path:  │
│       │          │       │ worth checking the caller owns it                 │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: Jinja2 2.10         │
│       │          │       │ (CVE-2019-10906, CVE-2020-28493, CVE-2024-22195)  │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: lodash 4.17.15      │
│       │          │       │ (CVE-2021-23337, CVE-2020-8203, CVE-2020-28500)   │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: axios 0.21.0        │
│       │          │       │ (CVE-2021-3749, CVE-2020-28168)                   │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: jsonwebtoken 8.5.1  │
│       │          │       │ (CVE-2022-23529)                                  │
│create │ high     │ -     │ [HIGH] Data from a http_param source reaches a    │
│       │          │       │ http sink (fetch)                                 │
│create │ medium   │ -     │ [MEDIUM] The workflow grants write-all permissions│
│       │          │       │ to the token.                                     │
│create │ medium   │ -     │ [MEDIUM] The container runs as root (no non-root  │
│       │          │       │ USER in the final stage).                         │
│create │ medium   │ -     │ [MEDIUM] ADD fetches a remote URL with no         │
│       │          │       │ integrity check; use COPY plus a verified         │
│       │          │       │ download.                                         │
│create │ medium   │ -     │ [MEDIUM] Service 'api' shares the host network    │
│       │          │       │ namespace.                                        │
│create │ medium   │ -     │ [MEDIUM] Pod security context runs as UID 0.      │
│create │ medium   │ -     │ [MEDIUM] Database 'ledger' storage is not         │
│       │          │       │ encrypted.                                        │
│create │ medium   │ -     │ [MEDIUM] CORS allows every origin ('*'); any      │
│       │          │       │ website can call this API from a user's browser.  │
│create │ medium   │ -     │ [MEDIUM] Vulnerable dependency: express 4.16.0    │
│       │          │       │ (CVE-2024-29041, CVE-2024-43796)                  │
│skip   │ medium   │ -     │ [MEDIUM] Data from a http_param source reaches a  │
│       │          │       │ html sink (res.send)                              │
│skip   │ medium   │ -     │ [MEDIUM] RUN pipes a download straight into a     │
│       │          │       │ shell without integrity verification.             │
│skip   │ medium   │ -     │ [MEDIUM] Debug mode is enabled; it exposes stack  │
│       │          │       │ traces and interactive consoles in production.    │
│skip   │ medium   │ -     │ [MEDIUM] Data from a http_param source reaches a  │
│       │          │       │ html sink (res.send)                              │
└───────┴──────────┴───────┴───────────────────────────────────────────────────┘
note: no token: assuming the repository has no CodeKavach issues yet
  proves: findings reach the client's tracker without code leaving, and dry-run changes nothing

== Step 12: Leakage: what could a curious provider learn? ==
Beyond verbatim terms: attack the payloads and measure.
$ codekavach eval leakage --level L3
dataset    KavachBank
zero_leak  True
frontier   [{"level": "L3", "privacy_score": 89.1, "leakage_score": 10.9, "f1":
           0.8696}]
ablations  [{"ablation": "default", "leakage_score": 10.9, "canary_passed":
           true, "f1": 0.8696}, {"ablation": "sink-window-slices",
           "leakage_score": 10.8, "canary_passed": true, "f1": 0.8696},
           {"ablation": "per-request-pseudonyms", "leakage_score": 10.9,
           "canary_passed": true, "f1": 0.8696}, {"ablation": "role-hints",
           "leakage_score": 10.9, "canary_passed": true, "f1": 0.8696}]
files      []
  proves: privacy is measured, not asserted

== Done: 12 ok, 0 skipped (not in this build), 0 failed ==
  files: /tmp/codekavach-demo
```
