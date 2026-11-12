# Terminal demo transcript (mock provider)

A recorded run of [`scripts/demo-cli.sh`](../../scripts/demo-cli.sh) on the mock provider. It holds no key and no code beyond what the synthetic `fixtures/kavachbank` project shows: the payload previews are the pseudonymised slices the tool prepares for a model.

Reproduce it:

```console
$ NO_COLOR=1 scripts/demo-cli.sh --auto --provider mock --out /tmp/codekavach-demo
```

Scan ids, timings, file sizes and counts differ from run to run and between versions of the tool. The two `skipped` steps (`providers test mock`, `eval leakage`) were not in the build this was recorded on; the script marks them instead of failing and runs them when they land. Re-record this file when they do.

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
PASS  plugins:pipeline            11 stage(s) resolve into a valid order
SKIP  engine:bandit               not installed
SKIP  engine:eslint-security      not installed
SKIP  engine:opengrep             not installed
PASS  provider:mock:configured    kind mock
SKIP  provider:mock:reachable     use --probe-providers
hint  privacy:ner-model           optional: install spaCy and a model such as en_core_web_sm offline
hint  secrets:keyring             install a keyring backend or use passphrase mode
14 passed, 2 warnings, 0 failed, 5 skipped
  proves: every prerequisite is verified up front; optional parts are warnings with an install hint, never silent gaps

== Step 3: Providers: who could review the code ==
Each provider has a locality and a minimum privacy level.
$ codekavach providers list
warning[auto_resolution_unavailable]: llm.default_provider is auto and provider
selection is not in this build; mock is used
   id    kind  model  enabled  locality  host  tier   min level  credential    adapter
*  mock  mock  -      yes      local     -     local  L1         not-required  missing
default: mock (llm.default_provider = "auto")
  proves: providers are an explicit, inspectable list; local ones never leave the machine

== Step 4: Providers: does the chosen one answer? ==
A constant probe; no code is involved.
$ codekavach providers test mock
error[backend_unavailable]: no adapter for provider kind 'mock' is available in
this build
hint: delivered by epic E22
  skipped: not in this build yet (exit 2)

== Step 5: Scan the sample bank ==
A synthetic bank with planted vulnerabilities and secrets. Exit 1 only means findings at or above the threshold.
$ codekavach scan . --provider mock
[ingest] started
[ingest] 34/34
[ingest] finished 0.3s
[parse] started
[analyse-engines] started
[analyse-sca] started
[analyse-sca] finished 1.0s
[parse] 34/34
[parse] finished 3.1s
[analyse-engines] finished 3.5s
[analyse-taint] started
[analyse-rules] started
[analyse-taint] 18/18
[analyse-taint] finished 4.9s
[analyse-rules] 18/18
[analyse-rules] finished 6.1s
[aggregate] started
[aggregate] finished 0.3s
[privacy-prepare] started
[privacy-prepare] 23/23
[privacy-prepare] finished 2.7s
[llm-review] started
[llm-review] 15/15
[llm-review] finished 6.1s
[restore] started
[restore] finished 1.6s
[rate] started
[rate] finished 0.3s
warning[egress_blocked]: the egress guard blocked 1 payload(s); those candidates
are reported from deterministic evidence
         Scan
scan_01M78HJVWSFPEWP5QZ
       G30WERB0
┌──────────┬──────────┐
│ Severity │ Findings │
├──────────┼──────────┤
│ critical │        2 │
│ high     │       13 │
│ medium   │        8 │
│ low      │        0 │
│ info     │        0 │
└──────────┴──────────┘
findings: 23
threshold: high; 15 finding(s) at or above it: failing (exit 1)
LLM provider: mock (local), level L3, payloads recorded: 14, blocked by guard: 1
provider is local/mock: payloads were recorded but not transmitted
next: codekavach privacy inspect --scan scan_01M78HJVWSFPEWP5QZG30WERB0
next: codekavach report --scan scan_01M78HJVWSFPEWP5QZG30WERB0
error[threshold_exceeded]: 15 finding(s) at or above high
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
│cand_01M78HK85ZN5V14VHGGXRYV0VB │ py │ CW │ se │ L3 │ f5 │ 70 │ 4  │     │ sen│
│                                │ .c │ E- │ rv │    │ 53 │    │    │     │ t  │
│                                │ om │ 78 │ ic │    │ d9 │    │    │     │    │
│                                │ ma │    │ es │    │ 1f │    │    │     │    │
│                                │ nd │    │ /a │    │ 40 │    │    │     │    │
│                                │ -i │    │ pi │    │ 0d │    │    │     │    │
│                                │ nj │    │ /r │    │    │    │    │     │    │
│                                │ ec │    │ ep │    │    │    │    │     │    │
│                                │ ti │    │ or │    │    │    │    │     │    │
│                                │ on │    │ ts │    │    │    │    │     │    │
│                                │    │    │ .p │    │    │    │    │     │    │
│                                │    │    │ y: │    │    │    │    │     │    │
│                                │    │    │ 9  │    │    │    │    │     │    │
│cand_01M78HK5JZM3XJ3NR7E626339T │ py │ CW │ se │ L3 │ 18 │ 66 │ 5  │     │ sen│
│                                │ .s │ E- │ rv │    │ 96 │    │    │     │ t  │
│                                │ ql │ 89 │ ic │    │ 6e │    │    │     │    │
│                                │ -i │    │ es │    │ 0a │    │    │     │    │
│                                │ nj │    │ /a │    │ 90 │    │    │     │    │
│                                │ ec │    │ pi │    │ c1 │    │    │     │    │
│                                │ ti │    │ /a │    │    │    │    │     │    │
│                                │ on │    │ cc │    │    │    │    │     │    │
│                                │    │    │ ou │    │    │    │    │     │    │
│                                │    │    │ nt │    │    │    │    │     │    │
│                                │    │    │ s. │    │    │    │    │     │    │
│                                │    │    │ py │    │    │    │    │     │    │
│                                │    │    │ :1 │    │    │    │    │     │    │
│                                │    │    │ 1  │    │    │    │    │     │    │
│cand_01M78HK6S3MFJDFEBJ7QCBNDQD │ py │ CW │ se │ L3 │ 72 │ 17 │ 17 │     │ blo│
│                                │ .i │ E- │ rv │    │ 2d │ 2  │    │     │ cke│
│                                │ ns │ 63 │ ic │    │ f3 │    │    │     │ d: │
│                                │ ec │ 9  │ es │    │ 19 │    │    │     │ vau│
│                                │ ur │    │ /a │    │ 81 │    │    │     │ lt_│
│                                │ e- │    │ pi │    │ c0 │    │    │     │ ide│
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
│cand_01M78HK6S47Z3XCF8S0XCP30J9 │ py │ CW │ se │ L3 │ 6d │ 85 │ 10 │     │ sen│
│                                │ .m │ E- │ rv │    │ ae │    │    │     │ t  │
│                                │ is │ 86 │ ic │    │ 96 │    │    │     │    │
│                                │ si │ 2  │ es │    │ 57 │    │    │     │    │
│                                │ ng │    │ /a │    │ ae │    │    │     │    │
│                                │ -a │    │ pi │    │ 7b │    │    │     │    │
│                                │ ut │    │ /h │    │    │    │    │     │    │
│                                │ ho │    │ an │    │    │    │    │     │    │
│                                │ ri │    │ dl │    │    │    │    │     │    │
│                                │ za │    │ er │    │    │    │    │     │    │
│                                │ ti │    │ s. │    │    │    │    │     │    │
│                                │ on │    │ py │    │    │    │    │     │    │
│                                │    │    │ :3 │    │    │    │    │     │    │
│                                │    │    │ 9  │    │    │    │    │     │    │
│cand_01M78HK8BVSFZTXA0KQ0XPQNC7 │ py │ CW │ se │ L3 │ a8 │ 52 │ 3  │     │ sen│
│                                │ .w │ E- │ rv │    │ e3 │    │    │     │ t  │
│                                │ ea │ 32 │ ic │    │ aa │    │    │     │    │
│                                │ k- │ 7  │ es │    │ 48 │    │    │     │    │
│                                │ pa │    │ /a │    │ 55 │    │    │     │    │
│                                │ ss │    │ pi │    │ bd │    │    │     │    │
│                                │ wo │    │ /s │    │    │    │    │     │    │
│                                │ rd │    │ ec │    │    │    │    │     │    │
│                                │ -h │    │ ur │    │    │    │    │     │    │
│                                │ as │    │ it │    │    │    │    │     │    │
│                                │ h  │    │ y. │    │    │    │    │     │    │
│                                │    │    │ py │    │    │    │    │     │    │
│                                │    │    │ :1 │    │    │    │    │     │    │
│                                │    │    │ 5  │    │    │    │    │     │    │
└────────────────────────────────┴────┴────┴────┴────┴────┴────┴────┴─────┴────┘
10 more payload(s); use --limit 0 to show all
  proves: a payload is a slice with pseudonyms, not the file

== Step 7: Privacy: side by side ==
Original code left, exact payload right.
$ codekavach privacy inspect . --html /tmp/codekavach-demo/inspect.html
candidate cand_01M78HK85ZN5V14VHGGXRYV0VB rule py.command-injection CWE-78  services/api/reports.py:9  level L3
payload f553d91f400d  ~70 tokens  pseudonyms 4  placeholders none  ledger: sent
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
  2 # file_8
  3 import subprocess
  4
  5
  6 def fn_6(param_5, param_4):
  7     """xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"""
  8     subprocess.run(f"zip -x {param_4} {param_5}", shell=True, check=True)
  9     return param_4

candidate cand_01M78HK5JZM3XJ3NR7E626339T rule py.sql-injection CWE-89  services/api/accounts.py:11  level L3
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

candidate cand_01M78HK6S3MFJDFEBJ7QCBNDQD rule py.insecure-direct-object-reference CWE-639  services/api/handlers.py:34  level L3
payload 722df31981c0  ~172 tokens  pseudonyms 17  placeholders none  ledger: blocked: vault_identifier
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
   6 import mod_4
   7 # ... elided ...
   8 import mod_1
   9 from mod_5 import mod_2
  10 # ... elided ...
  11 @app.route("/file_3/file_4/file_5/file_6")
  12 @mod_2
  13 def fn_4(param_1):
  14     var_3 = mod_4.connect()
  15     var_4 = mod_3.fn_3(var_3, param_1)
  16     return jsonify(mod_1.fn_2(var_4))
  17
  18 # unresolved
  19 def fn_2(*args, **param_3): ...
  20 # effects unknown; derived: syntactic
  21 # unresolved
  22 def fn_3(*args, **param_3): ...
  23 # effects unknown; derived: syntactic

candidate cand_01M78HK6S47Z3XCF8S0XCP30J9 rule py.missing-authorization CWE-862  services/api/handlers.py:39  level L3
payload 6dae9657ae7b  ~85 tokens  pseudonyms 10  placeholders none  ledger: sent
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
   6 import mod_4
   7 # ... elided ...
   8 @app.route("/file_3/file_4/file_5/file_7", methods=["POST"])
   9 def fn_5(param_1):
  10     var_3 = mod_4.connect()
  11     mod_3.close(var_3, param_1)
  12     return jsonify(status="xxxxxx")

candidate cand_01M78HK8BVSFZTXA0KQ0XPQNC7 rule py.weak-password-hash CWE-327  services/api/security.py:15  level L3
payload a8e3aa4855bd  ~52 tokens  pseudonyms 3  placeholders none  ledger: sent
Original (stays on this machine)
services/api/security.py
  3 import hashlib
services/api/security.py
  13 def hash_password(password):
  14     """The stored form of a customer password."""
  15     return hashlib.md5(password.encode("utf-8")).hexdigest()
Payload (what the provider receives)
  1 # codekavach payload L3
  2 # file_9
  3 import hashlib
  4 # ... elided ...
  5 def fn_7(param_6):
  6     """xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"""
  7     return hashlib.md5(param_6.encode("xxx-x")).hexdigest()

10 more payload(s); use --limit 0 to show all
  proves: secrets are typed placeholders and identifiers are renamed, on one page that loads nothing from the network

== Step 8: Privacy: audit the ledger ==
Hash chain, payload hashes, and a search for every planted term in every payload.
$ codekavach privacy ledger verify . --check-terms /home/lamp/scrt/repo/.claude/worktrees/wf_8795dd47-dc4-4/fixtures/kavachbank/ground-truth/terms.txt --include-blocked
warning[payload_unreadable]: payload 10662a8eae45 cannot be read
warning[payload_unreadable]: payload 18966e0a90c1 cannot be read
warning[payload_unreadable]: payload 34376a00a18a cannot be read
warning[payload_unreadable]: payload 3cc03e695842 cannot be read
warning[payload_unreadable]: payload 56055674003d cannot be read
warning[payload_unreadable]: payload 679f2e9e7460 cannot be read
warning[payload_unreadable]: payload 6dae9657ae7b cannot be read
warning[payload_unreadable]: payload 722df31981c0 cannot be read
warning[payload_unreadable]: payload a8e3aa4855bd cannot be read
warning[payload_unreadable]: payload bb61e86ab346 cannot be read
warning[payload_unreadable]: payload d4ba6198b8c8 cannot be read
warning[payload_unreadable]: payload f553d91f400d cannot be read
chain intact: 29 records
payloads: 0 checked, 0 mismatches
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
$ codekavach report . --format html,pdf --output-dir /tmp/codekavach-demo/reports
scan scan_01M78HJVWSFPEWP5QZG30WERB0 (2026-11-12 18:51 UTC, 23 findings)
┌───────┬──────────────────────────────────────────────────────┬──────┐
│format │ path                                                 │ size │
├───────┼──────────────────────────────────────────────────────┼──────┤
│html   │ /tmp/codekavach-demo/reports/report.html │ 43 kB│
│pdf    │ /tmp/codekavach-demo/reports/report.pdf  │ 83 kB│
└───────┴──────────────────────────────────────────────────────┴──────┘
  proves: one scan yields html,pdf (SARIF is for code scanning, XLSX for triage, DOCX for the client)
    report.html
    report.pdf

== Step 11: Send findings to GitHub (dry run) ==
Issues and a project board; here only what would change.
$ codekavach sync github . --repo example-org/kavachbank --dry-run
example-org/kavachbank: 23 to create, 0 to update, 0 to close (dry run: nothing
was changed)
┌───────┬──────────┬───────┬───────────────────────────────────────────────────┐
│action │ severity │ issue │ title                                             │
├───────┼──────────┼───────┼───────────────────────────────────────────────────┤
│create │ critical │ -     │ [CRITICAL] A shell command is built from variable │
│       │          │       │ parts that are not quoted.                        │
│create │ critical │ -     │ [CRITICAL] Vulnerable dependency: PyYAML 5.3      │
│       │          │       │ (CVE-2020-14343)                                  │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: Flask 2.2.3         │
│       │          │       │ (CVE-2023-30861)                                  │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: requests 2.19.1     │
│       │          │       │ (CVE-2018-18074, CVE-2023-32681)                  │
│create │ high     │ -     │ [HIGH] A database call receives query text that   │
│       │          │       │ was built by string interpolation.                │
│create │ high     │ -     │ [HIGH] A record is fetched by an identifier from  │
│       │          │       │ the caller with no ownership check.               │
│create │ high     │ -     │ [HIGH] An account-scoped route has no             │
│       │          │       │ authentication or authorisation check.            │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: Jinja2 2.10         │
│       │          │       │ (CVE-2019-10906, CVE-2020-28493, CVE-2024-22195)  │
│create │ high     │ -     │ [HIGH] A password is hashed with an algorithm that│
│       │          │       │ is broken or far too fast.                        │
│create │ high     │ -     │ [HIGH] Data is deserialised with a loader that can│
│       │          │       │ construct arbitrary objects.                      │
│create │ high     │ -     │ [HIGH] A file operation uses a path that comes    │
│       │          │       │ from the caller without a containment check.      │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: lodash 4.17.15      │
│       │          │       │ (CVE-2021-23337, CVE-2020-8203, CVE-2020-28500)   │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: axios 0.21.0        │
│       │          │       │ (CVE-2021-3749, CVE-2020-28168)                   │
│create │ high     │ -     │ [HIGH] Vulnerable dependency: jsonwebtoken 8.5.1  │
│       │          │       │ (CVE-2022-23529)                                  │
│create │ high     │ -     │ [HIGH] An outbound request goes to a URL chosen by│
│       │          │       │ the caller, with no allow-list check.             │
│create │ medium   │ -     │ [MEDIUM] Vulnerable dependency: express 4.16.0    │
│       │          │       │ (CVE-2024-29041, CVE-2024-43796)                  │
│create │ medium   │ -     │ [MEDIUM] A block cipher is given a fixed          │
│       │          │       │ initialisation vector instead of a random one.    │
│create │ medium   │ -     │ [MEDIUM] Data from a http_param source reaches a  │
│       │          │       │ path sink (fs.createReadStream)                   │
│create │ medium   │ -     │ [MEDIUM] Input from the caller is written into an │
│       │          │       │ HTML response without escaping.                   │
│create │ medium   │ -     │ [MEDIUM] Data from a http_param source reaches a  │
│       │          │       │ html sink (res.send)                              │
│create │ medium   │ -     │ [MEDIUM] Handler takes an object id from the path:│
│       │          │       │ worth checking the caller owns it                 │
│create │ medium   │ -     │ [MEDIUM] Data from a http_param source reaches a  │
│       │          │       │ path sink (fs.createReadStream)                   │
│create │ medium   │ -     │ [MEDIUM] Data from a http_param source reaches a  │
│       │          │       │ html sink (res.send)                              │
└───────┴──────────┴───────┴───────────────────────────────────────────────────┘
note: no token: assuming the repository has no CodeKavach issues yet
  proves: findings reach the client's tracker without code leaving, and dry-run changes nothing

== Step 12: Leakage: what could a curious provider learn? ==
Beyond verbatim terms: attack the payloads and measure.
$ codekavach eval leakage --level L3
error[backend_unavailable]: the leakage evaluation is not available in this
build
hint: delivered by epic E37
  skipped: not in this build yet (exit 2)

== Done: 10 ok, 2 skipped (not in this build), 0 failed ==
  files: /tmp/codekavach-demo
```
