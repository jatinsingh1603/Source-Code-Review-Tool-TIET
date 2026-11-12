/**
 * Fixture data for mock mode, modelled on the KavachBank sample application in
 * fixtures/kavachbank (its planted vulnerabilities are listed in
 * fixtures/kavachbank/ground-truth/manifest.yaml). Shapes follow the REST
 * contract exactly so the views behave the same against a live server.
 */
import type {
  Finding,
  LedgerDetail,
  Markup,
  MarkupKind,
  PrivacyLevel,
  Severity,
  TaintStep,
} from "@/api/types";

export interface FindingTemplate {
  key: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  cwe: string;
  cwe_name: string;
  owasp: string;
  asvs: string;
  capec: string;
  cvss4_vector: string;
  cvss4_score: number;
  cvss31_vector: string;
  cvss31_score: number;
  likelihood: string;
  impact: string;
  compliance: { framework: string; clause: string; title?: string }[];
  path: string;
  line: number;
  language: string;
  code: { start: number; text: string };
  taint: TaintStep[];
  /** null: never sent to a model (secrets are handled deterministically). */
  llm: { is_vulnerable: boolean; confidence: number; reasoning: string; impact: string; remediation: string } | null;
  remediation: string;
  references: { title: string; url: string }[];
  engine: string;
  rule_id: string;
}

const CERT_IN = { framework: "CERT-In", clause: "Directions 2022 §4(v)", title: "Secure coding and vulnerability management" };

export const FINDING_TEMPLATES: FindingTemplate[] = [
  {
    key: "KB-VULN-001",
    title: "SQL injection in premium account lookup",
    description:
      "The account identifier from the request path is interpolated into a SQL statement with the % operator and executed without parameter binding.",
    severity: "critical",
    confidence: 0.96,
    cwe: "CWE-89",
    cwe_name: "Improper Neutralization of Special Elements used in an SQL Command",
    owasp: "A03:2021 Injection",
    asvs: "V5.3.4",
    capec: "CAPEC-66",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cvss4_score: 9.3,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    cvss31_score: 8.8,
    likelihood: "High",
    impact: "High",
    compliance: [
      { framework: "PCI DSS 4.0", clause: "6.2.4", title: "Software engineering techniques prevent common attacks" },
      { framework: "ISO/IEC 27001:2022", clause: "A.8.28", title: "Secure coding" },
      { framework: "RBI Cyber Security Framework", clause: "Annex 1 §6", title: "Application security life cycle" },
      CERT_IN,
    ],
    path: "services/api/accounts.py",
    line: 11,
    language: "python",
    code: {
      start: 8,
      text: `def find_premium_account(conn, account_id):
    """The premium-tier account with this id."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM premium_accounts WHERE id = '%s'" % account_id)
    return cur.fetchone()`,
    },
    taint: [
      { kind: "source", label: "Route parameter account_id (Flask)", path: "services/api/handlers.py", line: 31, code: '@app.route("/api/accounts/<account_id>/statement")' },
      { kind: "propagation", label: "Passed to accounts.find_premium_account", path: "services/api/handlers.py", line: 34, code: "accounts.find_premium_account(conn, account_id)" },
      { kind: "propagation", label: "String formatting with %", path: "services/api/accounts.py", line: 11, code: "\"... WHERE id = '%s'\" % account_id" },
      { kind: "sink", label: "cursor.execute (psycopg2)", path: "services/api/accounts.py", line: 11, code: "cur.execute(...)" },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.95,
      reasoning:
        "The parameter reaches cursor.execute through Python %-formatting, so quote characters in the identifier terminate the literal and append SQL. No validation or binding occurs on the path from the route parameter to the sink, and the surrounding function returns the row directly to the caller.",
      impact: "An authenticated user can read or modify any row of the database, including other customers' accounts.",
      remediation: "Pass the identifier as a bound parameter: cur.execute(\"SELECT * FROM premium_accounts WHERE id = %s\", (account_id,)).",
    },
    remediation:
      "Use parameterised queries for every statement. Replace the % interpolation with a bound parameter and add a regression test with a quote character in the identifier.",
    references: [
      { title: "OWASP SQL Injection Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
      { title: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html" },
    ],
    engine: "codekavach-taint",
    rule_id: "py.sqli.string-format",
  },
  {
    key: "KB-VULN-002",
    title: "OS command injection in statement archiving",
    description: "Folder and archive names are formatted into a shell command run with shell=True.",
    severity: "critical",
    confidence: 0.93,
    cwe: "CWE-78",
    cwe_name: "Improper Neutralization of Special Elements used in an OS Command",
    owasp: "A03:2021 Injection",
    asvs: "V5.3.8",
    capec: "CAPEC-88",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    cvss4_score: 9.4,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    cvss31_score: 9.9,
    likelihood: "High",
    impact: "High",
    compliance: [
      { framework: "PCI DSS 4.0", clause: "6.2.4" },
      { framework: "ISO/IEC 27001:2022", clause: "A.8.28" },
      CERT_IN,
    ],
    path: "services/api/reports.py",
    line: 9,
    language: "python",
    code: {
      start: 7,
      text: `def archive_statements(folder, archive_name):
    """Pack a folder of statements into an archive for download."""
    subprocess.run(f"zip -r {archive_name} {folder}", shell=True, check=True)
    return archive_name`,
    },
    taint: [
      { kind: "source", label: "Request argument archive_name", path: "services/api/handlers.py", line: 88 },
      { kind: "propagation", label: "f-string interpolation", path: "services/api/reports.py", line: 9 },
      { kind: "sink", label: "subprocess.run(shell=True)", path: "services/api/reports.py", line: 9 },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.94,
      reasoning:
        "Both arguments are interpolated into a single command string that is executed by the shell. Shell metacharacters such as ; or $() in either value run arbitrary commands. A safe variant exists in the same module (archive_statements_safely) that applies shlex.quote, which confirms the unsafe one is reachable as written.",
      impact: "Remote code execution as the API service account.",
      remediation: "Call subprocess.run with an argument list and shell=False, or quote each argument with shlex.quote.",
    },
    remediation: "Invoke zip with an argument vector and shell=False; validate the archive name against an allowlist pattern.",
    references: [{ title: "OWASP OS Command Injection Defense Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" }],
    engine: "bandit",
    rule_id: "B602",
  },
  {
    key: "KB-VULN-005",
    title: "Insecure deserialisation of cached customer profiles",
    description: "Data from a shared cache is passed to pickle.loads, which executes code embedded in the payload.",
    severity: "high",
    confidence: 0.9,
    cwe: "CWE-502",
    cwe_name: "Deserialization of Untrusted Data",
    owasp: "A08:2021 Software and Data Integrity Failures",
    asvs: "V5.5.1",
    capec: "CAPEC-586",
    cvss4_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cvss4_score: 8.3,
    cvss31_vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    cvss31_score: 7.5,
    likelihood: "Medium",
    impact: "High",
    compliance: [{ framework: "ISO/IEC 27001:2022", clause: "A.8.28" }, CERT_IN],
    path: "services/api/serialisation.py",
    line: 14,
    language: "python",
    code: {
      start: 12,
      text: `def load_cached_profile(blob):
    """A customer profile read back from the shared cache."""
    return pickle.loads(blob)`,
    },
    taint: [
      { kind: "source", label: "Shared cache value", path: "services/api/handlers.py", line: 102 },
      { kind: "sink", label: "pickle.loads", path: "services/api/serialisation.py", line: 14 },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.86,
      reasoning:
        "pickle.loads reconstructs arbitrary objects and runs their __reduce__ hooks. The blob comes from a cache that other services can write, so anyone able to write the cache can execute code in this process.",
      impact: "Code execution for an attacker with write access to the shared cache.",
      remediation: "Store profiles as JSON and parse with json.loads; if pickle is unavoidable, sign the blob with an HMAC and verify before loading.",
    },
    remediation: "Replace pickle with JSON for cached profiles, and authenticate cache entries.",
    references: [{ title: "OWASP Deserialization Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" }],
    engine: "codekavach-rules",
    rule_id: "py.deserialisation.pickle",
  },
  {
    key: "KB-VULN-004",
    title: "Server-side request forgery in settlement status callback",
    description: "A caller-supplied URL is fetched by the server without an allowlist.",
    severity: "high",
    confidence: 0.88,
    cwe: "CWE-918",
    cwe_name: "Server-Side Request Forgery (SSRF)",
    owasp: "A10:2021 Server-Side Request Forgery",
    asvs: "V5.2.6",
    capec: "CAPEC-664",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    cvss4_score: 8.7,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    cvss31_score: 9.3,
    likelihood: "High",
    impact: "Medium",
    compliance: [{ framework: "PCI DSS 4.0", clause: "6.2.4" }, CERT_IN],
    path: "services/web/payments.js",
    line: 18,
    language: "javascript",
    code: {
      start: 17,
      text: `async function fetchSettlementStatus(callbackUrl) {
  const response = await fetch(callbackUrl);
  return response.json();
}`,
    },
    taint: [
      { kind: "source", label: "req.body.callbackUrl", path: "services/web/routes.js", line: 22 },
      { kind: "sink", label: "fetch(url)", path: "services/web/payments.js", line: 18 },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.9,
      reasoning:
        "The URL is used as-is. Unlike fetchPartnerRate in the same file, there is no hostname allowlist, so internal endpoints such as the cloud metadata service are reachable from the server.",
      impact: "Access to internal services and cloud credentials from the network position of the web tier.",
      remediation: "Apply the same allowlist check used by fetchPartnerRate and reject private address ranges after DNS resolution.",
    },
    remediation: "Validate the callback host against config.allowedHosts and block private and link-local ranges.",
    references: [{ title: "OWASP SSRF Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" }],
    engine: "opengrep",
    rule_id: "js.ssrf.fetch-user-url",
  },
  {
    key: "KB-VULN-003",
    title: "Path traversal in statement export",
    description: "The requested file name is joined to the export directory without normalisation checks.",
    severity: "high",
    confidence: 0.91,
    cwe: "CWE-22",
    cwe_name: "Improper Limitation of a Pathname to a Restricted Directory",
    owasp: "A01:2021 Broken Access Control",
    asvs: "V12.3.1",
    capec: "CAPEC-126",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cvss4_score: 8.7,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss31_score: 7.5,
    likelihood: "High",
    impact: "High",
    compliance: [{ framework: "ISO/IEC 27001:2022", clause: "A.8.28" }, CERT_IN],
    path: "services/web/exporter.js",
    line: 9,
    language: "javascript",
    code: {
      start: 7,
      text: `function exportStatement(req, res) {
  const file = path.join(config.exportDir, req.query.file);
  fs.createReadStream(file).pipe(res);
}`,
    },
    taint: [
      { kind: "source", label: "req.query.file", path: "services/web/exporter.js", line: 8 },
      { kind: "propagation", label: "path.join", path: "services/web/exporter.js", line: 8 },
      { kind: "sink", label: "fs.createReadStream", path: "services/web/exporter.js", line: 9 },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.92,
      reasoning:
        "path.join normalises ../ segments, so a value such as ../../etc/passwd escapes the export directory. The safe variant in the same module resolves and checks the prefix; this one does not.",
      impact: "Read access to any file the web process can read, including configuration with credentials.",
      remediation: "Resolve the path and verify it stays under the export root, as exportStatementSafely does.",
    },
    remediation: "Resolve against the root and reject results outside it; prefer opaque statement identifiers over file names.",
    references: [{ title: "CWE-22", url: "https://cwe.mitre.org/data/definitions/22.html" }],
    engine: "codekavach-taint",
    rule_id: "js.path-traversal.fs",
  },
  {
    key: "KB-VULN-008",
    title: "Missing authorisation on account closure endpoint",
    description: "POST /api/accounts/<id>/close has no authentication decorator and no ownership check.",
    severity: "high",
    confidence: 0.84,
    cwe: "CWE-862",
    cwe_name: "Missing Authorization",
    owasp: "A01:2021 Broken Access Control",
    asvs: "V4.1.1",
    capec: "CAPEC-122",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N",
    cvss4_score: 8.8,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
    cvss31_score: 9.1,
    likelihood: "High",
    impact: "High",
    compliance: [{ framework: "RBI Cyber Security Framework", clause: "Annex 1 §8", title: "Access control" }, CERT_IN],
    path: "services/api/handlers.py",
    line: 39,
    language: "python",
    code: {
      start: 38,
      text: `@app.route("/api/accounts/<account_id>/close", methods=["POST"])
def close_account(account_id):
    conn = db.connect()
    accounts.close(conn, account_id)
    return jsonify(status="closed")`,
    },
    taint: [],
    llm: {
      is_vulnerable: true,
      confidence: 0.88,
      reasoning:
        "Every other state-changing route in the module is wrapped in @require_auth and checks ownership through _owned_account. This route has neither, so an anonymous request can close any account by identifier.",
      impact: "Unauthenticated closure of arbitrary customer accounts.",
      remediation: "Add @require_auth and load the account through _owned_account before closing it.",
    },
    remediation: "Require authentication and verify ownership before the state change.",
    references: [{ title: "OWASP Authorization Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" }],
    engine: "codekavach-rules",
    rule_id: "py.flask.route-without-auth",
  },
  {
    key: "KB-VULN-009",
    title: "Insecure direct object reference in account statement",
    description: "The statement endpoint authenticates the caller but does not check that the account belongs to them.",
    severity: "medium",
    confidence: 0.78,
    cwe: "CWE-639",
    cwe_name: "Authorization Bypass Through User-Controlled Key",
    owasp: "A01:2021 Broken Access Control",
    asvs: "V4.2.1",
    capec: "CAPEC-1",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cvss4_score: 7.1,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    cvss31_score: 6.5,
    likelihood: "Medium",
    impact: "High",
    compliance: [{ framework: "DPDP Act 2023", clause: "§8(5)", title: "Reasonable security safeguards" }, CERT_IN],
    path: "services/api/handlers.py",
    line: 34,
    language: "python",
    code: {
      start: 30,
      text: `@app.route("/api/accounts/<account_id>/statement")
@require_auth
def account_statement(account_id):
    conn = db.connect()
    statement = accounts.get_statement(conn, account_id)
    return jsonify(serialisation.dump_statement(statement))`,
    },
    taint: [
      { kind: "source", label: "Route parameter account_id", path: "services/api/handlers.py", line: 30 },
      { kind: "sink", label: "accounts.get_statement (data read)", path: "services/api/handlers.py", line: 34 },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.81,
      reasoning:
        "The handler is authenticated but passes the user-controlled identifier straight to get_statement. The neighbouring account_interest handler uses _owned_account to enforce ownership; this one omits it.",
      impact: "Any signed-in customer can read another customer's 90-day statement.",
      remediation: "Load the account through _owned_account(conn, account_id) before reading the statement.",
    },
    remediation: "Enforce object-level authorisation on every route that takes an account identifier.",
    references: [{ title: "OWASP API1:2023 Broken Object Level Authorization", url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/" }],
    engine: "codekavach-rules",
    rule_id: "py.idor.unchecked-owner",
  },
  {
    key: "KB-VULN-010",
    title: "Reflected cross-site scripting in greeting",
    description: "The name query parameter is concatenated into HTML without escaping.",
    severity: "medium",
    confidence: 0.89,
    cwe: "CWE-79",
    cwe_name: "Improper Neutralization of Input During Web Page Generation",
    owasp: "A03:2021 Injection",
    asvs: "V5.3.3",
    capec: "CAPEC-591",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    cvss4_score: 5.1,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    cvss31_score: 6.1,
    likelihood: "Medium",
    impact: "Medium",
    compliance: [{ framework: "PCI DSS 4.0", clause: "6.2.4" }],
    path: "services/web/renderer.js",
    line: 18,
    language: "javascript",
    code: {
      start: 17,
      text: `function renderGreeting(req, res) {
  res.send('<h1>Welcome back, ' + req.query.name + '</h1>');
}`,
    },
    taint: [
      { kind: "source", label: "req.query.name", path: "services/web/renderer.js", line: 18 },
      { kind: "sink", label: "res.send (HTML)", path: "services/web/renderer.js", line: 18 },
    ],
    llm: {
      is_vulnerable: true,
      confidence: 0.91,
      reasoning:
        "The value is placed into an HTML response body without escapeHtml, which the module defines and uses in renderGreetingSafely. A script tag in the name parameter executes in the victim's session.",
      impact: "Session riding and credential theft through a crafted link.",
      remediation: "Escape the value with escapeHtml or render through the template helper.",
    },
    remediation: "Escape all untrusted values in HTML context; add a Content-Security-Policy.",
    references: [{ title: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" }],
    engine: "eslint",
    rule_id: "security/detect-xss",
  },
  {
    key: "KB-VULN-006",
    title: "Customer passwords hashed with MD5",
    description: "hash_password stores an unsalted MD5 digest of the password.",
    severity: "medium",
    confidence: 0.97,
    cwe: "CWE-327",
    cwe_name: "Use of a Broken or Risky Cryptographic Algorithm",
    owasp: "A02:2021 Cryptographic Failures",
    asvs: "V2.4.1",
    capec: "CAPEC-55",
    cvss4_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cvss4_score: 6.3,
    cvss31_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss31_score: 5.9,
    likelihood: "Low",
    impact: "High",
    compliance: [{ framework: "PCI DSS 4.0", clause: "8.3.2" }, { framework: "DPDP Act 2023", clause: "§8(5)" }],
    path: "services/api/security.py",
    line: 15,
    language: "python",
    code: {
      start: 13,
      text: `def hash_password(password):
    """The stored form of a customer password."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()`,
    },
    taint: [],
    llm: {
      is_vulnerable: true,
      confidence: 0.96,
      reasoning:
        "MD5 is fast and unsalted here, so a leaked table is cracked offline with commodity hardware. The module already contains hash_password_strong based on scrypt.",
      impact: "Mass recovery of customer passwords after a database leak.",
      remediation: "Switch callers to hash_password_strong (scrypt with a random salt) and rehash on next login.",
    },
    remediation: "Use a memory-hard password hash (scrypt, Argon2id) with a per-user salt.",
    references: [{ title: "OWASP Password Storage Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html" }],
    engine: "bandit",
    rule_id: "B324",
  },
  {
    key: "KB-VULN-007",
    title: "Static initialisation vector in field encryption",
    description: "AES-CBC is used with a constant IV for every encrypted column value.",
    severity: "medium",
    confidence: 0.85,
    cwe: "CWE-329",
    cwe_name: "Generation of Predictable IV with CBC Mode",
    owasp: "A02:2021 Cryptographic Failures",
    asvs: "V6.2.5",
    capec: "CAPEC-20",
    cvss4_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    cvss4_score: 5.9,
    cvss31_vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
    cvss31_score: 5.3,
    likelihood: "Low",
    impact: "Medium",
    compliance: [{ framework: "ISO/IEC 27001:2022", clause: "A.8.24", title: "Use of cryptography" }],
    path: "services/api/security.py",
    line: 27,
    language: "python",
    code: {
      start: 25,
      text: `def encrypt_field(key, plaintext):
    """Encrypt a column value before it is stored."""
    cipher = AES.new(key, AES.MODE_CBC, STATIC_IV)
    return cipher.encrypt(plaintext.ljust(16 * ((len(plaintext) + 15) // 16)).encode("utf-8"))`,
    },
    taint: [],
    llm: {
      is_vulnerable: true,
      confidence: 0.83,
      reasoning:
        "A constant IV makes equal plaintext prefixes produce equal ciphertext, leaking equality between stored values. Padding with spaces also offers no integrity.",
      impact: "Equality and prefix leakage of encrypted personal data.",
      remediation: "Use AES-GCM with a fresh random nonce per value, stored alongside the ciphertext.",
    },
    remediation: "Generate a random IV or nonce per encryption; prefer an AEAD mode such as AES-GCM.",
    references: [{ title: "CWE-329", url: "https://cwe.mitre.org/data/definitions/329.html" }],
    engine: "codekavach-rules",
    rule_id: "py.crypto.static-iv",
  },
  {
    key: "KB-SEC-002",
    title: "Hard-coded AWS access key in configuration",
    description: "An AWS access key identifier and secret are committed in source.",
    severity: "high",
    confidence: 0.99,
    cwe: "CWE-798",
    cwe_name: "Use of Hard-coded Credentials",
    owasp: "A07:2021 Identification and Authentication Failures",
    asvs: "V2.10.4",
    capec: "CAPEC-191",
    cvss4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cvss4_score: 8.8,
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cvss31_score: 9.1,
    likelihood: "High",
    impact: "High",
    compliance: [{ framework: "PCI DSS 4.0", clause: "8.6.2" }, CERT_IN],
    path: "services/api/config.py",
    line: 16,
    language: "python",
    code: {
      start: 16,
      text: `AWS_ACCESS_KEY_ID = "AKIA************MPLE"
AWS_SECRET_ACCESS_KEY = "wJal********************************EKEY"`,
    },
    taint: [],
    llm: null,
    remediation: "Rotate the credential, purge it from history and load it at runtime from a secret store.",
    references: [{ title: "OWASP Secrets Management Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" }],
    engine: "codekavach-secrets",
    rule_id: "secret.aws_access_key",
  },
  {
    key: "KB-LOW-001",
    title: "Debug health endpoint discloses service status without rate limiting",
    description: "The health route is public and unthrottled.",
    severity: "low",
    confidence: 0.55,
    cwe: "CWE-770",
    cwe_name: "Allocation of Resources Without Limits or Throttling",
    owasp: "A04:2021 Insecure Design",
    asvs: "V11.1.4",
    capec: "CAPEC-125",
    cvss4_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
    cvss4_score: 2.3,
    cvss31_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
    cvss31_score: 3.7,
    likelihood: "Low",
    impact: "Low",
    compliance: [],
    path: "services/api/handlers.py",
    line: 25,
    language: "python",
    code: {
      start: 25,
      text: `@app.route("/health")
def health():
    return jsonify(status="ok")`,
    },
    taint: [],
    llm: {
      is_vulnerable: false,
      confidence: 0.72,
      reasoning:
        "The endpoint returns a constant and touches no backing service, so the denial-of-service potential is negligible. Kept at low severity with the model's dismissal recorded; the deterministic evidence is preserved.",
      impact: "Negligible.",
      remediation: "Apply the platform rate limiter to public routes.",
    },
    remediation: "Apply rate limiting at the gateway for all public endpoints.",
    references: [],
    engine: "codekavach-rules",
    rule_id: "py.flask.public-route",
  },
  {
    key: "KB-INFO-001",
    title: "Flask application created without explicit secret key configuration",
    description: "Session signing key is not set in code; ensure it is configured at deploy time.",
    severity: "info",
    confidence: 0.4,
    cwe: "CWE-1188",
    cwe_name: "Initialization of a Resource with an Insecure Default",
    owasp: "A05:2021 Security Misconfiguration",
    asvs: "V14.1.1",
    capec: "",
    cvss4_vector: "",
    cvss4_score: 0,
    cvss31_vector: "",
    cvss31_score: 0,
    likelihood: "Low",
    impact: "Low",
    compliance: [],
    path: "services/api/handlers.py",
    line: 15,
    language: "python",
    code: { start: 15, text: `app = Flask(__name__)` },
    taint: [],
    llm: {
      is_vulnerable: false,
      confidence: 0.6,
      reasoning: "Informational: configuration may be supplied by the environment at deploy time.",
      impact: "None if configured correctly.",
      remediation: "Document the SECRET_KEY requirement in deployment configuration.",
    },
    remediation: "Set SECRET_KEY from the environment and fail start-up if it is missing.",
    references: [],
    engine: "codekavach-rules",
    rule_id: "py.flask.no-secret-key",
  },
];

export const PIPELINE_STAGES = [
  "ingest",
  "parse",
  "analyse",
  "aggregate",
  "privacy-prepare",
  "llm-review",
  "restore",
  "rate",
  "privacy-check",
  "report",
];

export function buildFinding(
  t: FindingTemplate,
  scanId: string,
  idx: number,
  provider: string,
  model: string,
  withLlm: boolean,
): Finding {
  const lines = t.code.text.split("\n").map((text, i) => ({ number: t.code.start + i, text }));
  return {
    id: `${scanId}-f${String(idx + 1).padStart(2, "0")}`,
    scan_id: scanId,
    title: t.title,
    description: t.description,
    severity: t.severity,
    confidence: t.confidence,
    cwe: t.cwe,
    cwe_name: t.cwe_name,
    owasp: t.owasp,
    asvs: t.asvs,
    capec: t.capec || null,
    cvss4_vector: t.cvss4_vector || null,
    cvss4_score: t.cvss4_vector ? t.cvss4_score : null,
    cvss31_vector: t.cvss31_vector || null,
    cvss31_score: t.cvss31_vector ? t.cvss31_score : null,
    likelihood: t.likelihood,
    impact: t.impact,
    compliance: t.compliance,
    locations: [{ path: t.path, start_line: t.line, end_line: t.line }],
    evidence: {
      snippet: lines.find((l) => l.number === t.line)?.text.trim() ?? null,
      code: { path: t.path, start_line: t.code.start, lines, highlight: [{ start: t.line, end: t.line }], language: t.language },
      taint_path: t.taint,
    },
    llm: withLlm && t.llm ? { ...t.llm, model, provider } : null,
    remediation: t.remediation,
    references: t.references,
    status: "open",
    engine: t.engine,
    rule_id: t.rule_id,
    fingerprint: `sha256:${hashish(t.key + t.path + t.line)}`,
    created_at: new Date().toISOString(),
  };
}

export function hashish(s: string, len = 64): string {
  // Deterministic, non-cryptographic hex digest for fixture identifiers only.
  let h1 = 0x811c9dc5;
  let out = "";
  let i = 0;
  while (out.length < len) {
    for (const ch of s + i) {
      h1 ^= ch.charCodeAt(0);
      h1 = Math.imul(h1, 0x01000193) >>> 0;
    }
    out += h1.toString(16).padStart(8, "0");
    i++;
  }
  return out.slice(0, len);
}

// ---- ledger -----------------------------------------------------------------

interface LedgerSample {
  candidate: string;
  findingKey: string;
  original: string;
  payload: string;
  marks: { kind: MarkupKind; original?: string; payload?: string; label?: string }[];
}

export const LEDGER_SAMPLES: LedgerSample[] = [
  {
    candidate: "cand-sqli-accounts-11",
    findingKey: "KB-VULN-001",
    original: `def find_premium_account(conn, account_id):
    """The premium-tier account with this id."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM premium_accounts WHERE id = '%s'" % account_id)
    return cur.fetchone()`,
    payload: `def fn_7(conn, id_3):
    cur = conn.cursor()
    cur.execute("SELECT * FROM <TABLE_1> WHERE id = '%s'" % id_3)
    return cur.fetchone()`,
    marks: [
      { kind: "identifier", original: "find_premium_account", payload: "fn_7" },
      { kind: "identifier", original: "account_id", payload: "id_3" },
      { kind: "literal", original: "premium_accounts", payload: "<TABLE_1>" },
      { kind: "literal", original: '"""The premium-tier account with this id."""' },
    ],
  },
  {
    candidate: "cand-cmdi-reports-9",
    findingKey: "KB-VULN-002",
    original: `def archive_statements(folder, archive_name):
    """Pack a folder of statements into an archive for download."""
    subprocess.run(f"zip -r {archive_name} {folder}", shell=True, check=True)
    return archive_name`,
    payload: `def fn_2(var_1, var_2):
    subprocess.run(f"zip -r {var_2} {var_1}", shell=True, check=True)
    return var_2`,
    marks: [
      { kind: "identifier", original: "archive_statements", payload: "fn_2" },
      { kind: "identifier", original: "folder", payload: "var_1" },
      { kind: "identifier", original: "archive_name", payload: "var_2" },
      { kind: "literal", original: '"""Pack a folder of statements into an archive for download."""' },
    ],
  },
  {
    candidate: "cand-config-secrets",
    findingKey: "KB-SEC-002",
    original: `DATABASE_URL = "postgresql://kb_app:Kavach#2024@db.kavachbank.internal:5432/core"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
RELATIONSHIP_MANAGER = "priya.sharma@kavachbank.example"`,
    payload: `VAR_1 = "<SECRET_CONNECTION_STRING_1>"
VAR_2 = "<SECRET_AWS_ACCESS_KEY_1>"
VAR_3 = "<SECRET_AWS_SECRET_KEY_1>"
VAR_4 = "<PII_EMAIL_1>"`,
    marks: [
      { kind: "secret", original: "postgresql://kb_app:Kavach#2024@db.kavachbank.internal:5432/core", payload: "<SECRET_CONNECTION_STRING_1>", label: "connection_string" },
      { kind: "secret", original: "AKIAIOSFODNN7EXAMPLE", payload: "<SECRET_AWS_ACCESS_KEY_1>", label: "aws_access_key" },
      { kind: "secret", original: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", payload: "<SECRET_AWS_SECRET_KEY_1>", label: "aws_secret_key" },
      { kind: "pii", original: "priya.sharma@kavachbank.example", payload: "<PII_EMAIL_1>", label: "email" },
      { kind: "identifier", original: "DATABASE_URL", payload: "VAR_1" },
      { kind: "identifier", original: "AWS_ACCESS_KEY_ID", payload: "VAR_2" },
      { kind: "identifier", original: "AWS_SECRET_ACCESS_KEY", payload: "VAR_3" },
      { kind: "identifier", original: "RELATIONSHIP_MANAGER", payload: "VAR_4" },
    ],
  },
  {
    candidate: "cand-ssrf-payments-18",
    findingKey: "KB-VULN-004",
    original: `async function fetchSettlementStatus(callbackUrl) {
  const response = await fetch(callbackUrl);
  return response.json();
}`,
    payload: `async function fn_4(var_5) {
  const response = await fetch(var_5);
  return response.json();
}`,
    marks: [
      { kind: "identifier", original: "fetchSettlementStatus", payload: "fn_4" },
      { kind: "identifier", original: "callbackUrl", payload: "var_5" },
    ],
  },
  {
    candidate: "cand-idor-handlers-34",
    findingKey: "KB-VULN-009",
    original: `def account_statement(account_id):
    conn = db.connect()
    statement = accounts.get_statement(conn, account_id)
    return jsonify(serialisation.dump_statement(statement))`,
    payload: `def fn_9(id_3):
    conn = mod_1.connect()
    var_8 = mod_2.fn_10(conn, id_3)
    return jsonify(mod_3.fn_11(var_8))`,
    marks: [
      { kind: "identifier", original: "account_statement", payload: "fn_9" },
      { kind: "identifier", original: "account_id", payload: "id_3" },
      { kind: "identifier", original: "get_statement", payload: "fn_10" },
      { kind: "identifier", original: "dump_statement", payload: "fn_11" },
      { kind: "identifier", original: "statement", payload: "var_8" },
    ],
  },
];

export function markupFor(sample: LedgerSample): Markup[] {
  const out: Markup[] = [];
  const scan = (text: string, needle: string | undefined, kind: MarkupKind, side: "original" | "payload", label?: string) => {
    if (!needle) return;
    let from = 0;
    for (;;) {
      const i = text.indexOf(needle, from);
      if (i < 0) break;
      // only whole-token matches for identifiers
      const before = text[i - 1] ?? " ";
      const after = text[i + needle.length] ?? " ";
      const ok = kind !== "identifier" || (!/[A-Za-z0-9_]/.test(before) && !/[A-Za-z0-9_]/.test(after));
      if (ok && !out.some((m) => m.side === side && i < m.end && i + needle.length > m.start)) {
        out.push({ kind, start: i, end: i + needle.length, side, label });
      }
      from = i + needle.length;
    }
  };
  for (const m of sample.marks.filter((x) => x.kind !== "identifier")) {
    scan(sample.original, m.original, m.kind, "original", m.label);
    scan(sample.payload, m.payload, m.kind, "payload", m.label);
  }
  for (const m of sample.marks.filter((x) => x.kind === "identifier")) {
    scan(sample.original, m.original, m.kind, "original", m.label);
    scan(sample.payload, m.payload, m.kind, "payload", m.label);
  }
  return out.sort((a, b) => a.start - b.start);
}

export function ledgerDetail(
  scanId: string,
  seq: number,
  level: PrivacyLevel,
  provider: string,
  model: string,
  ts: string,
  prevHash: string,
): LedgerDetail {
  const s = LEDGER_SAMPLES[(seq - 1) % LEDGER_SAMPLES.length]!;
  const payloadHash = `sha256:${hashish(s.payload + scanId)}`;
  const entryHash = `sha256:${hashish(prevHash + payloadHash + seq)}`;
  return {
    entry: {
      seq,
      timestamp: ts,
      provider,
      model,
      level,
      payload_hash: payloadHash,
      entry_hash: entryHash,
      prev_hash: prevHash,
      tokens: Math.round(s.payload.length / 3.6) + 180,
      candidate_id: s.candidate,
      finding_id: null,
      outcome: s.candidate === "cand-config-secrets" ? "blocked: secret_density" : "sent",
    },
    payload_text: s.payload,
    original_text: s.original,
    markup: markupFor(s),
  };
}

export const DEFAULT_POLICY = `# CodeKavach privacy policy
# Decides what may leave this machine, per path and per provider.

[policy]
default_level = "L3"
max_level = "L4"
fail_closed = true

[[policy.paths]]
pattern = "services/api/config.py"
level = "L0"          # never send configuration files
reason = "contains credentials"

[[policy.paths]]
pattern = "fixtures/seed/**"
never_send = true
reason = "customer seed data"

[providers.agentrouter]
trust_tier = "hosted"
max_level = "L3"
retention = "provider terms: no training, 30 day abuse log"

[providers.ollama]
trust_tier = "local"
max_level = "L4"

[redaction]
secrets = true
pii = ["email", "phone_intl", "pan_number", "aadhaar_number", "upi_id", "credit_card"]
domain_terms = "fixtures/kavachbank/ground-truth/terms.txt"
`;
