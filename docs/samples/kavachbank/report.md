# Secure Source Code Review: KavachBank

**Report** CK-RPT-2026-13RKHE0V · **Classification** Confidential · **Generated** 2026-11-12 19:25 UTC

**Overall risk: Critical** · 59 findings

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 15 | 27 | 12 | 5 | 0 |

## Executive summary

Thapar Institute of Engineering and Technology commissioned a secure source code review of KavachBank. The review was performed on 12 November 2026 with CodeKavach, combining deterministic rule and taint analysis with model-assisted triage under a privacy-preserving egress policy. 30 files and 947 lines of YAML, Python, Unknown, JavaScript, Dockerfile, Terraform code were analysed.

The review identified 59 findings (15 critical, 27 high, 12 medium, 5 low). The overall security posture is rated critical: at least one weakness can be exploited to compromise the application or its data, and immediate action is required. 6 findings are supported by a complete source-to-sink data-flow trace.


### Most significant findings

- CK-2026-001 (Critical): A pull_request_target workflow checks out the pull request head, running untrusted code with repository secrets and a write token. An attacker can run code with the pipeline's secrets and write token, tamper with releases and pivot into the supply chain.
- CK-2026-002 (Critical): Container 'api' is privileged. Any other weakness in the component becomes a full host or cluster compromise, because the attacker inherits the excess privileges.
- CK-2026-003 (Critical): Data from a http_param source reaches a sql sink (cur.execute). If account_id is attacker-controlled, an attacker could alter the query predicate and potentially retrieve unauthorized database rows; broader effects depend on the database driver and permissions.
- CK-2026-004 (Critical): Hard-coded credential of type connection_string (masked preview po****** (51 chars), entropy 4.91 bits/char). Anyone with access to the repository, a build artefact or a decompiled binary obtains the credential; rotating it requires a code change and redeployment.
- CK-2026-005 (Critical): Hard-coded credential of type aws_access_key (masked preview AK****** (20 chars), entropy 3.68 bits/char). Anyone with access to the repository, a build artefact or a decompiled binary obtains the credential; rotating it requires a code change and redeployment.

### Where the weaknesses concentrate

The most frequent weakness classes are CWE-798 Use of Hard-coded Credentials (11); CWE-250 Execution with Unnecessary Privileges (8); CWE-1395 Dependency on Vulnerable Third-Party Component (8). By OWASP Top 10 category the largest group is A07:2021 Identification and Authentication Failures (12 findings). Recurring classes indicate a missing shared control rather than isolated mistakes, so the recommendations below address the control as well as each instance.


### Strategic recommendations

- Immediate (within 7 days): Revoke and rotate the exposed credential immediately, then load it at run time from a secret manager or environment. [CK-2026-004, CK-2026-005, CK-2026-006, CK-2026-007 and others]
- Immediate (within 7 days): Upgrade the component to a fixed version, or remove it if it is not needed. [CK-2026-015]
- Short term (within 30 days): Upgrade the component to a fixed version, or remove it if it is not needed. [CK-2026-026, CK-2026-027, CK-2026-038, CK-2026-040 and others]
- Short term (within 30 days): Run the component as a non-root user, drop the privileged flag and grant only the capabilities it needs. [CK-2026-018, CK-2026-019, CK-2026-021, CK-2026-022]
- Medium term (within 90 days): Run the component as a non-root user, drop the privileged flag and grant only the capabilities it needs. [CK-2026-043, CK-2026-044, CK-2026-047]
- Medium term (within 90 days): Encode output for its HTML context (or use a template engine with auto-escaping) and never send raw request data with res.send or equivalent. [CK-2026-051, CK-2026-054]
- Planned (next release cycle): Do not check out untrusted code in privileged workflows; pin third-party actions to a full commit SHA and reduce the token permissions. [CK-2026-058, CK-2026-059]
- Planned (next release cycle): Pin the component to a reviewed version or digest and replace unmaintained components. [CK-2026-055, CK-2026-057]
- Embed the deterministic rules in CI so that the weakness classes found here are blocked at pull-request time, and schedule a retest once the fixes are deployed.

## Findings

| ID | Severity | Title | CWE | Location | Status |
|---|---|---|---|---|---|
| CK-2026-001 | critical | A pull_request_target workflow checks out the pull request head, running untrusted code with repository secrets and a write token. | CWE-829 | `.github/workflows/ci.yml:12` | open |
| CK-2026-002 | critical | Container 'api' is privileged. | CWE-250 | `deploy/k8s/api.yaml:24` | open |
| CK-2026-003 | critical | Data from a http_param source reaches a sql sink (cur.execute) | CWE-89 | `services/api/accounts.py:11` | open |
| CK-2026-004 | critical | Hard-coded credential of type connection_string (masked preview po****** (51 chars), entropy 4.91 bits/char). | CWE-798 | `services/api/config.py:14` | open |
| CK-2026-005 | critical | Hard-coded credential of type aws_access_key (masked preview AK****** (20 chars), entropy 3.68 bits/char). | CWE-798 | `services/api/config.py:16` | open |
| CK-2026-006 | critical | Hard-coded credential of type private_key_block (masked preview --****** (313 chars), entropy 5.97 bits/char). | CWE-798, CWE-321 | `services/api/config.py:20` | open |
| CK-2026-007 | critical | Hard-coded credential of type razorpay_key_id (masked preview rz****** (23 chars), entropy 4.26 bits/char). | CWE-798 | `services/web/config.js:10` | open |
| CK-2026-008 | critical | Hard-coded credential of type generic_credential (masked preview ad****** (12 chars), entropy 3.08 bits/char). | CWE-798 | `deploy/docker-compose.yml:9` | open |
| CK-2026-009 | critical | Hard-coded credential of type aws_secret_key (masked preview wJ****** (40 chars), entropy 4.66 bits/char). | CWE-798 | `services/api/config.py:17` | open |
| CK-2026-010 | critical | Hard-coded credential of type razorpay_key_secret (masked preview ab****** (24 chars), entropy 4.58 bits/char). | CWE-798 | `services/api/config.py:18` | open |
| CK-2026-011 | critical | Hard-coded credential of type generic_credential (masked preview hu****** (14 chars), entropy 2.81 bits/char). | CWE-798 | `services/api/config.py:19` | open |
| CK-2026-012 | critical | A shell command is built from variable parts that are not quoted. | CWE-78 | `services/api/reports.py:9` | open |
| CK-2026-013 | critical | Data is deserialised with a loader that can construct arbitrary objects. | CWE-502 | `services/api/serialisation.py:14` | open |
| CK-2026-014 | critical | Hard-coded credential of type razorpay_key_secret (masked preview ab****** (24 chars), entropy 4.58 bits/char). | CWE-798 | `services/web/config.js:11` | open |
| CK-2026-015 | critical | Vulnerable dependency: PyYAML 5.3 (CVE-2020-14343) | CWE-1395, CWE-20 | `services/api/requirements.txt:5` | open |
| CK-2026-016 | high | A run step in job 'build' interpolates attacker-controlled event data into a shell script; pass it through an environment variable instead. | CWE-78 | `.github/workflows/ci.yml:14` | open |
| CK-2026-017 | high | ENV KB_DB_PASSWORD bakes a credential into the image layers; use a build secret or runtime injection. | CWE-798 | `deploy/Dockerfile:5` | open |
| CK-2026-018 | high | Service 'api' runs privileged, giving it nearly full host access. | CWE-250 | `deploy/docker-compose.yml:4` | open |
| CK-2026-019 | high | Service 'api' mounts the Docker socket, which is root on the host. | CWE-250 | `deploy/docker-compose.yml:6` | open |
| CK-2026-020 | high | Service 'api' sets KB_ADMIN_PASSWORD to a literal in the compose file; use an env file or secret store. | CWE-798 | `deploy/docker-compose.yml:8` | open |
| CK-2026-021 | high | Pod shares the host network namespace. | CWE-250 | `deploy/k8s/api.yaml:15` | open |
| CK-2026-022 | high | Pod mounts a hostPath volume, exposing the node filesystem. | CWE-250 | `deploy/k8s/api.yaml:18` | open |
| CK-2026-023 | high | S3 bucket 'statements' uses a public ACL. | CWE-732 | `infra/main.tf:3` | open |
| CK-2026-024 | high | Security group 'admin' allows ingress from the whole internet on an administrative or database port. | CWE-284 | `infra/main.tf:11` | open |
| CK-2026-025 | high | Database 'ledger' is publicly accessible. | CWE-668 | `infra/main.tf:19` | open |
| CK-2026-026 | high | Vulnerable dependency: Flask 2.2.3 (CVE-2023-30861) | CWE-1395, CWE-539 | `services/api/requirements.txt:2` | open |
| CK-2026-027 | high | Vulnerable dependency: requests 2.19.1 (CVE-2018-18074, CVE-2023-32681) | CWE-1395, CWE-522, CWE-200 | `services/api/requirements.txt:4` | open |
| CK-2026-028 | high | TLS certificate verification is disabled, enabling man-in-the-middle attacks. | CWE-295 | `services/api/settings.yaml:4` | open |
| CK-2026-029 | high | A deprecated protocol version (SSLv2/3, TLS 1.0 or 1.1) is allowed. | CWE-326 | `services/api/settings.yaml:5` | open |
| CK-2026-030 | high | Data from a http_param source reaches a path sink (fs.createReadStream) | CWE-22 | `services/web/exporter.js:9` | open |
| CK-2026-031 | high | Data from a http_param source reaches a http sink (fetch) | CWE-918 | `services/web/payments.js:18` | open |
| CK-2026-032 | high | A record is fetched by an identifier from the caller with no ownership check. | CWE-639 | `services/api/handlers.py:34` | open |
| CK-2026-033 | high | An account-scoped route has no authentication or authorisation check. | CWE-862 | `services/api/handlers.py:39` | open |
| CK-2026-034 | high | A password is hashed with an algorithm that is broken or far too fast. | CWE-327 | `services/api/security.py:15` | open |
| CK-2026-035 | high | A block cipher is given a fixed initialisation vector instead of a random one. | CWE-329 | `services/api/security.py:27` | open |
| CK-2026-036 | high | Handler takes an object id from the path: worth checking the caller owns it | CWE-639, CWE-863 | `services/api/handlers.py:39` | open |
| CK-2026-037 | high | Handler takes an object id from the path: worth checking the caller owns it | CWE-639, CWE-863 | `services/api/handlers.py:97` | open |
| CK-2026-038 | high | Vulnerable dependency: Jinja2 2.10 (CVE-2019-10906, CVE-2020-28493, CVE-2024-22195) | CWE-1395, CWE-400, CWE-79 | `services/api/requirements.txt:3` | open |
| CK-2026-039 | high | Data from a http_param source reaches a path sink (fs.createReadStream) | CWE-22 | `services/web/exporter.js:19` | open |
| CK-2026-040 | high | Vulnerable dependency: lodash 4.17.15 (CVE-2021-23337, CVE-2020-8203, CVE-2020-28500) | CWE-1395, CWE-77, CWE-94, CWE-1321, CWE-1333 | `services/web/package.json:8` | open |
| CK-2026-041 | high | Vulnerable dependency: axios 0.21.0 (CVE-2021-3749, CVE-2020-28168) | CWE-1395, CWE-1333, CWE-918 | `services/web/package.json:9` | open |
| CK-2026-042 | high | Vulnerable dependency: jsonwebtoken 8.5.1 (CVE-2022-23529) | CWE-1395, CWE-287 | `services/web/package.json:10` | open |
| CK-2026-043 | medium | The workflow grants write-all permissions to the token. | CWE-250 | `.github/workflows/ci.yml:5` | open |
| CK-2026-044 | medium | The container runs as root (no non-root USER in the final stage). | CWE-250 | `deploy/Dockerfile:1` | open |
| CK-2026-045 | medium | ADD fetches a remote URL with no integrity check; use COPY plus a verified download. | CWE-494 | `deploy/Dockerfile:3` | open |
| CK-2026-046 | medium | Service 'api' shares the host network namespace. | CWE-668 | `deploy/docker-compose.yml:5` | open |
| CK-2026-047 | medium | Pod security context runs as UID 0. | CWE-250 | `deploy/k8s/api.yaml:25` | open |
| CK-2026-048 | medium | Database 'ledger' storage is not encrypted. | CWE-311 | `infra/main.tf:18` | open |
| CK-2026-049 | medium | CORS allows every origin ('*'); any website can call this API from a user's browser. | CWE-942 | `services/api/settings.yaml:3` | open |
| CK-2026-050 | medium | Vulnerable dependency: express 4.16.0 (CVE-2024-29041, CVE-2024-43796) | CWE-1395, CWE-601, CWE-79 | `services/web/package.json:7` | open |
| CK-2026-051 | medium | Data from a http_param source reaches a html sink (res.send) | CWE-79 | `services/web/renderer.js:18` | open |
| CK-2026-052 | medium | RUN pipes a download straight into a shell without integrity verification. | CWE-494 | `deploy/Dockerfile:4` | open |
| CK-2026-053 | medium | Debug mode is enabled; it exposes stack traces and interactive consoles in production. | CWE-489 | `services/api/settings.yaml:2` | open |
| CK-2026-054 | medium | Data from a http_param source reaches a html sink (res.send) | CWE-79 | `services/web/renderer.js:22` | open |
| CK-2026-055 | low | Base image uses the floating 'latest' tag or no tag, so builds are not reproducible and may pull an unreviewed image. | CWE-1104 | `deploy/Dockerfile:1` | open |
| CK-2026-056 | low | Container 'api' has no resource limits. | CWE-770 | `deploy/k8s/api.yaml:21` | open |
| CK-2026-057 | low | Container 'api' uses a floating image tag. | CWE-1104 | `deploy/k8s/api.yaml:22` | open |
| CK-2026-058 | low | Action reference in job 'build' is not pinned to a commit SHA, so a moved tag changes what runs. | CWE-829 | `.github/workflows/ci.yml:10` | open |
| CK-2026-059 | low | Action reference in job 'build' is not pinned to a commit SHA, so a moved tag changes what runs. | CWE-829 | `.github/workflows/ci.yml:15` | open |

## Remediation roadmap

| Priority | Timeline | Action | Findings |
|---|---|---|---|
| P1 | Immediate (within 7 days) | Revoke and rotate the exposed credential immediately, then load it at run time from a secret manager or environment. | CK-2026-004, CK-2026-005, CK-2026-006, CK-2026-007, CK-2026-008, CK-2026-009, CK-2026-010, CK-2026-011, CK-2026-014 |
| P1 | Immediate (within 7 days) | Upgrade the component to a fixed version, or remove it if it is not needed. | CK-2026-015 |
| P1 | Immediate (within 7 days) | Use a safe loader (for example yaml.safe_load or JSON) that builds plain data only; never unpickle data from an untrusted source. | CK-2026-013 |
| P1 | Immediate (within 7 days) | Run the component as a non-root user, drop the privileged flag and grant only the capabilities it needs. | CK-2026-002 |
| P1 | Immediate (within 7 days) | Do not check out untrusted code in privileged workflows; pin third-party actions to a full commit SHA and reduce the token permissions. | CK-2026-001 |
| P1 | Immediate (within 7 days) | Stop passing the command to a shell: call the program with an argument list (shell=False) and validate each argument against a strict allow-list. | CK-2026-012 |
| P1 | Immediate (within 7 days) | Use parameterised queries or prepared statements for every value that reaches the query; never format user data into SQL text. | CK-2026-003 |
| P2 | Short term (within 30 days) | Upgrade the component to a fixed version, or remove it if it is not needed. | CK-2026-026, CK-2026-027, CK-2026-038, CK-2026-040, CK-2026-041, CK-2026-042 |
| P2 | Short term (within 30 days) | Run the component as a non-root user, drop the privileged flag and grant only the capabilities it needs. | CK-2026-018, CK-2026-019, CK-2026-021, CK-2026-022 |
| P2 | Short term (within 30 days) | Scope every lookup to the authenticated principal (for example WHERE owner_id = current_user) and return 404 for records the caller does not own. | CK-2026-032, CK-2026-036, CK-2026-037 |
| P2 | Short term (within 30 days) | Resolve the final path and reject it unless it lies inside an allow-listed base directory; prefer opaque identifiers mapped server-side to file names. | CK-2026-030, CK-2026-039 |
| P2 | Short term (within 30 days) | Revoke and rotate the exposed credential immediately, then load it at run time from a secret manager or environment. | CK-2026-017, CK-2026-020 |
| P2 | Short term (within 30 days) | Restrict the exposure to the intended network or principals. | CK-2026-025 |
| P2 | Short term (within 30 days) | Re-enable certificate and hostname verification. | CK-2026-028 |
| P2 | Short term (within 30 days) | Use at least 2048-bit RSA or 256-bit elliptic curves and AES-128 or stronger. | CK-2026-029 |
| P2 | Short term (within 30 days) | Tighten the permissions to the owning principal only. | CK-2026-023 |
| P2 | Short term (within 30 days) | Add the authentication and authorisation guard used elsewhere in the service to this route, defaulting to deny. | CK-2026-033 |
| P2 | Short term (within 30 days) | Stop passing the command to a shell: call the program with an argument list (shell=False) and validate each argument against a strict allow-list. | CK-2026-016 |
| P2 | Short term (within 30 days) | Generate a fresh random IV (or nonce) for every encryption with a CSPRNG and store it alongside the ciphertext. | CK-2026-035 |
| P2 | Short term (within 30 days) | Add the missing access check, denying by default. | CK-2026-024 |
| P2 | Short term (within 30 days) | Validate the destination against an allow-list of hosts and schemes and block private, loopback and link-local address ranges after DNS resolution. | CK-2026-031 |
| P2 | Short term (within 30 days) | Hash passwords with a slow, salted, memory-hard function such as Argon2id, scrypt or bcrypt, and migrate existing hashes on next login. | CK-2026-034 |
| P3 | Medium term (within 90 days) | Run the component as a non-root user, drop the privileged flag and grant only the capabilities it needs. | CK-2026-043, CK-2026-044, CK-2026-047 |
| P3 | Medium term (within 90 days) | Encode output for its HTML context (or use a template engine with auto-escaping) and never send raw request data with res.send or equivalent. | CK-2026-051, CK-2026-054 |
| P3 | Medium term (within 90 days) | Verify a pinned checksum or signature before executing downloaded artefacts. | CK-2026-045, CK-2026-052 |
| P3 | Medium term (within 90 days) | Disable debug mode and remove debug endpoints from production builds. | CK-2026-053 |
| P3 | Medium term (within 90 days) | Upgrade the component to a fixed version, or remove it if it is not needed. | CK-2026-050 |
| P3 | Medium term (within 90 days) | Restrict the exposure to the intended network or principals. | CK-2026-046 |
| P3 | Medium term (within 90 days) | Restrict allowed origins to a known list. | CK-2026-049 |
| P3 | Medium term (within 90 days) | Encrypt the data in transit with TLS and at rest with a managed key. | CK-2026-048 |
| P4 | Planned (next release cycle) | Do not check out untrusted code in privileged workflows; pin third-party actions to a full commit SHA and reduce the token permissions. | CK-2026-058, CK-2026-059 |
| P4 | Planned (next release cycle) | Pin the component to a reviewed version or digest and replace unmaintained components. | CK-2026-055, CK-2026-057 |
| P4 | Planned (next release cycle) | Set explicit limits (request size, rate, timeouts, container resources). | CK-2026-056 |

## Finding details

### CK-2026-001: A pull_request_target workflow checks out the pull request head, running untrusted code with repository secrets and a write token.

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-829 · **OWASP:** A08:2021 Software and Data Integrity Failures
- **Location:** `.github/workflows/ci.yml:12`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-002: Container 'api' is privileged.

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/k8s/api.yaml:24`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-003: Data from a http_param source reaches a sql sink (cur.execute)

- **Severity:** critical · **Risk:** 25 (critical) · **Confidence:** high
- **CWE:** CWE-89 · **OWASP:** A03:2021 Injection
- **Location:** `services/api/accounts.py:11`
- **Remediation:** If account_id is attacker-influenced, pass it separately using the database driver's parameterized-query API and its required placeholder syntax rather than formatting it into the SQL string.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-004: Hard-coded credential of type connection_string (masked preview po****** (51 chars), entropy 4.91 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/api/config.py:14`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-005: Hard-coded credential of type aws_access_key (masked preview AK****** (20 chars), entropy 3.68 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/api/config.py:16`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-006: Hard-coded credential of type private_key_block (masked preview --****** (313 chars), entropy 5.97 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-798, CWE-321 · **OWASP:** A07:2021 Identification and Authentication Failures, A02:2021 Cryptographic Failures
- **Location:** `services/api/config.py:20`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-007: Hard-coded credential of type razorpay_key_id (masked preview rz****** (23 chars), entropy 4.26 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/web/config.js:10`
- **Remediation:** 1. Revoke and rotate the exposed 'razorpayKeyId'/'razorpayKeySecret' credential pair immediately. 2. Store the replacements in a managed secrets service, or inject them as protected deployment environment variables. 3. Replace both literals with runtime lookups and do not provide hard-coded fallback values. 4. Validate at startup that both values are present and terminate without printing them if either is missing. 5. Remove the credentials from repository history, build artifacts, caches, and deployment bundles, then redeploy using the rotated values. 6. Ensure local secret files are excluded from version control and are not copied into container images.  Secure example: '''javascript razorpayKeyId: process.env.razorpayKeyId,   razorpayKeySecret: process.env.razorpayKeySecret, '''  Defence in depth: - Enable repository and CI secret scanning with push protection for future commits. - Restrict secret-store access to the application identity, use separate credentials per environment, and grant only required permissions. - Prevent configuration and environment values from appearing in logs, diagnostics, error reports, or support bundles.
- **Model assessment:** Confirmed vulnerable (gpt-5.6-sol)

### CK-2026-008: Hard-coded credential of type generic_credential (masked preview ad****** (12 chars), entropy 3.08 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** medium
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `deploy/docker-compose.yml:9`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-009: Hard-coded credential of type aws_secret_key (masked preview wJ****** (40 chars), entropy 4.66 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** medium
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/api/config.py:17`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-010: Hard-coded credential of type razorpay_key_secret (masked preview ab****** (24 chars), entropy 4.58 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** medium
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/api/config.py:18`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-011: Hard-coded credential of type generic_credential (masked preview hu****** (14 chars), entropy 2.81 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** medium
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/api/config.py:19`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-012: A shell command is built from variable parts that are not quoted.

- **Severity:** critical · **Risk:** 25 (critical) · **Confidence:** medium
- **CWE:** CWE-78 · **OWASP:** A03:2021 Injection
- **Location:** `services/api/reports.py:9`
- **Remediation:** If either parameter can be untrusted, avoid the shell and pass separate arguments, for example subprocess.run(["zip", "-x", archive_name, folder], check=True), while also handling option-like values according to the zip CLI's argument rules.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-013: Data is deserialised with a loader that can construct arbitrary objects.

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** medium
- **CWE:** CWE-502 · **OWASP:** A08:2021 Software and Data Integrity Failures
- **Location:** `services/api/serialisation.py:14`
- **Remediation:** If blob can be attacker-influenced, replace pickle with a non-executable format such as JSON plus strict schema validation. If pickle is unavoidable, accept only authenticated data from a trusted source before deserialization; type checks alone are insufficient.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-014: Hard-coded credential of type razorpay_key_secret (masked preview ab****** (24 chars), entropy 4.58 bits/char).

- **Severity:** critical · **Risk:** 20 (critical) · **Confidence:** medium
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/web/config.js:11`
- **Remediation:** 1. Revoke and rotate the exposed Razorpay key secret immediately. 2. Store the replacement in a managed secrets service or a protected deployment environment variable. 3. Replace the hard-coded 'razorpayKeySecret' value with runtime retrieval and do not provide a source-code fallback. 4. Validate during startup that the secret is present, and fail closed if it is missing. 5. Remove the credential from repository history, build artifacts, caches, and deployment bundles; do this in addition to rotation. 6. Redeploy with the rotated credential and verify that the old credential no longer works.  Secure example: '''javascript razorpayKeySecret: process.env.razorpayKeySecret, '''  Defence in depth: - Add pre-commit and CI secret scanning that blocks Razorpay credentials from entering source or artifacts. - Use separate, least-privilege credentials per environment and rotate them on a defined schedule. - Prevent configuration objects and environment variables from being written to application, CI, or deployment logs.
- **Model assessment:** Confirmed vulnerable (gpt-5.6-sol)

### CK-2026-015: Vulnerable dependency: PyYAML 5.3 (CVE-2020-14343)

- **Severity:** critical · **Risk:** 15 (high) · **Confidence:** low
- **CWE:** CWE-1395, CWE-20 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A03:2021 Injection
- **Location:** `services/api/requirements.txt:5`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-016: A run step in job 'build' interpolates attacker-controlled event data into a shell script; pass it through an environment variable instead.

- **Severity:** high · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-78 · **OWASP:** A03:2021 Injection
- **Location:** `.github/workflows/ci.yml:14`
- **Remediation:** Do not build commands, code or templates from untrusted input. Call the program directly with an argument list (for example subprocess.run([...], shell=False)) instead of a shell string, never pass request data to eval/exec or a template compiler, and validate input against a strict allow-list of expected values before it reaches the sink.

### CK-2026-017: ENV KB_DB_PASSWORD bakes a credential into the image layers; use a build secret or runtime injection.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `deploy/Dockerfile:5`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-018: Service 'api' runs privileged, giving it nearly full host access.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/docker-compose.yml:4`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-019: Service 'api' mounts the Docker socket, which is root on the host.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/docker-compose.yml:6`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-020: Service 'api' sets KB_ADMIN_PASSWORD to a literal in the compose file; use an env file or secret store.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-798 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `deploy/docker-compose.yml:8`
- **Remediation:** Remove the credential from source code and version history, rotate it immediately, and load secrets at run time from a secrets manager or the environment. Add secret scanning to the pre-commit hooks and CI so a new secret is caught before it is pushed.

### CK-2026-021: Pod shares the host network namespace.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/k8s/api.yaml:15`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-022: Pod mounts a hostPath volume, exposing the node filesystem.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/k8s/api.yaml:18`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-023: S3 bucket 'statements' uses a public ACL.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-732 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `infra/main.tf:3`
- **Remediation:** Enforce authorisation on the server for every request: check that the authenticated principal owns or may act on the referenced object (deny by default), derive the owner from the session rather than from request parameters, and centralise the check in a decorator or policy layer so no handler can skip it.

### CK-2026-024: Security group 'admin' allows ingress from the whole internet on an administrative or database port.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-284 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `infra/main.tf:11`
- **Remediation:** Enforce authorisation on the server for every request: check that the authenticated principal owns or may act on the referenced object (deny by default), derive the owner from the session rather than from request parameters, and centralise the check in a decorator or policy layer so no handler can skip it.

### CK-2026-025: Database 'ledger' is publicly accessible.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-668 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `infra/main.tf:19`
- **Remediation:** Do not write secrets, credentials, tokens or personal data to logs, error messages or URLs. Mask or omit sensitive fields at the logging boundary, return generic error messages to clients, and keep detailed diagnostics server-side.

### CK-2026-026: Vulnerable dependency: Flask 2.2.3 (CVE-2023-30861)

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-1395, CWE-539 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A04:2021 Insecure Design
- **Location:** `services/api/requirements.txt:2`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-027: Vulnerable dependency: requests 2.19.1 (CVE-2018-18074, CVE-2023-32681)

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-1395, CWE-522, CWE-200 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A04:2021 Insecure Design, A01:2021 Broken Access Control
- **Location:** `services/api/requirements.txt:4`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-028: TLS certificate verification is disabled, enabling man-in-the-middle attacks.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-295 · **OWASP:** A07:2021 Identification and Authentication Failures
- **Location:** `services/api/settings.yaml:4`
- **Remediation:** Use current, vetted primitives from a maintained library: AES-GCM or ChaCha20-Poly1305 for encryption with a fresh random nonce per message, SHA-256 or better for integrity, a password hashing function (Argon2id, scrypt, bcrypt) for passwords, and the operating system CSPRNG (Python secrets / os.urandom) for keys, tokens and IVs.

### CK-2026-029: A deprecated protocol version (SSLv2/3, TLS 1.0 or 1.1) is allowed.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-326 · **OWASP:** A02:2021 Cryptographic Failures
- **Location:** `services/api/settings.yaml:5`
- **Remediation:** Use current, vetted primitives from a maintained library: AES-GCM or ChaCha20-Poly1305 for encryption with a fresh random nonce per message, SHA-256 or better for integrity, a password hashing function (Argon2id, scrypt, bcrypt) for passwords, and the operating system CSPRNG (Python secrets / os.urandom) for keys, tokens and IVs.

### CK-2026-030: Data from a http_param source reaches a path sink (fs.createReadStream)

- **Severity:** high · **Risk:** 20 (critical) · **Confidence:** high
- **CWE:** CWE-22 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `services/web/exporter.js:9`
- **Remediation:** Resolve the candidate against a canonical base directory and reject it unless path.relative confirms it remains beneath that base. Prefer an allowlist of permitted filenames, and account for symlink escapes when untrusted users can affect filesystem entries.
- **Model assessment:** Confirmed vulnerable (gpt-5.6-sol)

### CK-2026-031: Data from a http_param source reaches a http sink (fetch)

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** high
- **CWE:** CWE-918 · **OWASP:** A10:2021 Server-Side Request Forgery (SSRF)
- **Location:** `services/web/payments.js:18`
- **Remediation:** If callers can supply attacker-influenced values, parse callbackUrl and restrict it to an explicit allowlist of schemes, hosts, and ports; reject credentials and private, loopback, link-local, and reserved destinations, including after DNS resolution and redirects.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-032: A record is fetched by an identifier from the caller with no ownership check.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** medium
- **CWE:** CWE-639 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `services/api/handlers.py:34`
- **Remediation:** Enforce authorisation on the server for every request: check that the authenticated principal owns or may act on the referenced object (deny by default), derive the owner from the session rather than from request parameters, and centralise the check in a decorator or policy layer so no handler can skip it.

### CK-2026-033: An account-scoped route has no authentication or authorisation check.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** medium
- **CWE:** CWE-862 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `services/api/handlers.py:39`
- **Remediation:** Enforce authorisation on the server for every request: check that the authenticated principal owns or may act on the referenced object (deny by default), derive the owner from the session rather than from request parameters, and centralise the check in a decorator or policy layer so no handler can skip it.

### CK-2026-034: A password is hashed with an algorithm that is broken or far too fast.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** medium
- **CWE:** CWE-327 · **OWASP:** A02:2021 Cryptographic Failures
- **Location:** `services/api/security.py:15`
- **Remediation:** If hash_password hashes passwords, replace MD5 with a password-hashing API using Argon2id, scrypt, bcrypt, or PBKDF2 with a unique salt and an appropriate work factor; otherwise document and constrain the function to its non-security checksum use.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-035: A block cipher is given a fixed initialisation vector instead of a random one.

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** medium
- **CWE:** CWE-329 · **OWASP:** A02:2021 Cryptographic Failures
- **Location:** `services/api/security.py:27`
- **Remediation:** If STATIC_IV is reused, generate a fresh unpredictable IV for every encryption and transmit it with the ciphertext; preferably use an authenticated-encryption mode such as AES-GCM.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-036: Handler takes an object id from the path: worth checking the caller owns it

- **Severity:** high · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-639, CWE-863 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `services/api/handlers.py:39`
- **Remediation:** Enforce authorisation on the server for every request: check that the authenticated principal owns or may act on the referenced object (deny by default), derive the owner from the session rather than from request parameters, and centralise the check in a decorator or policy layer so no handler can skip it.
- **Model assessment:** Undecided (gpt-5.6-sol)

### CK-2026-037: Handler takes an object id from the path: worth checking the caller owns it

- **Severity:** high · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-639, CWE-863 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `services/api/handlers.py:97`
- **Remediation:** Enforce authorisation on the server for every request: check that the authenticated principal owns or may act on the referenced object (deny by default), derive the owner from the session rather than from request parameters, and centralise the check in a decorator or policy layer so no handler can skip it.

### CK-2026-038: Vulnerable dependency: Jinja2 2.10 (CVE-2019-10906, CVE-2020-28493, CVE-2024-22195)

- **Severity:** high · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-1395, CWE-400, CWE-79 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A03:2021 Injection
- **Location:** `services/api/requirements.txt:3`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-039: Data from a http_param source reaches a path sink (fs.createReadStream)

- **Severity:** high · **Risk:** 16 (high) · **Confidence:** low
- **CWE:** CWE-22 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `services/web/exporter.js:19`
- **Remediation:** Do not use request data as a file path. Map user input to an identifier in an allow-list, or resolve the joined path (os.path.realpath / Path.resolve) and reject it unless it stays inside the intended base directory; use werkzeug.utils.safe_join or an equivalent helper.
- **Model assessment:** Assessed not vulnerable (gpt-5.6-sol)

### CK-2026-040: Vulnerable dependency: lodash 4.17.15 (CVE-2021-23337, CVE-2020-8203, CVE-2020-28500)

- **Severity:** high · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-1395, CWE-77, CWE-94, CWE-1321, CWE-1333 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A03:2021 Injection, A08:2021 Software and Data Integrity Failures
- **Location:** `services/web/package.json:8`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-041: Vulnerable dependency: axios 0.21.0 (CVE-2021-3749, CVE-2020-28168)

- **Severity:** high · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-1395, CWE-1333, CWE-918 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A10:2021 Server-Side Request Forgery (SSRF)
- **Location:** `services/web/package.json:9`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-042: Vulnerable dependency: jsonwebtoken 8.5.1 (CVE-2022-23529)

- **Severity:** high · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-1395, CWE-287 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A07:2021 Identification and Authentication Failures
- **Location:** `services/web/package.json:10`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-043: The workflow grants write-all permissions to the token.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `.github/workflows/ci.yml:5`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-044: The container runs as root (no non-root USER in the final stage).

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/Dockerfile:1`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-045: ADD fetches a remote URL with no integrity check; use COPY plus a verified download.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-494 · **OWASP:** A08:2021 Software and Data Integrity Failures
- **Location:** `deploy/Dockerfile:3`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-046: Service 'api' shares the host network namespace.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-668 · **OWASP:** A01:2021 Broken Access Control
- **Location:** `deploy/docker-compose.yml:5`
- **Remediation:** Do not write secrets, credentials, tokens or personal data to logs, error messages or URLs. Mask or omit sensitive fields at the logging boundary, return generic error messages to clients, and keep detailed diagnostics server-side.

### CK-2026-047: Pod security context runs as UID 0.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-250 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `deploy/k8s/api.yaml:25`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-048: Database 'ledger' storage is not encrypted.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-311 · **OWASP:** A04:2021 Insecure Design
- **Location:** `infra/main.tf:18`
- **Remediation:** Use current, vetted primitives from a maintained library: AES-GCM or ChaCha20-Poly1305 for encryption with a fresh random nonce per message, SHA-256 or better for integrity, a password hashing function (Argon2id, scrypt, bcrypt) for passwords, and the operating system CSPRNG (Python secrets / os.urandom) for keys, tokens and IVs.

### CK-2026-049: CORS allows every origin ('*'); any website can call this API from a user's browser.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-942 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `services/api/settings.yaml:3`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-050: Vulnerable dependency: express 4.16.0 (CVE-2024-29041, CVE-2024-43796)

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** high
- **CWE:** CWE-1395, CWE-601, CWE-79 · **OWASP:** A06:2021 Vulnerable and Outdated Components, A01:2021 Broken Access Control, A03:2021 Injection
- **Location:** `services/web/package.json:7`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-051: Data from a http_param source reaches a html sink (res.send)

- **Severity:** medium · **Risk:** 15 (high) · **Confidence:** high
- **CWE:** CWE-79 · **OWASP:** A03:2021 Injection
- **Location:** `services/web/renderer.js:18`
- **Remediation:** 1. Add a maintained HTML-encoding library such as 'escape-html' as a direct dependency. 2. Convert 'req.query.name' to a string and encode it immediately before insertion into the HTML text context. 3. Keep encoding context-specific; use the appropriate encoder if the value is later placed in an attribute, URL, CSS, or JavaScript context. 4. Prefer an auto-escaping template engine for larger HTML responses.  Secure example: '''javascript res.send(   '&lt;xx&gt;xxxxxxx xxxx, ' +   require('escape-html')(String(req.query.name ?? '')) +   '&lt;/xx&gt;' ); '''  Defence in depth: - Apply a restrictive Content-Security-Policy that disallows inline scripts. - Validate the field's type, length, and expected business format before rendering it; validation does not replace output encoding. - Add regression tests with HTML metacharacters and executable-markup payloads to verify they are displayed only as text.
- **Model assessment:** Confirmed vulnerable (gpt-5.6-sol)

### CK-2026-052: RUN pipes a download straight into a shell without integrity verification.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** medium
- **CWE:** CWE-494 · **OWASP:** A08:2021 Software and Data Integrity Failures
- **Location:** `deploy/Dockerfile:4`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-053: Debug mode is enabled; it exposes stack traces and interactive consoles in production.

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** medium
- **CWE:** CWE-489 · **OWASP:** A05:2021 Security Misconfiguration
- **Location:** `services/api/settings.yaml:2`
- **Remediation:** Ship secure defaults: disable debug mode in production, set Secure, HttpOnly and SameSite on session cookies, expire sessions, verify TLS certificates, and restrict CORS to the origins that need it.

### CK-2026-054: Data from a http_param source reaches a html sink (res.send)

- **Severity:** medium · **Risk:** 12 (high) · **Confidence:** low
- **CWE:** CWE-79 · **OWASP:** A03:2021 Injection
- **Location:** `services/web/renderer.js:22`
- **Remediation:** Encode untrusted data for the output context (HTML body, attribute, JavaScript, URL) using the template engine's auto-escaping, and never mark request data as safe (Markup, \|safe, dangerouslySetInnerHTML, innerHTML). Add a restrictive Content-Security-Policy as defence in depth.
- **Model assessment:** Assessed not vulnerable (gpt-5.6-sol)

### CK-2026-055: Base image uses the floating 'latest' tag or no tag, so builds are not reproducible and may pull an unreviewed image.

- **Severity:** low · **Risk:** 8 (medium) · **Confidence:** high
- **CWE:** CWE-1104 · **OWASP:** A06:2021 Vulnerable and Outdated Components
- **Location:** `deploy/Dockerfile:1`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-056: Container 'api' has no resource limits.

- **Severity:** low · **Risk:** 8 (medium) · **Confidence:** high
- **CWE:** CWE-770 · **OWASP:** A04:2021 Insecure Design
- **Location:** `deploy/k8s/api.yaml:21`
- **Remediation:** Bound every resource an attacker can drive: limit request and upload sizes, decompressed archive sizes and entry counts, use regular expressions without nested quantifiers (or a linear-time engine) on untrusted input, and set time-outs and rate limits.

### CK-2026-057: Container 'api' uses a floating image tag.

- **Severity:** low · **Risk:** 8 (medium) · **Confidence:** high
- **CWE:** CWE-1104 · **OWASP:** A06:2021 Vulnerable and Outdated Components
- **Location:** `deploy/k8s/api.yaml:22`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-058: Action reference in job 'build' is not pinned to a commit SHA, so a moved tag changes what runs.

- **Severity:** low · **Risk:** 8 (medium) · **Confidence:** medium
- **CWE:** CWE-829 · **OWASP:** A08:2021 Software and Data Integrity Failures
- **Location:** `.github/workflows/ci.yml:10`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

### CK-2026-059: Action reference in job 'build' is not pinned to a commit SHA, so a moved tag changes what runs.

- **Severity:** low · **Risk:** 8 (medium) · **Confidence:** medium
- **CWE:** CWE-829 · **OWASP:** A08:2021 Software and Data Integrity Failures
- **Location:** `.github/workflows/ci.yml:15`
- **Remediation:** Bind request data only to an explicit allow-list of fields (DTOs), never merge untrusted objects into prototypes or configuration, and load code and libraries only from fixed, trusted locations.

## Privacy attestation

- Privacy level: L3; provider none / none
- Ledger entries: 52; sent 25, blocked 2
- Ledger head: `fc5127cbb93a05fb615e7562d0dfd992cacc7fa1f6f3efb9a1be5eb28e6673c1`; chain verified: every entry links to its predecessor and its hash recomputes
- Zero-leak check: not checked in this run

