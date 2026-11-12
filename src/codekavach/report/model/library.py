"""The local, CWE-keyed text library that seeds finding descriptions and remediation.

Owning epic: E30 (E30-02). The library is static data shipped with the package: no network, no
model. A finding's own text always leads; the library fills what the finding leaves empty, so a
report never prints an empty description, impact or remediation field. References point to public
MITRE and OWASP pages; they are printed as text and never fetched.
"""

from dataclasses import dataclass, field
from typing import Final


@dataclass(frozen=True)
class CweEntry:
    """What the report says about one weakness class when the finding says nothing more."""

    cwe: int
    name: str
    description: str
    impact: str
    short_term: str
    long_term: str
    effort: str = "medium"
    owasp: str | None = None
    asvs: tuple[str, ...] = ()
    capec: tuple[str, ...] = ()
    cheat_sheet: str | None = None
    extra_refs: tuple[tuple[str, str], ...] = field(default=())


OWASP_2021: Final[dict[str, str]] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"

_ENTRIES: Final[tuple[CweEntry, ...]] = (
    CweEntry(
        78,
        "OS Command Injection",
        "The application builds an operating-system command from data that an external party "
        "can influence and runs it through a shell. Shell metacharacters in that data change "
        "the command that is executed.",
        "An attacker can run arbitrary commands with the privileges of the application process, "
        "read or alter any data the process can reach, and use the host as a foothold for "
        "lateral movement.",
        "Stop passing the command to a shell: call the program with an argument list "
        "(shell=False) and validate each argument against a strict allow-list.",
        "Replace shell invocations with native library calls where possible, run the service "
        "with least privilege, and add a static-analysis gate that blocks shell=True and "
        "string-built commands.",
        "low",
        "A03:2021",
        ("V5.3.8",),
        ("CAPEC-88",),
        _CS + "OS_Command_Injection_Defense_Cheat_Sheet.html",
    ),
    CweEntry(
        77,
        "Command Injection",
        "A command is assembled from external input without neutralising the elements that "
        "change its meaning.",
        "An attacker can alter the command that is executed and run operations of their choice.",
        "Pass arguments separately from the command and validate them against an allow-list.",
        "Remove dynamic command construction from the design and enforce it with a lint rule.",
        "low",
        "A03:2021",
        ("V5.3.8",),
        ("CAPEC-248",),
        _CS + "OS_Command_Injection_Defense_Cheat_Sheet.html",
    ),
    CweEntry(
        89,
        "SQL Injection",
        "A database query is built by concatenating or interpolating data that an external "
        "party controls, so that data is parsed as SQL rather than treated as a value.",
        "An attacker can read, modify or delete database records outside their authorisation, "
        "bypass authentication and, on some engines, execute commands on the database host.",
        "Use parameterised queries or prepared statements for every value that reaches the "
        "query; never format user data into SQL text.",
        "Standardise on an ORM or query builder that parameterises by default, restrict the "
        "database account to the least privilege required, and add query-construction checks "
        "to code review and CI.",
        "low",
        "A03:2021",
        ("V5.3.4", "V5.3.5"),
        ("CAPEC-66",),
        _CS + "SQL_Injection_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        79,
        "Cross-site Scripting",
        "Data from the request is written into an HTML response without context-aware output "
        "encoding, so a browser may interpret it as markup or script.",
        "An attacker can execute script in a victim's browser session, steal session tokens, "
        "perform actions as the victim and deface or phish from a trusted origin.",
        "Encode output for its HTML context (or use a template engine with auto-escaping) and "
        "never send raw request data with res.send or equivalent.",
        "Adopt auto-escaping templates throughout, deploy a strict Content-Security-Policy, and "
        "set HttpOnly on session cookies.",
        "low",
        "A03:2021",
        ("V5.3.3",),
        ("CAPEC-63",),
        _CS + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        22,
        "Path Traversal",
        "A file-system path is built from data an external party controls without checking that "
        "the resolved path stays inside the intended directory.",
        "An attacker can read or overwrite files outside the intended directory, including "
        "configuration files, credentials and other customers' documents.",
        "Resolve the final path and reject it unless it lies inside an allow-listed base "
        "directory; prefer opaque identifiers mapped server-side to file names.",
        "Centralise file access behind a storage service that enforces containment, and run the "
        "process with a file-system view restricted to the data it needs.",
        "low",
        "A01:2021",
        ("V12.3.1",),
        ("CAPEC-126",),
        _CS + "File_Upload_Cheat_Sheet.html",
    ),
    CweEntry(
        918,
        "Server-Side Request Forgery",
        "The server issues an outbound request to a URL that the caller chooses, without "
        "restricting the destination.",
        "An attacker can make the server reach internal services, cloud metadata endpoints and "
        "administrative interfaces that are not exposed to the internet, leading to credential "
        "theft and internal reconnaissance.",
        "Validate the destination against an allow-list of hosts and schemes and block private, "
        "loopback and link-local address ranges after DNS resolution.",
        "Route outbound calls through an egress proxy with an allow-list, and enforce IMDSv2 or "
        "the equivalent metadata protection on cloud hosts.",
        "medium",
        "A10:2021",
        ("V12.6.1",),
        ("CAPEC-664",),
        _CS + "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        502,
        "Deserialisation of Untrusted Data",
        "Data from outside the trust boundary is deserialised with a loader that can instantiate "
        "arbitrary types or invoke code during loading.",
        "An attacker who controls the serialised data can typically achieve remote code "
        "execution, or at least tamper with application state.",
        "Use a safe loader (for example yaml.safe_load or JSON) that builds plain data only; "
        "never unpickle data from an untrusted source.",
        "Adopt data-only formats with schema validation at trust boundaries, and sign serialised "
        "objects that must round-trip through clients.",
        "low",
        "A08:2021",
        ("V5.5.1", "V5.5.3"),
        ("CAPEC-586",),
        _CS + "Deserialization_Cheat_Sheet.html",
    ),
    CweEntry(
        327,
        "Use of a Broken or Risky Cryptographic Algorithm",
        "The code relies on a cryptographic algorithm that is broken or unsuitable for its "
        "purpose, such as MD5 or SHA-1 for password storage.",
        "Protected data such as password hashes can be reversed or forged at low cost, exposing "
        "customer credentials after any database disclosure.",
        "Hash passwords with a slow, salted, memory-hard function such as Argon2id, scrypt or "
        "bcrypt, and migrate existing hashes on next login.",
        "Maintain an approved-algorithms list, wrap cryptography in a small vetted internal "
        "library, and add a CI check that rejects deprecated primitives.",
        "medium",
        "A02:2021",
        ("V2.4.1", "V6.2.2"),
        ("CAPEC-97",),
        _CS + "Password_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        328,
        "Use of Weak Hash",
        "A hash function that is too weak or too fast for its security purpose is used.",
        "Hashed values can be brute-forced or collided, defeating integrity or confidentiality.",
        "Replace the hash with a modern algorithm appropriate to the purpose.",
        "Maintain an approved-algorithms list enforced in CI.",
        "medium",
        "A02:2021",
        ("V6.2.2",),
        ("CAPEC-461",),
        _CS + "Cryptographic_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        916,
        "Password Hash With Insufficient Computational Effort",
        "Passwords are hashed with an algorithm that is too fast to resist offline guessing.",
        "Stolen hashes can be cracked at scale, exposing customer passwords that are often "
        "reused on other services.",
        "Use Argon2id, scrypt or bcrypt with a tuned work factor.",
        "Rehash existing passwords on login and monitor work-factor settings over time.",
        "medium",
        "A02:2021",
        ("V2.4.1",),
        ("CAPEC-55",),
        _CS + "Password_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        329,
        "Predictable Initialisation Vector",
        "A block cipher in a chaining mode is used with a fixed or predictable initialisation "
        "vector.",
        "Identical plaintexts produce identical ciphertexts and, in some modes, an attacker can "
        "recover or manipulate plaintext.",
        "Generate a fresh random IV (or nonce) for every encryption with a CSPRNG and store it "
        "alongside the ciphertext.",
        "Move to an authenticated encryption mode such as AES-GCM through a vetted library that "
        "manages nonces for you.",
        "low",
        "A02:2021",
        ("V6.2.5",),
        ("CAPEC-20",),
        _CS + "Cryptographic_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        639,
        "Authorisation Bypass Through User-Controlled Key (IDOR)",
        "A record is retrieved by an identifier supplied by the caller without verifying that "
        "the caller is entitled to that record.",
        "Any authenticated user can read or change other customers' records by changing the "
        "identifier in the request, a direct breach of confidentiality and integrity.",
        "Scope every lookup to the authenticated principal (for example WHERE owner_id = "
        "current_user) and return 404 for records the caller does not own.",
        "Enforce object-level authorisation in a shared data-access layer and add negative "
        "authorisation tests for every resource endpoint.",
        "medium",
        "A01:2021",
        ("V4.2.1",),
        ("CAPEC-122",),
        _CS + "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        862,
        "Missing Authorisation",
        "A route that acts on protected resources performs no authentication or authorisation "
        "check before doing so.",
        "Unauthenticated or under-privileged callers can invoke the operation directly, "
        "bypassing the access-control model.",
        "Add the authentication and authorisation guard used elsewhere in the service to this "
        "route, defaulting to deny.",
        "Make authorisation deny-by-default at the framework level so a new route is protected "
        "unless explicitly opened, and test it in CI.",
        "low",
        "A01:2021",
        ("V4.1.3", "V4.1.5"),
        ("CAPEC-665",),
        _CS + "Authorization_Cheat_Sheet.html",
    ),
    CweEntry(
        863,
        "Incorrect Authorisation",
        "An authorisation check exists but does not correctly restrict access to the resource.",
        "Callers can perform actions or access data beyond their privileges.",
        "Correct the check so it validates the caller's rights over the specific resource.",
        "Centralise authorisation decisions in a policy component with tests.",
        "medium",
        "A01:2021",
        ("V4.2.1",),
        ("CAPEC-233",),
        _CS + "Authorization_Cheat_Sheet.html",
    ),
    CweEntry(
        306,
        "Missing Authentication for Critical Function",
        "A critical function can be invoked without the caller proving their identity.",
        "Anyone who can reach the endpoint can perform the critical operation.",
        "Require authentication on the function and verify the session server-side.",
        "Adopt deny-by-default routing with explicit public allow-lists.",
        "low",
        "A07:2021",
        ("V4.1.1",),
        ("CAPEC-12",),
        _CS + "Authentication_Cheat_Sheet.html",
    ),
    CweEntry(
        798,
        "Use of Hard-coded Credentials",
        "A credential such as a password, API key or token is embedded in the source code.",
        "Anyone with access to the repository, a build artefact or a decompiled binary obtains "
        "the credential; rotating it requires a code change and redeployment.",
        "Revoke and rotate the exposed credential immediately, then load it at run time from a "
        "secret manager or environment.",
        "Adopt a secret manager, add pre-commit and CI secret scanning, and purge the value from "
        "version-control history.",
        "low",
        "A07:2021",
        ("V2.10.4", "V6.4.1"),
        ("CAPEC-191",),
        _CS + "Secrets_Management_Cheat_Sheet.html",
    ),
    CweEntry(
        259,
        "Use of Hard-coded Password",
        "A password is embedded in the source code.",
        "The password is disclosed to anyone with access to the code or artefacts.",
        "Rotate the password and load it from a secret manager.",
        "Enforce secret scanning in CI and purge history.",
        "low",
        "A07:2021",
        ("V2.10.4",),
        ("CAPEC-191",),
        _CS + "Secrets_Management_Cheat_Sheet.html",
    ),
    CweEntry(
        321,
        "Use of Hard-coded Cryptographic Key",
        "A cryptographic key is embedded in the source code.",
        "Data protected by the key can be decrypted or forged by anyone who obtains the code.",
        "Rotate the key and load it from a key-management service.",
        "Adopt a KMS with envelope encryption and key rotation.",
        "medium",
        "A02:2021",
        ("V6.4.1",),
        ("CAPEC-191",),
        _CS + "Key_Management_Cheat_Sheet.html",
    ),
    CweEntry(
        532,
        "Sensitive Information in Log Files",
        "Sensitive data such as credentials or personal data is written to logs.",
        "Log readers, log pipelines and third-party log services receive data they should not "
        "hold, widening the impact of any log compromise.",
        "Remove or mask the sensitive fields before logging.",
        "Adopt structured logging with a redaction filter and a data-classification policy.",
        "low",
        "A09:2021",
        ("V7.1.1",),
        ("CAPEC-215",),
        _CS + "Logging_Cheat_Sheet.html",
    ),
    CweEntry(
        611,
        "XML External Entity Reference",
        "An XML parser processes external entities in documents from an untrusted source.",
        "An attacker can read local files, perform SSRF or cause denial of service.",
        "Disable DTDs and external entity resolution in the parser configuration.",
        "Use hardened parser factories (for example defusedxml) project-wide.",
        "low",
        "A05:2021",
        ("V5.5.2",),
        ("CAPEC-221",),
        _CS + "XML_External_Entity_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        352,
        "Cross-Site Request Forgery",
        "A state-changing request is accepted without verifying that the user intended it.",
        "An attacker can cause a logged-in user's browser to perform actions on their behalf.",
        "Require an anti-CSRF token or SameSite cookies on state-changing requests.",
        "Enable framework CSRF protection globally.",
        "low",
        "A01:2021",
        ("V4.2.2",),
        ("CAPEC-62",),
        _CS + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        601,
        "Open Redirect",
        "The application redirects to a URL taken from the request without validation.",
        "Attackers can use the trusted domain to redirect victims to phishing pages.",
        "Redirect only to relative paths or allow-listed destinations.",
        "Replace URL parameters with server-side redirect identifiers.",
        "low",
        "A01:2021",
        ("V5.1.5",),
        ("CAPEC-194",),
        _CS + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ),
    CweEntry(
        94,
        "Code Injection",
        "Data from outside the trust boundary is evaluated as code.",
        "An attacker can execute arbitrary code in the application process.",
        "Remove eval-style evaluation of external data; parse data with a data-only parser.",
        "Ban dynamic code evaluation in lint rules.",
        "medium",
        "A03:2021",
        ("V5.2.4",),
        ("CAPEC-242",),
        _CS + "Injection_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        95,
        "Eval Injection",
        "Input is passed to an eval-style function.",
        "An attacker can execute arbitrary code.",
        "Remove eval of external input.",
        "Ban eval in lint rules.",
        "medium",
        "A03:2021",
        ("V5.2.4",),
        ("CAPEC-35",),
        _CS + "Injection_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        1336,
        "Server-Side Template Injection",
        "A template is built from data an external party controls and is then evaluated.",
        "An attacker can typically execute code on the server through the template engine.",
        "Pass user data to templates as context variables, never as template source.",
        "Use sandboxed template environments for any user-authored template.",
        "medium",
        "A03:2021",
        ("V5.2.5",),
        ("CAPEC-242",),
        _CS + "Injection_Prevention_Cheat_Sheet.html",
    ),
    CweEntry(
        200,
        "Exposure of Sensitive Information",
        "The application exposes sensitive information to an actor not authorised to see it.",
        "Disclosed data can be used directly or to plan further attacks.",
        "Remove the sensitive data from the response or restrict it to authorised callers.",
        "Classify data and enforce field-level filtering on outbound responses.",
        "low",
        "A01:2021",
        ("V8.3.1",),
        ("CAPEC-118",),
        None,
    ),
    CweEntry(
        209,
        "Information Exposure Through an Error Message",
        "Error responses include stack traces or internal details.",
        "Attackers learn internal structure, versions and paths that ease further attacks.",
        "Return generic error messages and log the details server-side.",
        "Install a global error handler that sanitises responses.",
        "low",
        "A05:2021",
        ("V7.4.1",),
        ("CAPEC-54",),
        _CS + "Error_Handling_Cheat_Sheet.html",
    ),
    CweEntry(
        295,
        "Improper Certificate Validation",
        "TLS certificate validation is disabled or incomplete.",
        "A network attacker can intercept and modify traffic.",
        "Re-enable certificate and hostname verification.",
        "Pin trust stores centrally and forbid verify=False in CI.",
        "low",
        "A07:2021",
        ("V9.2.1",),
        ("CAPEC-94",),
        _CS + "Transport_Layer_Security_Cheat_Sheet.html",
    ),
    CweEntry(
        330,
        "Use of Insufficiently Random Values",
        "A non-cryptographic random generator is used for a security-sensitive value.",
        "Tokens, identifiers or keys can be predicted by an attacker.",
        "Use a CSPRNG such as secrets or crypto.randomBytes.",
        "Wrap token generation in a shared vetted helper.",
        "low",
        "A02:2021",
        ("V6.3.1",),
        ("CAPEC-112",),
        _CS + "Cryptographic_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        338,
        "Use of Cryptographically Weak PRNG",
        "A weak pseudo-random generator is used in a security context.",
        "Generated secrets can be predicted.",
        "Use a CSPRNG.",
        "Ban weak PRNGs for security values in lint rules.",
        "low",
        "A02:2021",
        ("V6.3.1",),
        ("CAPEC-112",),
        None,
    ),
    CweEntry(
        434,
        "Unrestricted File Upload",
        "Files are accepted without validating type, size or destination.",
        "Attackers can upload executable content or exhaust storage.",
        "Validate type and size, rename files and store them outside the web root.",
        "Scan uploads and serve them from an isolated domain.",
        "medium",
        "A04:2021",
        ("V12.2.1",),
        ("CAPEC-1",),
        _CS + "File_Upload_Cheat_Sheet.html",
    ),
    CweEntry(
        287,
        "Improper Authentication",
        "The application does not sufficiently prove that a caller is who they claim to be.",
        "Attackers can impersonate other users.",
        "Use the framework's vetted authentication flow.",
        "Adopt MFA and centralised identity management.",
        "medium",
        "A07:2021",
        ("V2.1.1",),
        ("CAPEC-115",),
        _CS + "Authentication_Cheat_Sheet.html",
    ),
    CweEntry(
        312,
        "Cleartext Storage of Sensitive Information",
        "Sensitive data is stored without encryption.",
        "Anyone with access to the storage reads the data directly.",
        "Encrypt the data at rest with a managed key.",
        "Adopt a data-classification-driven encryption policy.",
        "medium",
        "A02:2021",
        ("V6.1.1",),
        ("CAPEC-37",),
        _CS + "Cryptographic_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        1004,
        "Sensitive Cookie Without HttpOnly",
        "A session cookie is set without the HttpOnly flag.",
        "Script injected into the page can read the session cookie.",
        "Set HttpOnly, Secure and SameSite on session cookies.",
        "Configure secure cookie defaults in the framework.",
        "low",
        "A05:2021",
        ("V3.4.2",),
        ("CAPEC-31",),
        _CS + "Session_Management_Cheat_Sheet.html",
    ),
    CweEntry(
        942,
        "Permissive Cross-domain Policy",
        "CORS is configured to trust any origin.",
        "Malicious sites can read authenticated responses.",
        "Restrict allowed origins to a known list.",
        "Manage CORS centrally per environment.",
        "low",
        "A05:2021",
        ("V14.5.3",),
        ("CAPEC-111",),
        None,
    ),
    CweEntry(
        250,
        "Execution with Unnecessary Privileges",
        "A process, container or job runs with more privileges than its function requires, "
        "for example as root or with a privileged container flag.",
        "Any other weakness in the component becomes a full host or cluster compromise, because "
        "the attacker inherits the excess privileges.",
        "Run the component as a non-root user, drop the privileged flag and grant only the "
        "capabilities it needs.",
        "Enforce least privilege with admission policies (for example Pod Security Standards) "
        "and image linting in CI.",
        "low",
        "A05:2021",
        ("V14.1.1",),
        ("CAPEC-69",),
        _CS + "Docker_Security_Cheat_Sheet.html",
    ),
    CweEntry(
        829,
        "Inclusion of Functionality from Untrusted Control Sphere",
        "The build or runtime executes code from a source outside the trust boundary, such as "
        "an untrusted pull request in a privileged CI workflow or an unpinned third-party action.",
        "An attacker can run code with the pipeline's secrets and write token, tamper with "
        "releases and pivot into the supply chain.",
        "Do not check out untrusted code in privileged workflows; pin third-party actions to a "
        "full commit SHA and reduce the token permissions.",
        "Separate untrusted builds from privileged jobs and review CI configuration as code.",
        "low",
        "A08:2021",
        ("V14.2.4",),
        ("CAPEC-175",),
        _CS + "CI_CD_Security_Cheat_Sheet.html",
    ),
    CweEntry(
        1395,
        "Dependency on Vulnerable Third-Party Component",
        "The project depends on a third-party component version with a published vulnerability.",
        "Attackers can exploit the known vulnerability, for which public exploit code is often "
        "available, without finding a flaw in the application's own code.",
        "Upgrade the component to a fixed version, or remove it if it is not needed.",
        "Run software composition analysis in CI, keep an SBOM, and automate dependency updates.",
        "low",
        "A06:2021",
        ("V14.2.1",),
        ("CAPEC-673",),
        _CS + "Vulnerable_Dependency_Management_Cheat_Sheet.html",
    ),
    CweEntry(
        1104,
        "Use of Unmaintained Third-Party Components",
        "A component is unpinned or no longer maintained, so fixes may never arrive and the "
        "version that is built can change without review.",
        "A compromised or abandoned upstream can introduce vulnerable or malicious code.",
        "Pin the component to a reviewed version or digest and replace unmaintained components.",
        "Maintain an approved-components list and monitor upstream health.",
        "low",
        "A06:2021",
        ("V14.2.1",),
        ("CAPEC-538",),
        _CS + "Vulnerable_Dependency_Management_Cheat_Sheet.html",
    ),
    CweEntry(
        494,
        "Download of Code Without Integrity Check",
        "Code or binaries are downloaded and executed without verifying a checksum or signature.",
        "A network attacker or compromised mirror can substitute malicious code that then runs "
        "with build or runtime privileges.",
        "Verify a pinned checksum or signature before executing downloaded artefacts.",
        "Use signed artefacts and a controlled internal mirror.",
        "low",
        "A08:2021",
        ("V10.3.2",),
        ("CAPEC-185",),
        None,
    ),
    CweEntry(
        668,
        "Exposure of Resource to Wrong Sphere",
        "A resource such as a port, bucket or service is exposed beyond its intended audience.",
        "Attackers outside the intended sphere can reach and abuse the resource.",
        "Restrict the exposure to the intended network or principals.",
        "Define exposure in reviewed infrastructure as code with deny-by-default policies.",
        "low",
        "A05:2021",
        ("V14.4.1",),
        ("CAPEC-1",),
        None,
    ),
    CweEntry(
        732,
        "Incorrect Permission Assignment for Critical Resource",
        "A critical resource is readable or writable by principals that should not have access.",
        "Unauthorised users can read secrets or alter configuration and code.",
        "Tighten the permissions to the owning principal only.",
        "Audit permissions in CI and use least-privilege defaults.",
        "low",
        "A01:2021",
        ("V4.1.3",),
        ("CAPEC-232",),
        None,
    ),
    CweEntry(
        284,
        "Improper Access Control",
        "Access to a resource is not restricted to authorised actors.",
        "Unauthorised actors can read or modify protected data or invoke protected functions.",
        "Add the missing access check, denying by default.",
        "Centralise access control and test it with negative cases.",
        "medium",
        "A01:2021",
        ("V4.1.1",),
        ("CAPEC-19",),
        _CS + "Authorization_Cheat_Sheet.html",
    ),
    CweEntry(
        326,
        "Inadequate Encryption Strength",
        "Encryption uses a key size or algorithm strength below current recommendations.",
        "Protected data can be decrypted by an attacker with moderate resources.",
        "Use at least 2048-bit RSA or 256-bit elliptic curves and AES-128 or stronger.",
        "Maintain an approved-algorithms list enforced in CI.",
        "low",
        "A02:2021",
        ("V6.2.1",),
        ("CAPEC-112",),
        _CS + "Cryptographic_Storage_Cheat_Sheet.html",
    ),
    CweEntry(
        311,
        "Missing Encryption of Sensitive Data",
        "Sensitive data is stored or transmitted without encryption.",
        "Anyone who can read the storage or the network traffic obtains the data.",
        "Encrypt the data in transit with TLS and at rest with a managed key.",
        "Classify data and enforce encryption requirements per class.",
        "medium",
        "A02:2021",
        ("V8.3.4",),
        ("CAPEC-157",),
        _CS + "Transport_Layer_Security_Cheat_Sheet.html",
    ),
    CweEntry(
        489,
        "Active Debug Code",
        "Debug features or debug mode are left enabled in deployable code.",
        "Debug endpoints and verbose errors disclose internals and can allow code execution.",
        "Disable debug mode and remove debug endpoints from production builds.",
        "Make production configuration the default and check it in CI.",
        "low",
        "A05:2021",
        ("V14.3.2",),
        ("CAPEC-121",),
        None,
    ),
    CweEntry(
        770,
        "Allocation of Resources Without Limits",
        "A resource such as memory, connections or request size is allocated without a limit.",
        "An attacker can exhaust the resource and deny service to legitimate users.",
        "Set explicit limits (request size, rate, timeouts, container resources).",
        "Adopt rate limiting and resource quotas as platform defaults.",
        "low",
        "A04:2021",
        ("V11.1.4",),
        ("CAPEC-125",),
        None,
    ),
)

LIBRARY: Final[dict[int, CweEntry]] = {entry.cwe: entry for entry in _ENTRIES}

GENERIC: Final = CweEntry(
    0,
    "Security weakness",
    "The code contains a pattern that weakens the security of the application.",
    "Depending on context, the weakness may allow an attacker to compromise the confidentiality, "
    "integrity or availability of the application or its data.",
    "Review the affected code and apply the secure coding practice for this weakness class.",
    "Add a regression test and a static-analysis rule so the pattern does not return.",
    "medium",
)


def lookup(cwes: tuple[int, ...]) -> CweEntry:
    """The library entry of the first known CWE in ``cwes``, or the generic entry."""
    for cwe in cwes:
        if cwe in LIBRARY:
            return LIBRARY[cwe]
    return GENERIC


def cwe_name(cwe: int) -> str:
    """The short name of ``cwe``, or ``CWE-<n>`` when the library does not know it."""
    entry = LIBRARY.get(cwe)
    return entry.name if entry else f"CWE-{cwe}"


def cwe_url(cwe: int) -> str:
    """The MITRE page of ``cwe``."""
    return f"https://cwe.mitre.org/data/definitions/{cwe}.html"
