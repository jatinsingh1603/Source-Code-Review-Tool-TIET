# Rule coverage

Generated from the shipped pack by `python -m codekavach.analysis.rules.coverage`;
do not edit by hand.

Pack `default` version 1.0.0: 74 rules. A category or weakness is
covered for a language when at least one rule of that language names it in its
metadata; the count is rules, not findings, and says nothing about recall. A scan with
no finding in an uncovered row means the rules did not look, not that the code is safe.
OWASP names follow the 2021 edition; the weakness list is the CWE Top 25 of 2025.
Memory-safety rules carry A03:2021 (Injection) as the nearest 2021 category, which has
no memory-safety entry of its own.

## Rules per language

| Language | Rules | Hotspots |
|---|---|---|
| python | 38 | 2 |
| javascript | 25 | 1 |
| c | 11 | 0 |
| cpp | 11 | 0 |

## python

### OWASP Top 10 (2021)

| Category | Rules | Status |
|---|---|---|
| A01:2021 Broken Access Control | 4 | covered |
| A02:2021 Cryptographic Failures | 10 | covered |
| A03:2021 Injection | 11 | covered |
| A04:2021 Insecure Design | 3 | covered |
| A05:2021 Security Misconfiguration | 4 | covered |
| A06:2021 Vulnerable and Outdated Components | 0 | not covered |
| A07:2021 Identification and Authentication Failures | 2 | covered |
| A08:2021 Software and Data Integrity Failures | 2 | covered |
| A09:2021 Security Logging and Monitoring Failures | 1 | covered |
| A10:2021 Server-Side Request Forgery | 1 | covered |

### CWE Top 25 (2025)

| CWE | Weakness | Rules | Status |
|---|---|---|---|
| CWE-79 | Cross-site Scripting | 2 | covered |
| CWE-89 | SQL Injection | 2 | covered |
| CWE-352 | Cross-Site Request Forgery | 0 | not covered: needs knowledge of the framework's CSRF middleware across files |
| CWE-862 | Missing Authorization | 1 | covered |
| CWE-787 | Out-of-bounds Write | 0 | not applicable: a memory-safe language |
| CWE-22 | Path Traversal | 1 | covered |
| CWE-416 | Use After Free | 0 | not applicable: a memory-safe language |
| CWE-125 | Out-of-bounds Read | 0 | not applicable: a memory-safe language |
| CWE-78 | OS Command Injection | 2 | covered |
| CWE-94 | Code Injection | 0 | not covered: no rule yet |
| CWE-120 | Classic Buffer Overflow | 0 | not applicable: a memory-safe language |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 1 | covered |
| CWE-476 | NULL Pointer Dereference | 0 | not applicable: a memory-safe language |
| CWE-121 | Stack-based Buffer Overflow | 0 | not applicable: a memory-safe language |
| CWE-502 | Deserialization of Untrusted Data | 2 | covered |
| CWE-122 | Heap-based Buffer Overflow | 0 | not applicable: a memory-safe language |
| CWE-863 | Incorrect Authorization | 2 | covered |
| CWE-20 | Improper Input Validation | 0 | not covered: a generic weakness: rules map to the specific class instead |
| CWE-284 | Improper Access Control | 0 | not covered: a category weakness: rules map to CWE-862, CWE-863 and CWE-639 |
| CWE-200 | Exposure of Sensitive Information | 0 | not covered: needs data classification; belongs to the redaction layer and the reasoning step |
| CWE-306 | Missing Authentication for Critical Function | 0 | not covered: needs the application's authentication design; reported as an authorisation hotspot |
| CWE-918 | Server-Side Request Forgery | 1 | covered |
| CWE-77 | Command Injection | 0 | not covered: no rule yet |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 1 | covered |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 0 | not covered: needs resource-limit reasoning; not attempted by pattern rules |

## javascript

### OWASP Top 10 (2021)

| Category | Rules | Status |
|---|---|---|
| A01:2021 Broken Access Control | 3 | covered |
| A02:2021 Cryptographic Failures | 5 | covered |
| A03:2021 Injection | 8 | covered |
| A04:2021 Insecure Design | 1 | covered |
| A05:2021 Security Misconfiguration | 3 | covered |
| A06:2021 Vulnerable and Outdated Components | 0 | not covered |
| A07:2021 Identification and Authentication Failures | 1 | covered |
| A08:2021 Software and Data Integrity Failures | 2 | covered |
| A09:2021 Security Logging and Monitoring Failures | 1 | covered |
| A10:2021 Server-Side Request Forgery | 1 | covered |

### CWE Top 25 (2025)

| CWE | Weakness | Rules | Status |
|---|---|---|---|
| CWE-79 | Cross-site Scripting | 3 | covered |
| CWE-89 | SQL Injection | 1 | covered |
| CWE-352 | Cross-Site Request Forgery | 0 | not covered: needs knowledge of the framework's CSRF middleware across files |
| CWE-862 | Missing Authorization | 1 | covered |
| CWE-787 | Out-of-bounds Write | 0 | not applicable: a memory-safe language |
| CWE-22 | Path Traversal | 1 | covered |
| CWE-416 | Use After Free | 0 | not applicable: a memory-safe language |
| CWE-125 | Out-of-bounds Read | 0 | not applicable: a memory-safe language |
| CWE-78 | OS Command Injection | 1 | covered |
| CWE-94 | Code Injection | 0 | not covered: no rule yet |
| CWE-120 | Classic Buffer Overflow | 0 | not applicable: a memory-safe language |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 0 | not covered: no rule yet |
| CWE-476 | NULL Pointer Dereference | 0 | not applicable: a memory-safe language |
| CWE-121 | Stack-based Buffer Overflow | 0 | not applicable: a memory-safe language |
| CWE-502 | Deserialization of Untrusted Data | 1 | covered |
| CWE-122 | Heap-based Buffer Overflow | 0 | not applicable: a memory-safe language |
| CWE-863 | Incorrect Authorization | 1 | covered |
| CWE-20 | Improper Input Validation | 0 | not covered: a generic weakness: rules map to the specific class instead |
| CWE-284 | Improper Access Control | 0 | not covered: a category weakness: rules map to CWE-862, CWE-863 and CWE-639 |
| CWE-200 | Exposure of Sensitive Information | 0 | not covered: needs data classification; belongs to the redaction layer and the reasoning step |
| CWE-306 | Missing Authentication for Critical Function | 0 | not covered: needs the application's authentication design; reported as an authorisation hotspot |
| CWE-918 | Server-Side Request Forgery | 1 | covered |
| CWE-77 | Command Injection | 0 | not covered: no rule yet |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 0 | not covered: no rule yet |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 0 | not covered: needs resource-limit reasoning; not attempted by pattern rules |

## c

### OWASP Top 10 (2021)

| Category | Rules | Status |
|---|---|---|
| A01:2021 Broken Access Control | 1 | covered |
| A02:2021 Cryptographic Failures | 1 | covered |
| A03:2021 Injection | 9 | covered |
| A04:2021 Insecure Design | 0 | not covered |
| A05:2021 Security Misconfiguration | 0 | not covered |
| A06:2021 Vulnerable and Outdated Components | 0 | not covered |
| A07:2021 Identification and Authentication Failures | 0 | not covered |
| A08:2021 Software and Data Integrity Failures | 0 | not covered |
| A09:2021 Security Logging and Monitoring Failures | 0 | not covered |
| A10:2021 Server-Side Request Forgery | 0 | not covered |

### CWE Top 25 (2025)

| CWE | Weakness | Rules | Status |
|---|---|---|---|
| CWE-79 | Cross-site Scripting | 0 | not covered: no rule yet |
| CWE-89 | SQL Injection | 0 | not covered: no rule yet |
| CWE-352 | Cross-Site Request Forgery | 0 | not covered: needs knowledge of the framework's CSRF middleware across files |
| CWE-862 | Missing Authorization | 0 | not covered: no rule yet |
| CWE-787 | Out-of-bounds Write | 2 | covered |
| CWE-22 | Path Traversal | 0 | not covered: no rule yet |
| CWE-416 | Use After Free | 1 | covered |
| CWE-125 | Out-of-bounds Read | 0 | not covered: out-of-bounds reads need bounds reasoning that pattern rules do not have |
| CWE-78 | OS Command Injection | 1 | covered |
| CWE-94 | Code Injection | 0 | not covered: no rule yet |
| CWE-120 | Classic Buffer Overflow | 4 | covered |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 0 | not covered: no rule yet |
| CWE-476 | NULL Pointer Dereference | 1 | covered |
| CWE-121 | Stack-based Buffer Overflow | 0 | not covered: stack versus heap placement is not decided by a pattern; see CWE-120 and CWE-787 |
| CWE-502 | Deserialization of Untrusted Data | 0 | not covered: no rule yet |
| CWE-122 | Heap-based Buffer Overflow | 0 | not covered: stack versus heap placement is not decided by a pattern; see CWE-120 and CWE-787 |
| CWE-863 | Incorrect Authorization | 0 | not covered: no rule yet |
| CWE-20 | Improper Input Validation | 0 | not covered: a generic weakness: rules map to the specific class instead |
| CWE-284 | Improper Access Control | 0 | not covered: a category weakness: rules map to CWE-862, CWE-863 and CWE-639 |
| CWE-200 | Exposure of Sensitive Information | 0 | not covered: needs data classification; belongs to the redaction layer and the reasoning step |
| CWE-306 | Missing Authentication for Critical Function | 0 | not covered: needs the application's authentication design; reported as an authorisation hotspot |
| CWE-918 | Server-Side Request Forgery | 0 | not covered: no rule yet |
| CWE-77 | Command Injection | 0 | not covered: no rule yet |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 0 | not covered: no rule yet |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 0 | not covered: needs resource-limit reasoning; not attempted by pattern rules |

## cpp

### OWASP Top 10 (2021)

| Category | Rules | Status |
|---|---|---|
| A01:2021 Broken Access Control | 1 | covered |
| A02:2021 Cryptographic Failures | 1 | covered |
| A03:2021 Injection | 9 | covered |
| A04:2021 Insecure Design | 0 | not covered |
| A05:2021 Security Misconfiguration | 0 | not covered |
| A06:2021 Vulnerable and Outdated Components | 0 | not covered |
| A07:2021 Identification and Authentication Failures | 0 | not covered |
| A08:2021 Software and Data Integrity Failures | 0 | not covered |
| A09:2021 Security Logging and Monitoring Failures | 0 | not covered |
| A10:2021 Server-Side Request Forgery | 0 | not covered |

### CWE Top 25 (2025)

| CWE | Weakness | Rules | Status |
|---|---|---|---|
| CWE-79 | Cross-site Scripting | 0 | not covered: no rule yet |
| CWE-89 | SQL Injection | 0 | not covered: no rule yet |
| CWE-352 | Cross-Site Request Forgery | 0 | not covered: needs knowledge of the framework's CSRF middleware across files |
| CWE-862 | Missing Authorization | 0 | not covered: no rule yet |
| CWE-787 | Out-of-bounds Write | 2 | covered |
| CWE-22 | Path Traversal | 0 | not covered: no rule yet |
| CWE-416 | Use After Free | 1 | covered |
| CWE-125 | Out-of-bounds Read | 0 | not covered: out-of-bounds reads need bounds reasoning that pattern rules do not have |
| CWE-78 | OS Command Injection | 1 | covered |
| CWE-94 | Code Injection | 0 | not covered: no rule yet |
| CWE-120 | Classic Buffer Overflow | 4 | covered |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 0 | not covered: no rule yet |
| CWE-476 | NULL Pointer Dereference | 1 | covered |
| CWE-121 | Stack-based Buffer Overflow | 0 | not covered: stack versus heap placement is not decided by a pattern; see CWE-120 and CWE-787 |
| CWE-502 | Deserialization of Untrusted Data | 0 | not covered: no rule yet |
| CWE-122 | Heap-based Buffer Overflow | 0 | not covered: stack versus heap placement is not decided by a pattern; see CWE-120 and CWE-787 |
| CWE-863 | Incorrect Authorization | 0 | not covered: no rule yet |
| CWE-20 | Improper Input Validation | 0 | not covered: a generic weakness: rules map to the specific class instead |
| CWE-284 | Improper Access Control | 0 | not covered: a category weakness: rules map to CWE-862, CWE-863 and CWE-639 |
| CWE-200 | Exposure of Sensitive Information | 0 | not covered: needs data classification; belongs to the redaction layer and the reasoning step |
| CWE-306 | Missing Authentication for Critical Function | 0 | not covered: needs the application's authentication design; reported as an authorisation hotspot |
| CWE-918 | Server-Side Request Forgery | 0 | not covered: no rule yet |
| CWE-77 | Command Injection | 0 | not covered: no rule yet |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 0 | not covered: no rule yet |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 0 | not covered: needs resource-limit reasoning; not attempted by pattern rules |
