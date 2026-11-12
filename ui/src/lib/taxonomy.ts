/** Short names for common CWEs (labels for the Top CWEs card when the list omits `cwe_name`). */
export const CWE_SHORT: Record<string, string> = {
  "CWE-20": "Input validation",
  "CWE-22": "Path traversal",
  "CWE-78": "OS command injection",
  "CWE-79": "Cross-site scripting",
  "CWE-89": "SQL injection",
  "CWE-94": "Code injection",
  "CWE-200": "Information exposure",
  "CWE-250": "Excess privilege",
  "CWE-259": "Hardcoded password",
  "CWE-269": "Privilege management",
  "CWE-284": "Access control",
  "CWE-285": "Improper authorisation",
  "CWE-287": "Improper authentication",
  "CWE-295": "Certificate validation",
  "CWE-306": "Missing authentication",
  "CWE-311": "Missing encryption",
  "CWE-312": "Cleartext storage",
  "CWE-319": "Cleartext transmission",
  "CWE-321": "Hardcoded key",
  "CWE-326": "Weak encryption",
  "CWE-327": "Broken crypto",
  "CWE-328": "Weak hash",
  "CWE-330": "Weak randomness",
  "CWE-338": "Weak PRNG",
  "CWE-352": "CSRF",
  "CWE-400": "Resource exhaustion",
  "CWE-434": "Unrestricted upload",
  "CWE-502": "Unsafe deserialisation",
  "CWE-532": "Secrets in logs",
  "CWE-601": "Open redirect",
  "CWE-611": "XXE",
  "CWE-639": "IDOR",
  "CWE-668": "Resource exposure",
  "CWE-732": "Permissions",
  "CWE-798": "Hardcoded credentials",
  "CWE-829": "Untrusted functionality",
  "CWE-862": "Missing authorisation",
  "CWE-863": "Incorrect authorisation",
  "CWE-915": "Mass assignment",
  "CWE-918": "SSRF",
  "CWE-937": "Vulnerable component",
  "CWE-1035": "Vulnerable component",
  "CWE-1104": "Unmaintained component",
  "CWE-1321": "Prototype pollution",
  "CWE-1333": "ReDoS",
  "CWE-1395": "Vulnerable dependency",
};

/** OWASP Top 10 category names per edition; rows of the Overview heatmap. */
export const OWASP_TOP10: Record<"2021" | "2025", [string, string][]> = {
  "2025": [
    ["A01", "Broken Access Control"],
    ["A02", "Security Misconfiguration"],
    ["A03", "Supply Chain Failures"],
    ["A04", "Cryptographic Failures"],
    ["A05", "Injection"],
    ["A06", "Insecure Design"],
    ["A07", "Authentication Failures"],
    ["A08", "Integrity Failures"],
    ["A09", "Logging and Alerting"],
    ["A10", "Exceptional Conditions"],
  ],
  "2021": [
    ["A01", "Broken Access Control"],
    ["A02", "Cryptographic Failures"],
    ["A03", "Injection"],
    ["A04", "Insecure Design"],
    ["A05", "Security Misconfiguration"],
    ["A06", "Vulnerable Components"],
    ["A07", "Authentication Failures"],
    ["A08", "Integrity Failures"],
    ["A09", "Logging and Monitoring"],
    ["A10", "Server-Side Request Forgery"],
  ],
};

/** "A03:2021 Injection" → { code: "A03", year: "2021" }. */
export function parseOwasp(s?: string | null): { code: string; year: string | null } | null {
  if (!s) return null;
  const m = /(A\d{2})(?::(\d{4}))?/.exec(s);
  if (!m) return null;
  return { code: m[1]!, year: m[2] ?? null };
}
