"""Application configuration checks: debug mode, wildcard CORS and weak TLS."""

import re
from typing import Final

from codekavach.analysis.iac.common import Issue
from codekavach.core.models import Confidence, Severity

_NAME: Final = re.compile(
    r"(^|/)(\.env[\w.]*|[\w.-]*(config|settings|application|appsettings)[\w.-]*"
    r"\.(ya?ml|json|toml|ini|cfg|conf|properties|py|js|ts|env)|[\w.-]+\.(ini|cfg|conf|properties))$",
    re.I,
)
_RULES: Final = (
    (
        "iac.appconfig.debug-enabled",
        Severity.MEDIUM,
        489,
        Confidence.MEDIUM,
        "Debug mode is enabled; it exposes stack traces and interactive consoles in production.",
        re.compile(
            r"""(?i)^\s*["']?(debug|app_debug|flask_debug|django_debug)["']?\s*[:=]\s*["']?(true|1|yes|on)["']?\s*,?\s*(#.*|//.*)?$"""
        ),
    ),
    (
        "iac.appconfig.cors-wildcard",
        Severity.MEDIUM,
        942,
        Confidence.HIGH,
        "CORS allows every origin ('*'); any website can call this API from a user's browser.",
        re.compile(
            r"""(?i)(cors[\w.-]*(origin|origins)|allowed[_-]?origins?|access-control-allow-origin)["']?\s*[:=,(]\s*\[?\s*["']\*["']"""
        ),
    ),
    (
        "iac.appconfig.tls-verification-disabled",
        Severity.HIGH,
        295,
        Confidence.HIGH,
        "TLS certificate verification is disabled, enabling man-in-the-middle attacks.",
        re.compile(
            r"""(?i)["']?(verify[_-]?ssl|ssl[_-]?verify|tls[_-]?verify|verify_certs?|rejectUnauthorized|strict[_-]?ssl|check_hostname|NODE_TLS_REJECT_UNAUTHORIZED)["']?\s*[:=]\s*["']?(false|0|no|off)["']?"""
        ),
    ),
    (
        "iac.appconfig.weak-tls-version",
        Severity.HIGH,
        326,
        Confidence.HIGH,
        "A deprecated protocol version (SSLv2/3, TLS 1.0 or 1.1) is allowed.",
        re.compile(
            r"""(?i)(ssl[_-]?version|min[_-]?tls[_-]?version|tls[_-]?min[_-]?version|ssl_protocols?|minVersion|PROTOCOL_)[^\n]*?(SSLv?[23]\b|TLSv?1(\.[01])?\b(?![.\d])|TLSv1_[01]\b|tls1\.[01]\b)"""
        ),
    ),
    (
        "iac.appconfig.insecure-cookie",
        Severity.MEDIUM,
        614,
        Confidence.MEDIUM,
        "Session cookie is not marked Secure.",
        re.compile(
            r"""(?i)["']?(session_cookie_secure|cookie[_-]?secure|secure_cookies?)["']?\s*[:=]\s*["']?(false|0)["']?"""
        ),
    ),
)


def is_config_path(path: str) -> bool:
    """True for files that conventionally hold application configuration."""
    return _NAME.search(path) is not None


def check_appconfig(text: str) -> list[Issue]:
    """Line-based checks; each issue names a rule and a line, never the line's content."""
    issues: list[Issue] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 400 or line.lstrip().startswith(("#", "//")):
            continue
        for rule, severity, cwe, confidence, message, pattern in _RULES:
            if pattern.search(line):
                issues.append(Issue(rule, number, severity, cwe, message, confidence))
    return issues
