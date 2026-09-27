"""Configuration: settings models, loader, profiles and key handling.

Owning epic: E03. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.config.keys import SecretRef, parse_secret_ref
from codekavach.config.models.root import Settings

__all__ = [
    "ConfigError",
    "ConfigErrorCode",
    "ConfigIssue",
    "SecretRef",
    "Settings",
    "parse_secret_ref",
]
