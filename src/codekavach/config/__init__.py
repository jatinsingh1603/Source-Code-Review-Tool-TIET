"""Configuration: settings models, loader, profiles and key handling.

Owning epic: E03. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.config.keys import SecretRef, parse_secret_ref
from codekavach.config.loader import LoadedConfig, load_settings
from codekavach.config.masking import mask_settings
from codekavach.config.models.root import Settings
from codekavach.config.provenance import Layer, Origin

__all__ = [
    "ConfigError",
    "ConfigErrorCode",
    "ConfigIssue",
    "Layer",
    "LoadedConfig",
    "Origin",
    "SecretRef",
    "Settings",
    "load_settings",
    "mask_settings",
    "parse_secret_ref",
]
