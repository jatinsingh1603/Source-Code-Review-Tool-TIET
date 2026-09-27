"""Configuration constants: file names, environment prefix, limits and schema identifiers.

Owning epic: E03.
"""

from typing import Final

PROJECT_FILE_NAME: Final = "codekavach.toml"
USER_FILE_NAME: Final = "config.toml"
POLICY_FILE_NAME: Final = "policy.toml"
POLICY_PUBKEY_FILE_NAME: Final = "policy.pub"
TRUST_STORE_FILE_NAME: Final = "trusted-projects.json"
STATE_DIR_NAME: Final = ".codekavach"
ENV_PREFIX: Final = "CODEKAVACH_"
ENV_NESTED_DELIMITER: Final = "__"
KEYRING_SERVICE: Final = "codekavach"
CONFIG_VERSION: Final = 1
POLICY_VERSION: Final = 1
MAX_CONFIG_BYTES: Final = 1_048_576
MAX_SECRET_FILE_BYTES: Final = 65_536

# Identifiers written into generated files; CodeKavach never fetches them.
_RAW_BASE: Final = (
    "https://raw.githubusercontent.com/jatinsingh1603/Source-Code-Review-Tool-TIET/main"
)
SCHEMA_ID: Final = f"{_RAW_BASE}/docs/schemas/codekavach.schema.json"
POLICY_SCHEMA_ID: Final = f"{_RAW_BASE}/docs/schemas/codekavach-policy.schema.json"
