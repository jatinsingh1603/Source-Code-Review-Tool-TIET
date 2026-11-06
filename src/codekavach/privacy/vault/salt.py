"""The scan salt store (ruling O-9).

Owning epic: E10.

``project`` mode (the default) returns the persistent per-project salt kept sealed in the vault
header, so one name gets one pseudonym in every scan of the project: stable pseudonyms, working
caches, reproducible experiments (I5). The cost is that a provider can link the requests of
different scans of the project (metric M8 of docs/research/INSIGHTS.md section 4.3).

``scan`` mode returns a salt derived from the project salt and the scan id. Scans cannot be linked
by their pseudonyms, but pseudonyms, caches and comparisons no longer carry over from scan to scan.
``privacy.pseudonym.link_mode = per_request`` goes one step further, at the cost of cache hits and
of reasoning across slices. None of the three is claimed to be safe; the leakage harness measures
them.

The salt is as sensitive as the vault: with it and the public code, pseudonyms of guessed names
can be recomputed. It is returned in the ``ScanSalt`` wrapper and never logged.
"""

import hashlib
import hmac
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final, Literal

from codekavach.config import Settings
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault

VAULT_DIR_NAME: Final = "vault"
VAULT_FILE_NAME: Final = "vault.db"
_SCAN_LABEL: Final = b"ck-scan-salt-v1\x00"


def vault_path(state_dir: Path) -> Path:
    """The vault file of the project whose state directory this is."""
    return state_dir / VAULT_DIR_NAME / VAULT_FILE_NAME


def get_or_create_salt(
    state_dir: Path,
    settings: Settings,
    *,
    scan_id: str,
    mode: Literal["project", "scan"] = "project",
    key: SecretBytes | None = None,
    prompt: Callable[[], str] | None = None,
    env: Mapping[str, str] | None = None,
) -> ScanSalt:
    """The salt for a scan: the project's own, or one derived from it and ``scan_id``."""
    if mode not in ("project", "scan"):
        raise ValueError("salt mode is 'project' or 'scan'")
    with Vault(
        vault_path(state_dir),
        KeySource(settings.privacy.vault.key_source),
        key,
        settings=settings,
        prompt=prompt,
        env=env,
    ) as vault:
        project = vault.salt()
    if mode == "project":
        return project
    derived = hmac.new(project.reveal(), _SCAN_LABEL + scan_id.encode(), hashlib.sha256)
    return ScanSalt(derived.digest())
