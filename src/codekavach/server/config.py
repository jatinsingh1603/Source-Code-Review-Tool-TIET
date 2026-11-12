"""Run-time configuration of the REST API server (``codekavach serve``).

Owning epic: E32.

``ServerConfig`` is built once by the ``serve`` command (or by a test) and handed to
``create_app``. Everything the server writes lives below ``data_dir``: the server database, the
per-scan workspaces, uploaded archives, the server key and the vault passphrase file. Nothing in
this module reads a provider key; provider credentials stay secret references resolved by the
pipeline at use time.
"""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import platformdirs

ADMIN_PASSWORD_ENV: Final = "CODEKAVACH_ADMIN_PASSWORD"  # noqa: S105 - a variable name
DEFAULT_ADMIN_PASSWORD: Final = "kavach-admin"  # noqa: S105 - documented demo default
DEV_ENV: Final = "CODEKAVACH_DEV"
DATA_DIR_ENV: Final = "CODEKAVACH_SERVER_DATA_DIR"
VAULT_PASSPHRASE_ENV: Final = "CODEKAVACH_SERVER_VAULT_PASSPHRASE"  # noqa: S105 - a variable name
DEV_ORIGINS: Final = ("http://localhost:5173", "http://127.0.0.1:5173")
FILE_MODE: Final = 0o600
DIR_MODE: Final = 0o700


def default_data_dir() -> Path:
    """``$CODEKAVACH_SERVER_DATA_DIR`` or the platform data directory plus ``server``."""
    configured = os.environ.get(DATA_DIR_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(platformdirs.user_data_dir("codekavach")) / "server"


def repo_root() -> Path | None:
    """The checkout this package runs from, when it runs from one (``fixtures/`` present)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "fixtures" / "kavachbank").is_dir() and (parent / "pyproject.toml").is_file():
            return parent
    return None


def default_ui_dir() -> Path | None:
    """The built dashboard (``ui/dist``) of the checkout, when it exists."""
    root = repo_root()
    if root is not None and (root / "ui" / "dist" / "index.html").is_file():
        return root / "ui" / "dist"
    return None


def sample_project_dir() -> Path | None:
    """The KavachBank sample project shipped in ``fixtures/``."""
    root = repo_root()
    if root is not None:
        return root / "fixtures" / "kavachbank"
    candidate = Path.cwd() / "fixtures" / "kavachbank"
    return candidate if candidate.is_dir() else None


@dataclass
class ServerConfig:
    """Settings of one server process."""

    data_dir: Path = field(default_factory=default_data_dir)
    ui_dir: Path | None = field(default_factory=default_ui_dir)
    workers: int = 2
    admin_password: str = field(
        default_factory=lambda: os.environ.get(ADMIN_PASSWORD_ENV) or DEFAULT_ADMIN_PASSWORD
    )
    dev: bool = field(default_factory=lambda: os.environ.get(DEV_ENV, "") in {"1", "true", "yes"})
    cors_origins: tuple[str, ...] = ()
    token_ttl_seconds: int = 12 * 3600
    login_attempts_per_minute: int = 10
    max_upload_bytes: int = 200 * 1024 * 1024
    max_extracted_bytes: int = 1024 * 1024 * 1024
    max_archive_entries: int = 50_000
    max_compression_ratio: int = 200
    git_allowed_hosts: tuple[str, ...] = ("github.com", "gitlab.com", "bitbucket.org")
    allow_local_paths: bool = True
    seed: bool = True
    sample_dir: Path | None = field(default_factory=sample_project_dir)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir).expanduser().resolve()

    @property
    def db_path(self) -> Path:
        """The server database file."""
        return self.data_dir / "server.db"

    @property
    def scans_dir(self) -> Path:
        """Per-scan workspaces (source copy, state directory, reports, events)."""
        return self.data_dir / "scans"

    @property
    def uploads_dir(self) -> Path:
        """Uploaded project archives."""
        return self.data_dir / "uploads"

    @property
    def home_dir(self) -> Path:
        """``CODEKAVACH_HOME`` of the scans the server runs."""
        return self.data_dir / "home"

    def effective_cors_origins(self) -> tuple[str, ...]:
        """The configured origins, plus the Vite dev origin when ``CODEKAVACH_DEV=1``."""
        return self.cors_origins + (DEV_ORIGINS if self.dev else ())

    def prepare(self) -> None:
        """Create the data directory tree with owner-only permissions."""
        for path in (self.data_dir, self.scans_dir, self.uploads_dir, self.home_dir):
            path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                path.chmod(DIR_MODE)

    def secret_file(self, name: str, *, size: int = 32) -> str:
        """A random hex secret kept in ``data_dir/<name>`` (created on first use, mode 0600)."""
        path = self.data_dir / name
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
        value = secrets.token_hex(size)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
        return value
