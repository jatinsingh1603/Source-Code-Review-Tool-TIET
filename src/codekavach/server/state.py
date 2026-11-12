"""The state one server process shares between requests and workers, and first-start seeding.

Owning epic: E32.

``ServerState`` holds the configuration, the database, the event hub, the job runner and the login
rate limiter. ``bootstrap`` prepares the data directory, generates the server's vault passphrase
file on first start (mode 0600, kept in the process environment only as the value of
``CODEKAVACH_SERVER_VAULT_PASSPHRASE``), seeds the ``admin`` account and the
"KavachBank (sample)" project, and fails over scans orphaned by a previous process.
"""

import os
import secrets
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Final

from sqlalchemy import func, select

from codekavach.core.log import get_logger
from codekavach.server.auth.passwords import hash_password
from codekavach.server.config import VAULT_PASSPHRASE_ENV, ServerConfig
from codekavach.server.db.engine import Database
from codekavach.server.db.models import Project, SettingRow, User
from codekavach.server.events import EventHub

if TYPE_CHECKING:
    from codekavach.config import Settings

_log = get_logger("codekavach.server.state")

SAMPLE_PROJECT_ID: Final = "prj_kavachbank_sample"
SAMPLE_NAME: Final = "KavachBank (sample)"
SETTINGS_KEY: Final = "server"
POLICY_KEY: Final = "policy"
DEFAULT_SETTINGS: Final[dict[str, Any]] = {
    "default_provider": "mock",
    "default_model": None,
    "default_privacy_level": "L2",
    "org_name": "Thapar Institute of Engineering and Technology",
    "report_title": "Secure Source Code Review Report",
    "classification": "Confidential",
    "send_by_default": True,
}


def new_id(prefix: str) -> str:
    """A random identifier such as ``prj_3f9c...``."""
    return f"{prefix}_{secrets.token_hex(10)}"


class RateLimiter:
    """A sliding one-minute window per key (client address or user name)."""

    def __init__(self, per_minute: int, clock: Any = time.monotonic) -> None:
        self._limit = per_minute
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> float | None:
        """Record an attempt; returns seconds to wait when over the limit, else ``None``."""
        now = self._clock()
        with self._lock:
            window = self._hits.setdefault(key, deque())
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= self._limit:
                return float(max(1.0, 60.0 - (now - window[0])))
            window.append(now)
            return None

    def reset(self, key: str) -> None:
        """Forget the attempts of ``key`` (after a successful login)."""
        with self._lock:
            self._hits.pop(key, None)


class ServerState:
    """Everything a request handler or worker needs."""

    def __init__(self, config: ServerConfig) -> None:
        from codekavach.server.jobs.runner import JobRunner  # noqa: PLC0415

        self.config = config
        config.prepare()
        self.passphrase_env = VAULT_PASSPHRASE_ENV
        if not os.environ.get(VAULT_PASSPHRASE_ENV):
            os.environ[VAULT_PASSPHRASE_ENV] = config.secret_file("vault.passphrase")
        self.db = Database(config.db_path)
        self.hub = EventHub(config.scans_dir)
        self.login_limiter = RateLimiter(config.login_attempts_per_minute)
        self.runner: JobRunner = JobRunner(self, config.workers)
        self.started_at = time.time()

    # --- settings ------------------------------------------------------------------------

    def get_settings(self) -> dict[str, Any]:
        """The server settings merged over the defaults."""
        with self.db.transaction() as session:
            row = session.get(SettingRow, SETTINGS_KEY)
            stored = dict(row.value) if row is not None else {}
        return {**DEFAULT_SETTINGS, **stored}

    def put_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        """Store the known keys of ``values`` and return the merged settings."""
        current = self.get_settings()
        current.update({key: value for key, value in values.items() if key in DEFAULT_SETTINGS})
        with self.db.transaction() as session:
            row = session.get(SettingRow, SETTINGS_KEY)
            if row is None:
                session.add(SettingRow(key=SETTINGS_KEY, value=current))
            else:
                row.value = current
        return current

    def report_settings(self, settings: "Settings") -> "Settings":
        """``settings`` with the organisation name, title and classification of the server."""
        values = self.get_settings()
        reporting = settings.reporting.model_copy(
            update={
                "title": values.get("report_title") or settings.reporting.title,
                "auditor": values.get("org_name") or settings.reporting.auditor,
                "classification": values.get("classification") or settings.reporting.classification,
            }
        )
        return settings.model_copy(update={"reporting": reporting})

    # --- lifecycle -----------------------------------------------------------------------

    def bootstrap(self) -> dict[str, Any]:
        """Seed the admin user and the sample project when missing; recover orphaned scans."""
        seeded: dict[str, Any] = {"admin_created": False, "sample_created": False}
        with self.db.transaction() as session:
            users = session.scalar(select(func.count()).select_from(User)) or 0
            if users == 0:
                session.add(
                    User(
                        id=new_id("usr"),
                        username="admin",
                        full_name="Administrator",
                        role="admin",
                        password_hash=hash_password(self.config.admin_password),
                    )
                )
                seeded["admin_created"] = True
            if (
                self.config.seed
                and self.config.sample_dir is not None
                and session.get(Project, SAMPLE_PROJECT_ID) is None
            ):
                session.add(
                    Project(
                        id=SAMPLE_PROJECT_ID,
                        name=SAMPLE_NAME,
                        description="Synthetic banking application with planted vulnerabilities, "
                        "secrets and personal data; ships with CodeKavach for demonstrations.",
                        source_type="sample",
                    )
                )
                seeded["sample_created"] = True
        seeded["recovered_scans"] = self.runner.recover()
        return seeded

    def close(self) -> None:
        """Stop the workers and close the database."""
        self.runner.shutdown()
        self.db.dispose()
