"""Where configuration files and the state directory live, and whether they can be trusted.

Owning epic: E03.

- The user directory is ``$CODEKAVACH_HOME``, else ``$XDG_CONFIG_HOME/codekavach``, else the
  platform's roaming configuration directory (platformdirs). It holds ``config.toml``, the trust
  store and the CLI's per-user state files; egress consent lives there because it is not a setting.
- Project discovery walks up from the scan target and stops at the first repository boundary
  (``.git`` file or directory), at the home directory and at the file-system root, so a
  ``codekavach.toml`` above the repository is never used (CWE-426, CWE-427).
- Trusted files get OpenSSH-style ownership and mode checks on POSIX (CWE-732); on Windows the
  checks are skipped because POSIX modes do not describe its ACLs.
- The state directory is created with mode ``0o700`` and a ``.gitignore`` containing ``*`` so that
  vault and ledger files are not committed by accident.
"""

import os
import stat
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import platformdirs

from codekavach.config.constants import PROJECT_FILE_NAME, TRUST_STORE_FILE_NAME, USER_FILE_NAME
from codekavach.config.errors import ConfigError, ConfigErrorCode

APP_NAME = "codekavach"
DATABASE_FILE_NAME = "codekavach.db"
STATE_DIR_MODE = 0o700
_GROUP_OTHER_WRITE = 0o022
_OTHER_WRITE = 0o002
_GROUP_OTHER_ACCESS = 0o077


def user_config_dir(env: Mapping[str, str]) -> Path:
    """The user configuration directory; first match of the documented order wins."""
    home = env.get("CODEKAVACH_HOME", "").strip()
    if home:
        return Path(home).expanduser()
    xdg = env.get("XDG_CONFIG_HOME", "").strip()
    if xdg and Path(xdg).is_absolute():  # the XDG specification ignores relative paths
        return Path(xdg) / APP_NAME
    return platformdirs.user_config_path(APP_NAME, appauthor=False, roaming=True)


def user_config_file(env: Mapping[str, str]) -> Path:
    """``config.toml`` in the user configuration directory."""
    return user_config_dir(env) / USER_FILE_NAME


def _start_dir(start: Path) -> Path:
    start = start.resolve()
    return start if start.is_dir() else start.parent


def find_project_config(start: Path, *, home: Path | None = None) -> Path | None:
    """The nearest ``codekavach.toml`` at or above ``start`` inside the repository boundary."""
    directory = _start_dir(start)
    home = (home if home is not None else Path.home()).resolve()
    while True:
        candidate = directory / PROJECT_FILE_NAME
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists() or directory in (home, directory.parent):
            return None
        directory = directory.parent


def project_root_for(start: Path) -> Path:
    """The directory of the discovered project file, else the repository root, else ``start``."""
    found = find_project_config(start)
    if found is not None:
        return found.parent
    base = _start_dir(start)
    for directory in (base, *base.parents):
        if (directory / ".git").exists():
            return directory
    return base


def _is_windows() -> bool:
    return os.name == "nt"


def _trusted_uids() -> set[int]:
    geteuid = getattr(os, "geteuid", None)  # absent on Windows, where callers return early
    return {0} if geteuid is None else {int(geteuid()), 0}


def _refuse(code: ConfigErrorCode, path: Path, reason: str, hint: str) -> ConfigError:
    return ConfigError.single(code, reason, source=str(path), hint=hint)


def check_trusted_file(
    path: Path, *, what: str, code: ConfigErrorCode = ConfigErrorCode.CK_CFG_005
) -> None:
    """Refuse a file another local user could have written (POSIX only; a no-op on Windows).

    The file (after following symlinks) must be owned by the effective user or root, and neither
    it nor its directory may be writable by group or others.

    Raises:
        ConfigError: with ``code`` when a rule is broken.
    """
    if _is_windows():
        return
    target = path.resolve()
    info = target.stat()
    if info.st_uid not in _trusted_uids():
        raise _refuse(
            code, path, f"{what} is owned by another user", f"run: chown $(id -u) {target}"
        )
    if info.st_mode & _GROUP_OTHER_WRITE:
        raise _refuse(
            code, path, f"{what} is writable by group or others", f"run: chmod go-w {target}"
        )
    if target.parent.stat().st_mode & _GROUP_OTHER_WRITE:
        raise _refuse(
            code,
            path,
            f"the directory of {what} is writable by group or others",
            f"run: chmod go-w {target.parent}",
        )


def check_discovered_project_file(path: Path, start: Path) -> None:
    """Refuse a project file found above ``start`` that another local user may have planted.

    Files in ``start`` itself are exempt. POSIX only; a no-op on Windows.

    Raises:
        ConfigError: CK-CFG-005 when the file has a foreign owner or its directory is writable
            by others (sticky bit or not).
    """
    if _is_windows() or path.resolve().parent == _start_dir(start):
        return
    hint = "pass --config explicitly or move the file into the scanned directory"
    if path.stat().st_uid not in _trusted_uids():
        raise _refuse(
            ConfigErrorCode.CK_CFG_005, path, "discovered project file has another owner", hint
        )
    if path.resolve().parent.stat().st_mode & _OTHER_WRITE:
        raise _refuse(
            ConfigErrorCode.CK_CFG_005,
            path,
            "discovered project file is in a directory writable by others",
            hint,
        )


def resolve_state_dir(root: Path, state_dir: Path) -> Path:
    """``state_dir`` joined to ``root`` when relative, unchanged when absolute."""
    return state_dir if state_dir.is_absolute() else root / state_dir


def _unsafe_state(path: Path, reason: str) -> ConfigError:
    return _refuse(ConfigErrorCode.CK_CFG_070, path, reason, "choose another project.state_dir")


def ensure_state_dir(path: Path) -> Path:
    """Create or tighten the state directory and its self-ignoring ``.gitignore``; idempotent.

    Raises:
        ConfigError: CK-CFG-070 when the path is a symlink or exists and is not a directory.
    """
    if path.is_symlink():
        raise _unsafe_state(path, "state directory is a symbolic link")
    if path.exists() and not path.is_dir():
        raise _unsafe_state(path, "state directory path exists and is not a directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir(mode=STATE_DIR_MODE)
    except FileExistsError:
        if path.is_symlink() or not path.is_dir():
            raise _unsafe_state(path, "state directory changed while it was created") from None
    if not _is_windows() and stat.S_IMODE(path.stat().st_mode) != STATE_DIR_MODE:
        path.chmod(STATE_DIR_MODE)
    ignore = path / ".gitignore"
    if not ignore.exists() and not ignore.is_symlink():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(ignore, flags, 0o600)
        except FileExistsError:
            return path
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("*\n")
    return path


def default_database_path(state_dir: Path) -> Path:
    """The one local database file of CodeKavach (bootstrapped by E04-25)."""
    return state_dir / DATABASE_FILE_NAME


def system_policy_paths() -> tuple[Path, ...]:
    """Organisation policy locations, most specific first; no variable changes this list."""
    platform = sys.platform  # read at call time so that tests can simulate other platforms
    if platform == "win32":
        program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return (Path(program_data) / "CodeKavach" / "policy.toml",)
    if platform == "darwin":
        return (
            Path("/Library/Application Support/CodeKavach/policy.toml"),
            Path("/etc/codekavach/policy.toml"),
        )
    return (Path("/etc/codekavach/policy.toml"),)


# --- what ``codekavach config path`` shows (E03-36) --------------------------------------------

ORG_POLICY_ENV = "CODEKAVACH_ORG_POLICY"
ORG_POLICY_PUBKEY_ENV = "CODEKAVACH_ORG_POLICY_PUBKEY"
DEFAULT_STATE_DIR = ".codekavach"


@dataclass(frozen=True, slots=True)
class PathEntry:
    """One location the loader considers."""

    label: str
    path: Path | None
    exists: bool
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ConfigPaths:
    """Every location the loader considers for one target, without creating anything."""

    user_config: PathEntry
    project_root: PathEntry
    project_config: PathEntry
    state_dir: PathEntry
    database: PathEntry
    system_policies: tuple[PathEntry, ...]
    org_policy: PathEntry
    policy_public_key: PathEntry
    trust_store: PathEntry

    def entries(self) -> list[PathEntry]:
        """All entries in display order."""
        return [
            self.user_config,
            self.project_root,
            self.project_config,
            self.state_dir,
            self.database,
            *self.system_policies,
            self.org_policy,
            self.policy_public_key,
            self.trust_store,
        ]


def _entry(label: str, path: Path | None, note: str | None = None) -> PathEntry:
    return PathEntry(label, path, path is not None and path.exists(), note)


def _raw_state_dir(project_file: Path | None) -> tuple[str | None, bool]:
    """``project.state_dir`` from the raw project file, and whether the file parsed."""
    if project_file is None:
        return None, True
    try:
        data = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None, False
    project = data.get("project")
    value = project.get("state_dir") if isinstance(project, Mapping) else None
    return (value if isinstance(value, str) and value else None), True


def collect_paths(target: Path, env: Mapping[str, str]) -> ConfigPaths:
    """Every location the loader would consider for ``target``; reads, never creates.

    Works when the configuration would not validate: of the project file only the one key
    ``project.state_dir`` is read, and a file that does not parse is reported, not raised.
    """
    root = project_root_for(target)
    project_file = find_project_config(target)
    state_value, parsed = _raw_state_dir(project_file)
    project_note = None if project_file is None or parsed else "does not parse"
    state = resolve_state_dir(root, Path(state_value or DEFAULT_STATE_DIR))
    policy = env.get(ORG_POLICY_ENV, "").strip()
    pubkey = env.get(ORG_POLICY_PUBKEY_ENV, "").strip()
    return ConfigPaths(
        user_config=_entry("user config", user_config_file(env)),
        project_root=_entry("project root", root),
        project_config=_entry(
            "project config", project_file, project_note if project_file else "none found"
        ),
        state_dir=_entry(
            "state directory", state, None if state.exists() else "created on first scan"
        ),
        database=_entry("database", default_database_path(state)),
        system_policies=tuple(
            _entry("organisation policy", path) for path in system_policy_paths()
        ),
        org_policy=_entry(
            "policy (variable)",
            Path(policy).expanduser() if policy else None,
            None if policy else f"{ORG_POLICY_ENV} is not set",
        ),
        policy_public_key=_entry(
            "policy public key",
            Path(pubkey).expanduser() if pubkey else None,
            None if pubkey else f"{ORG_POLICY_PUBKEY_ENV} is not set",
        ),
        trust_store=_entry("trust store", user_config_dir(env) / TRUST_STORE_FILE_NAME),
    )
