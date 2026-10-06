"""Shared test support for configuration code (E03-15).

- ``ConfigSandbox`` and the ``config_sandbox`` fixture: a project root, a user configuration home
  and an outside directory, all under ``tmp_path``, with writers for the three kinds of file.
- ``isolate_config_env`` and the autouse ``_isolate_config_env`` fixture: every test module under
  a ``config`` directory runs without ``CODEKAVACH_*`` settings or provider variables (the harness
  variables ``CODEKAVACH_PERF_FACTOR`` and friends are kept), with ``HOME`` and
  ``CODEKAVACH_HOME`` under ``tmp_path`` and no system organisation policy paths, so a test can
  never read the developer's real configuration, keys or policy.
- ``MemoryKeyring`` and the ``memory_keyring`` fixture: an in-memory keyring backend, so tests
  never unlock the developer's OS keyring. The fixture skips when ``keyring`` is not installed.

Registered through ``pytest_plugins`` in ``tests/conftest.py``.
"""

import importlib
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import paths
from codekavach.config.constants import POLICY_FILE_NAME, PROJECT_FILE_NAME, USER_FILE_NAME
from codekavach.config.loader import LoadedConfig, load_settings

PROVIDER_VARIABLES = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "XAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "XDG_CONFIG_HOME",
)
ORG_POLICY_ENV = "CODEKAVACH_ORG_POLICY"
# Variables of the test harness, not settings: the loader recognises them (``RESERVED_ENV``) and
# the budget tests need CI's ``CODEKAVACH_PERF_FACTOR``, so isolation leaves them alone.
HARNESS_VARIABLES = frozenset(
    {"CODEKAVACH_PERF_FACTOR", "CODEKAVACH_SKIP_PERF", "CODEKAVACH_UPDATE_SNAPSHOTS"}
)
FILE_MODE = 0o644
DIR_MODE = 0o755


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_scalar(item) for item in value) + "]"
    return json.dumps(str(value), ensure_ascii=False)


def to_toml(data: dict[str, Any], prefix: str = "") -> str:
    """Serialise nested test data (tables, arrays of tables, scalars) to TOML text.

    A small writer for fixtures only; the loader reads the result with ``tomllib``.
    """
    lines: list[str] = []
    sections: list[str] = []
    for key, value in data.items():
        name = f"{prefix}.{json.dumps(key)}" if prefix else json.dumps(key)
        if isinstance(value, dict):
            sections.append(f"[{name}]\n" + to_toml(value, name))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            sections.extend(f"[[{name}]]\n" + to_toml(item, name) for item in value)
        elif value is not None:
            lines.append(f"{json.dumps(key)} = {_scalar(value)}\n")
    return "".join(lines) + "".join(sections)


def _mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(DIR_MODE)
    return path


def _write(path: Path, text: str) -> Path:
    _mkdir(path.parent)
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(FILE_MODE)
    return path


class ConfigSandbox:
    """A throw-away project, user home and outside directory for configuration tests."""

    def __init__(self, base: Path) -> None:
        self.root = _mkdir(base / "project")
        _mkdir(self.root / ".git")
        self.home = _mkdir(base / "home")
        self.outside = _mkdir(base / "outside")
        self.env: dict[str, str] = {"CODEKAVACH_HOME": str(self.home)}

    def write_user(self, toml_text: str) -> Path:
        """Write the user configuration file under ``home``."""
        return _write(self.home / USER_FILE_NAME, toml_text)

    def write_project(self, toml_text: str, *, subdir: str = "") -> Path:
        """Write ``codekavach.toml`` in the project root or one of its sub-directories."""
        directory = self.root / subdir if subdir else self.root
        return _write(directory / PROJECT_FILE_NAME, toml_text)

    def write_policy(self, toml_text: str, *, name: str = POLICY_FILE_NAME) -> Path:
        """Write an organisation policy outside the root and point the environment at it."""
        path = _write(self.outside / name, toml_text)
        self.env[ORG_POLICY_ENV] = str(path)
        return path

    def load(self, **kwargs: Any) -> LoadedConfig:
        """``load_settings(target=root, env=self.env, **kwargs)``."""
        return load_settings(target=self.root, env=self.env, **kwargs)


@pytest.fixture
def config_sandbox(tmp_path: Path) -> ConfigSandbox:
    """A fresh ``ConfigSandbox`` under ``tmp_path``."""
    return ConfigSandbox(tmp_path / "sandbox")


def isolate_config_env(monkeypatch: pytest.MonkeyPatch, base: Path) -> Path:
    """Hide the real user environment; return the redirected home directory."""
    for name in list(os.environ):
        if name in HARNESS_VARIABLES:
            continue
        if name.startswith("CODEKAVACH_") or name in PROVIDER_VARIABLES:
            monkeypatch.delenv(name, raising=False)
    home = _mkdir(base / "isolated-home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))
    monkeypatch.setenv("CODEKAVACH_HOME", str(_mkdir(home / "codekavach")))
    monkeypatch.setattr(paths, "system_policy_paths", lambda: ())
    return home


@pytest.fixture(autouse=True)
def _isolate_config_env(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Active for every test module that lives under a ``config`` directory."""
    if "config" not in Path(str(request.path)).parent.parts:
        return
    base = request.getfixturevalue("tmp_path")
    isolate_config_env(monkeypatch, base)


def memory_keyring_class() -> type[Any]:
    """Build ``MemoryKeyring`` on top of ``keyring.backend.KeyringBackend``.

    Raises:
        ImportError: ``keyring`` is not installed.
    """
    backend = importlib.import_module("keyring.backend")

    class MemoryKeyring(backend.KeyringBackend):  # type: ignore[misc,name-defined]
        """Dictionary storage; priority 1 so it is never chosen automatically."""

        priority = 1

        def __init__(self) -> None:
            super().__init__()
            self.store: dict[tuple[str, str], str] = {}

        def get_password(self, service: str, username: str) -> str | None:
            return self.store.get((service, username))

        def set_password(self, service: str, username: str, password: str) -> None:
            self.store[(service, username)] = password

        def delete_password(self, service: str, username: str) -> None:
            errors = importlib.import_module("keyring.errors")
            if (service, username) not in self.store:
                raise errors.PasswordDeleteError(username)
            del self.store[(service, username)]

    return MemoryKeyring


@pytest.fixture
def memory_keyring() -> Iterator[Any]:
    """Install a ``MemoryKeyring`` and restore the previous backend afterwards."""
    try:
        keyring = importlib.import_module("keyring")
        memory = memory_keyring_class()()
    except ImportError:
        pytest.skip("keyring is not installed")
    previous = keyring.get_keyring()
    keyring.set_keyring(memory)
    try:
        yield memory
    finally:
        keyring.set_keyring(previous)
