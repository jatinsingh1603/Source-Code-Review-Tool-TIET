import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings, parse_secret_ref, paths
from codekavach.config.env_source import RESERVED_ENV
from tests.support.config import (
    HARNESS_VARIABLES,
    ORG_POLICY_ENV,
    PROVIDER_VARIABLES,
    ConfigSandbox,
    isolate_config_env,
    memory_keyring_class,
    to_toml,
)
from tests.support.config_strategies import (
    SECTIONS,
    globs,
    layer_sets,
    provider_settings,
    secret_refs,
    section_dicts,
    settings_dicts,
)
from tests.support.strategies import fake_secrets
from tests.support.synthetic import SECRET_SHAPES, example_secret

REPO_ROOT = Path(__file__).resolve().parents[3]
POSIX = sys.platform != "win32"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# sandbox


def test_sandbox_writers(tmp_path: Path) -> None:
    sandbox = ConfigSandbox(tmp_path)
    assert (sandbox.root / ".git").is_dir()
    user = sandbox.write_user("[scan]\njobs = 2\n")
    project = sandbox.write_project("[scan]\njobs = 3\n", subdir="svc")
    policy = sandbox.write_policy("policy_version = 1\n")
    assert user == sandbox.home / "config.toml"
    assert project == sandbox.root / "svc" / "codekavach.toml"
    assert policy.parent == sandbox.outside
    assert sandbox.env[ORG_POLICY_ENV] == str(policy)
    assert sandbox.env["CODEKAVACH_HOME"] == str(sandbox.home)
    if POSIX:
        assert _mode(user) == 0o644
        assert _mode(sandbox.home) == 0o755


def test_sandbox_load_uses_both_layers(tmp_path: Path) -> None:
    sandbox = ConfigSandbox(tmp_path)
    sandbox.write_user("[scan]\njobs = 2\nmax_files = 7\n")
    sandbox.write_project("[scan]\njobs = 3\n")
    loaded = sandbox.load()
    assert loaded.settings.scan.jobs == 3
    assert loaded.settings.scan.max_files == 7
    assert loaded.user_config == sandbox.home / "config.toml"


# isolation


def test_isolation_hides_real_user_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_home = tmp_path / "real-home"
    real_config = real_home / ".config" / "codekavach" / "config.toml"
    real_config.parent.mkdir(parents=True)
    real_config.write_text("[scan]\njobs = 99\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(real_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(real_home / ".config"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", example_secret("anthropic_api_key"))
    monkeypatch.setenv("CODEKAVACH_SCAN__JOBS", "7")
    home = isolate_config_env(monkeypatch, tmp_path)
    assert os.environ["HOME"] == str(home)
    for name in PROVIDER_VARIABLES:
        assert name not in os.environ
    assert not [
        name
        for name in os.environ
        if name.startswith("CODEKAVACH_")
        and name != "CODEKAVACH_HOME"
        and name not in HARNESS_VARIABLES
    ]
    assert paths.system_policy_paths() == ()
    loaded = ConfigSandbox(tmp_path / "sandbox").load()
    assert loaded.user_config is None
    assert loaded.settings.scan.jobs == 0


def test_isolation_keeps_the_harness_variables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # CI sets a performance factor for the whole run; the budget tests under a config directory
    # must still see it, while every settings variable is removed.
    monkeypatch.setenv("CODEKAVACH_PERF_FACTOR", "3.0")
    monkeypatch.setenv("CODEKAVACH_SKIP_PERF", "1")
    monkeypatch.setenv("CODEKAVACH_SCAN__JOBS", "7")
    isolate_config_env(monkeypatch, tmp_path)
    assert os.environ["CODEKAVACH_PERF_FACTOR"] == "3.0"
    assert os.environ["CODEKAVACH_SKIP_PERF"] == "1"
    assert "CODEKAVACH_SCAN__JOBS" not in os.environ
    assert HARNESS_VARIABLES <= RESERVED_ENV  # the loader accepts them, so they cannot break a load


# keyring


def test_memory_keyring(memory_keyring: Any) -> None:
    keyring = pytest.importorskip("keyring")
    keyring.set_password("codekavach", "anthropic", "value-1")
    assert keyring.get_password("codekavach", "anthropic") == "value-1"
    keyring.delete_password("codekavach", "anthropic")
    assert keyring.get_password("codekavach", "anthropic") is None
    assert keyring.get_keyring() is memory_keyring


def test_memory_keyring_restores_previous_backend() -> None:
    keyring = pytest.importorskip("keyring")
    before = keyring.get_keyring()
    backend = memory_keyring_class()()
    keyring.set_keyring(backend)
    keyring.set_keyring(before)
    assert keyring.get_keyring() is before


def test_keyring_missing_raises_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setitem(sys.modules, "keyring.backend", None)
    with pytest.raises(ImportError):
        memory_keyring_class()


# synthetic additions

ADDED_KINDS = ("anthropic_api_key", "openai_project_key", "xai_api_key")


@pytest.mark.parametrize("kind", ADDED_KINDS)
def test_added_shapes(kind: str) -> None:
    shape = SECRET_SHAPES[kind]
    value = example_secret(kind)
    assert shape.pattern.fullmatch(value)
    body = value[len("".join(shape.prefix)) :]
    assert set(body) <= set(shape.alphabet)


@given(fake_secrets())
@settings(max_examples=300)
def test_fake_secrets_cover_added_kinds(pair: tuple[str, str]) -> None:
    kind, value = pair
    assert SECRET_SHAPES[kind].pattern.fullmatch(value)


def test_fake_secrets_draw_added_kinds() -> None:
    kinds: set[str] = set()

    @given(fake_secrets())
    @settings(max_examples=400, derandomize=True, database=None)
    def collect(pair: tuple[str, str]) -> None:
        kinds.add(pair[0])

    collect()
    assert set(ADDED_KINDS) <= kinds


def test_no_live_looking_tokens_in_tests() -> None:
    patterns = [
        re.compile("s" + r"k-ant-[A-Za-z0-9_-]{20,}"),
        re.compile("AI" + r"za[0-9A-Za-z_-]{35}"),
        re.compile("g" + r"h[pousr]_[A-Za-z0-9]{36,}"),
    ]
    offenders: list[str] = []
    for path in (REPO_ROOT / "tests").rglob("*"):
        if path.is_file() and path.suffix in {".py", ".toml", ".json", ".md", ".txt"}:
            text = path.read_text(encoding="utf-8", errors="ignore")
            offenders.extend(str(path) for p in patterns if p.search(text))
    assert offenders == []


# strategies


@given(secret_refs())
def test_secret_refs_are_valid(ref: str) -> None:
    parse_secret_ref(ref)


@given(globs())
def test_globs_are_relative(glob: str) -> None:
    assert not glob.startswith("/")
    assert ".." not in glob.split("/")


@given(provider_settings())
def test_provider_settings_validate(provider: dict[str, Any]) -> None:
    Settings.model_validate({"llm": {"providers": {"p": provider}}})


@pytest.mark.parametrize("name", SECTIONS)
@given(data=st.data())
def test_section_dicts_validate(name: str, data: st.DataObject) -> None:
    Settings.model_validate({name: data.draw(section_dicts(name))})


@given(settings_dicts())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_settings_dicts_validate(value: dict[str, Any]) -> None:
    Settings.model_validate(value)


@given(layer_sets())
@settings(
    max_examples=30,
    deadline=None,  # file I/O and the full loader; a cold first example can exceed 500 ms
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_layer_sets_load(tmp_path_factory: pytest.TempPathFactory, layers: Any) -> None:
    user, project = layers
    sandbox = ConfigSandbox(tmp_path_factory.mktemp("layers"))
    sandbox.write_user(to_toml(user))
    sandbox.write_project(to_toml(project))
    sandbox.load()
