import logging
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from codekavach.config import ConfigError
from codekavach.config.errors import ConfigIssue, SecretResolutionError
from codekavach.config.keys import (
    DEFAULT_KEY_ENV,
    KEYRING_UNAVAILABLE_HINT,
    effective_key_refs,
    resolve_provider_key,
    resolve_secret,
    secret_status,
)
from codekavach.config.models.llm import ProviderSettings
from tests.support.synthetic import example_secret

POSIX = sys.platform != "win32"
REPO_ROOT = Path(__file__).resolve().parents[3]


def provider(kind: str, **extra: Any) -> ProviderSettings:
    fields: dict[str, Any] = {"kind": kind}
    if kind not in ("mock", "replay"):
        fields["model"] = "m"
    if kind in ("openai-compatible", "azure-openai"):
        fields["base_url"] = "https://llm.example.test/v1"
    if kind == "bedrock":
        fields["region"] = "eu-west-1"
    if kind == "replay":
        fields["cassette_dir"] = "cassettes"
    if kind == "cli-bridge":
        fields["command"] = ["bridge"]
    fields.update(extra)
    return ProviderSettings.model_validate(fields)


def code_of(exc: ConfigError) -> str:
    return exc.issues[0].code.value


# env


def test_env_set_and_not_set() -> None:
    value = example_secret("anthropic_api_key")
    assert resolve_secret("env:K", env={"K": value}).get_secret_value() == value
    for env in ({}, {"K": ""}):
        with pytest.raises(SecretResolutionError) as info:
            resolve_secret("env:K", env=env)
        assert code_of(info.value) == "CK-CFG-012"
    assert secret_status("env:K", env={}).state == "not-set"


def test_fresh_secretstr_each_call() -> None:
    env = {"K": "value-one"}
    assert resolve_secret("env:K", env=env) is not resolve_secret("env:K", env=env)


# keyring


def test_keyring_set_and_not_set(memory_keyring: Any) -> None:
    memory_keyring.set_password("codekavach", "primary", "stored-value")
    assert resolve_secret("keyring:codekavach/primary").get_secret_value() == "stored-value"
    assert resolve_secret("keyring:primary").get_secret_value() == "stored-value"
    assert secret_status("keyring:codekavach/other").state == "not-set"
    with pytest.raises(SecretResolutionError):
        resolve_secret("keyring:codekavach/other")


def test_keyring_backend_unavailable(memory_keyring: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    errors = pytest.importorskip("keyring.errors")

    def boom(service: str, username: str) -> str:
        raise errors.NoKeyringError

    monkeypatch.setattr(memory_keyring, "get_password", boom)
    status = secret_status("keyring:codekavach/primary")
    assert status.state == "backend-unavailable"
    assert status.detail == KEYRING_UNAVAILABLE_HINT
    with pytest.raises(SecretResolutionError) as info:
        resolve_secret("keyring:codekavach/primary")
    assert info.value.issues[0].hint == KEYRING_UNAVAILABLE_HINT


def test_plaintext_keyring_backend_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = pytest.importorskip("keyring")
    backend_module = pytest.importorskip("keyring.backend")
    fake_module = types.ModuleType("keyrings.alt.file")

    class PlaintextKeyring(backend_module.KeyringBackend):  # type: ignore[misc,name-defined]
        priority = 1

        def get_password(self, service: str, username: str) -> str:
            return "must-not-be-read"

        def set_password(self, service: str, username: str, password: str) -> None:
            raise NotImplementedError

        def delete_password(self, service: str, username: str) -> None:
            raise NotImplementedError

    PlaintextKeyring.__module__ = fake_module.__name__
    previous = keyring.get_keyring()
    keyring.set_keyring(PlaintextKeyring())
    try:
        with pytest.raises(SecretResolutionError) as info:
            resolve_secret("keyring:codekavach/primary")
        assert code_of(info.value) == "CK-CFG-014"
        assert "must-not-be-read" not in str(info.value)
    finally:
        keyring.set_keyring(previous)


# file


def write(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_file_strips_one_trailing_newline(tmp_path: Path) -> None:
    lf = write(tmp_path / "lf", b"value\n\n")
    crlf = write(tmp_path / "crlf", b"value\r\n")
    assert resolve_secret(f"file:{lf}").get_secret_value() == "value\n"
    assert resolve_secret(f"file:{crlf}").get_secret_value() == "value"


def test_file_inside_project_refused(tmp_path: Path) -> None:
    root = tmp_path / "project"
    secret = write(root / "keys" / "k.txt", b"value")
    with pytest.raises(SecretResolutionError) as info:
        resolve_secret(f"file:{secret}", project_root=root)
    assert code_of(info.value) == "CK-CFG-012"
    assert "repository" in (info.value.issues[0].hint or "")


def test_file_readable_by_others_warns(tmp_path: Path) -> None:
    path = write(tmp_path / "k", b"value", 0o644)
    warnings: list[ConfigIssue] = []
    assert resolve_secret(f"file:{path}", warnings=warnings).get_secret_value() == "value"
    if POSIX:
        assert [w.code.value for w in warnings] == ["CK-CFG-013"]
        assert warnings[0].severity == "warning"


@pytest.mark.parametrize(
    ("data", "message"),
    [(b"x" * 65_537, "larger"), (b"\xff\xfe\x00", "UTF-8")],
    ids=["oversized", "not-utf8"],
)
def test_file_errors(tmp_path: Path, data: bytes, message: str) -> None:
    path = write(tmp_path / "k", data)
    with pytest.raises(SecretResolutionError, match=message):
        resolve_secret(f"file:{path}")
    assert secret_status(f"file:{path}").state == "error"


def test_missing_file_and_directory(tmp_path: Path) -> None:
    assert secret_status(f"file:{tmp_path / 'missing'}").state == "not-set"
    with pytest.raises(SecretResolutionError, match="regular file"):
        resolve_secret(f"file:{tmp_path}")


# providers


@pytest.mark.parametrize(
    ("kind", "names"),
    [
        ("anthropic", ("ANTHROPIC_API_KEY",)),
        ("openai", ("OPENAI_API_KEY",)),
        ("gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
        ("xai", ("XAI_API_KEY",)),
        ("azure-openai", ("AZURE_OPENAI_API_KEY",)),
        ("github", ("GITHUB_TOKEN", "GH_TOKEN")),
    ],
)
def test_defaults_table(kind: str, names: tuple[str, ...]) -> None:
    assert DEFAULT_KEY_ENV[kind] == names
    assert effective_key_refs(kind, None) == tuple(f"env:{n}" for n in names)
    assert effective_key_refs(kind, "keyring:x") == ("keyring:x",)


@pytest.mark.parametrize(
    "kind", ["bedrock", "ollama", "openai-compatible", "litellm", "cli-bridge", "mock", "replay"]
)
def test_kinds_without_default(kind: str) -> None:
    assert effective_key_refs(kind, None) == ()
    assert resolve_provider_key("p", provider(kind), env={}) is None


def test_provider_key_from_default_variable() -> None:
    value = "x" * 20
    key = resolve_provider_key("primary", provider("anthropic"), env={"ANTHROPIC_API_KEY": value})
    assert key is not None
    assert key.get_secret_value() == value


def test_two_step_fallback() -> None:
    key = resolve_provider_key("g", provider("gemini"), env={"GOOGLE_API_KEY": "second"})
    assert key is not None
    assert key.get_secret_value() == "second"


def test_provider_key_missing_message() -> None:
    with pytest.raises(SecretResolutionError) as info:
        resolve_provider_key("primary", provider("anthropic"), env={})
    assert code_of(info.value) == "CK-CFG-012"
    assert info.value.issues[0].message == (
        "provider 'primary' (anthropic): no API key. Tried env:ANTHROPIC_API_KEY. Set that "
        "variable, or run 'codekavach config key set primary' and use "
        # pragma: allowlist nextline secret
        'api_key = "keyring:codekavach/primary".'
    )


def test_explicit_key_on_optional_kind_must_resolve() -> None:
    with pytest.raises(SecretResolutionError):
        # pragma: allowlist nextline secret
        resolve_provider_key("lab", provider("ollama", api_key="env:LAB_KEY"), env={})


# hygiene


def test_keyring_not_imported_by_loading(tmp_path: Path) -> None:
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "import codekavach.config\n"
        "from codekavach.config.loader import load_settings\n"
        f"load_settings(target=Path({str(tmp_path)!r}), env={{}}, use_user_config=False)\n"
        "assert 'keyring' not in sys.modules, 'keyring imported'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stderr


_secret_text = st.text(
    alphabet=st.characters(codec="utf-8", blacklist_categories=["Cs", "Cc", "Zs", "Zl", "Zp"]),
    min_size=4,
    max_size=40,
)


@given(_secret_text)
@settings(max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_value_never_leaks(
    tmp_path_factory: pytest.TempPathFactory, caplog: pytest.LogCaptureFixture, value: str
) -> None:
    root = tmp_path_factory.mktemp("root")
    inside = write(root / "k.txt", value.encode("utf-8"), 0o644)
    outside = write(tmp_path_factory.mktemp("out") / "k.txt", value.encode("utf-8"), 0o644)
    # The paths themselves appear in messages; a value that is part of a path proves nothing.
    assume(value not in str(inside) and value not in str(outside))
    texts: list[str] = []
    with caplog.at_level(logging.DEBUG):
        try:
            resolve_secret(f"file:{inside}", project_root=root)
        except SecretResolutionError as exc:
            texts += [str(exc), repr(exc)]
        warnings: list[ConfigIssue] = []
        resolved = resolve_secret(f"file:{outside}", warnings=warnings)
        texts += [repr(resolved), str(resolved), *(repr(w) for w in warnings)]
        texts.append(repr(secret_status(f"file:{outside}")))
        texts.append(repr(secret_status("env:K", env={"K": value})))
    texts.append(caplog.text)
    for text in texts:
        assert value not in text
