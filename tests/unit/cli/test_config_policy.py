"""``codekavach config policy show|sign|verify`` (E03-32). Keys are generated in the tests."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codekavach.cli.exit_codes import ExitCode
from codekavach.config import paths as config_paths
from tests.support.cli import CliResult, run_cli
from tests.support.config import to_toml

POLICY = {
    "policy_version": 1,
    "organisation": "Example Bank Ltd",
    "enforcement": "reject",
    "expires": (datetime.now(UTC).date() + timedelta(days=365)).isoformat(),
    "privacy": {"min_level": "L3"},
    "llm": {"allowed_kinds": ["ollama", "azure-openai"]},
    "lock": {"scan.jobs": 2, "reporting.classification": "Confidential"},
}
PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def area(tmp_path: Path) -> Path:
    for name in ("project", "keys", "policies"):
        (tmp_path / name).mkdir()
    (tmp_path / "project" / ".git").mkdir()
    return tmp_path


def write_policy(area: Path, data: dict[str, Any] = POLICY, name: str = "policy.toml") -> Path:
    path = area / "policies" / name
    path.write_text(to_toml(data), encoding="utf-8")
    return path


def write_keys(area: Path, passphrase: str | None = None) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    private = area / "keys" / "policy.key"
    private.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    )
    private.chmod(0o600)
    public = area / "keys" / "policy.pub"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def cli(args: list[str], area: Path, env: dict[str, str] | None = None, **kwargs: Any) -> CliResult:
    return run_cli(["config", "policy", *args], cwd=area / "project", env=env, **kwargs)


# --- sign and verify --------------------------------------------------------------------------


def test_sign_then_verify(area: Path) -> None:
    policy = write_policy(area)
    private, public = write_keys(area)
    signed = cli(["sign", str(policy), "--key", str(private)], area)
    assert signed.exit_code == ExitCode.OK, signed.stderr
    sig = policy.with_name("policy.toml.sig")
    assert sig.is_file()
    if os.name != "nt":
        assert sig.stat().st_mode & 0o777 == 0o644
    verified = cli(["verify", str(policy), "--pubkey", str(public)], area)
    assert verified.exit_code == ExitCode.OK, verified.stderr
    assert "signature valid" in verified.stdout
    policy.write_bytes(policy.read_bytes().replace(b"L3", b"L4"))
    tampered = cli(["verify", str(policy), "--pubkey", str(public)], area)
    assert tampered.exit_code == ExitCode.USAGE
    assert "CK-CFG-054" in tampered.stderr


def test_verify_with_the_wrong_key_and_custom_paths(area: Path) -> None:
    policy = write_policy(area)
    private, _ = write_keys(area)
    out = area / "policies" / "custom.sig"
    assert cli(["sign", str(policy), "--key", str(private), "--out", str(out)], area).exit_code == 0
    other = Ed25519PrivateKey.generate().public_key()
    wrong = area / "keys" / "other.pub"
    wrong.write_bytes(
        other.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    result = cli(["verify", str(policy), "--pubkey", str(wrong), "--sig", str(out)], area)
    assert result.exit_code == ExitCode.USAGE
    assert "CK-CFG-054" in result.stderr


def test_sign_refuses_an_invalid_policy(area: Path) -> None:
    policy = write_policy(area, {**POLICY, "enforcement": "sometimes"})
    private, _ = write_keys(area)
    result = cli(["sign", str(policy), "--key", str(private)], area)
    assert result.exit_code == ExitCode.USAGE
    assert "invalid_policy" in result.stderr
    assert not policy.with_name("policy.toml.sig").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_sign_refuses_a_group_readable_key(area: Path) -> None:
    policy = write_policy(area)
    private, _ = write_keys(area)
    private.chmod(0o640)
    result = cli(["sign", str(policy), "--key", str(private)], area)
    assert result.exit_code == ExitCode.USAGE
    assert "CK-CFG-054" in result.stderr


def test_no_key_material_in_output_or_help(area: Path) -> None:
    policy = write_policy(area)
    private, _ = write_keys(area)
    signed = cli(["sign", str(policy), "--key", str(private)], area)
    help_text = cli(["sign", "--help"], area).stdout
    key_text = private.read_text(encoding="ascii")
    body = "".join(line for line in key_text.splitlines() if not line.startswith("-----"))
    for text in (signed.stdout, signed.stderr, help_text):
        assert "PRIVATE KEY" not in text
        assert body[:20] not in text
    assert "openssl genpkey -algorithm ed25519" in help_text


@pytest.mark.parametrize(
    "extra", [["EXTRA"], ["--passphrase", PASSPHRASE], ["--password", PASSPHRASE]]
)
def test_no_extra_arguments_or_passphrase_option(area: Path, extra: list[str]) -> None:
    policy = write_policy(area)
    private, _ = write_keys(area)
    result = cli(["sign", str(policy), "--key", str(private), *extra], area)
    assert result.exit_code == ExitCode.USAGE
    assert PASSPHRASE not in result.stdout


def test_encrypted_key_prompts_hidden(area: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = write_policy(area)
    private, public = write_keys(area, PASSPHRASE)
    asked: list[dict[str, Any]] = []

    def prompt(text: str, **kwargs: Any) -> str:
        asked.append({"text": text, **kwargs})
        return PASSPHRASE

    monkeypatch.setattr(typer, "prompt", prompt)
    result = cli(["sign", str(policy), "--key", str(private)], area, tty=True)
    assert result.exit_code == ExitCode.OK, result.stderr
    assert asked == [{"text": "Passphrase", "hide_input": True}]
    assert cli(["verify", str(policy), "--pubkey", str(public)], area).exit_code == 0


def test_encrypted_key_without_a_terminal_fails(area: Path) -> None:
    policy = write_policy(area)
    private, _ = write_keys(area, PASSPHRASE)
    result = cli(["sign", str(policy), "--key", str(private)], area, input="")
    assert result.exit_code == ExitCode.USAGE
    assert "prompt_unavailable" in result.stderr


# --- show -------------------------------------------------------------------------------------


def test_show_without_a_policy(area: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_paths, "system_policy_paths", lambda: ())
    text = cli(["show"], area)
    assert text.exit_code == ExitCode.OK
    assert text.stdout.strip() == "no organisation policy is active"
    as_json = cli(["show", "--format", "json"], area)
    assert json.loads(as_json.stdout) == []


def test_show_one_policy(area: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_paths, "system_policy_paths", lambda: ())
    policy = write_policy(area)
    env = {"CODEKAVACH_ORG_POLICY": str(policy)}
    text = cli(["show"], area, env=env)
    assert text.exit_code == ExitCode.OK, text.stderr
    lines = {line.split()[0]: line for line in text.stdout.splitlines() if line.strip()}
    assert "Example Bank Ltd" in lines["organisation"]
    assert "(env)" in lines["path"]
    assert lines["signature"].split()[1] == "not-checked"
    assert "privacy.min_level=L3" in lines["rules"]
    assert "llm.allowed_kinds=2" in lines["rules"]
    assert "lock=2 keys" in lines["rules"]
    (document,) = json.loads(cli(["show", "--format", "json"], area, env=env).stdout)
    assert set(document) == {
        "organisation",
        "path",
        "origin",
        "sha256",
        "signature",
        "enforcement",
        "issued",
        "expires",
        "rules",
    }
    assert len(document["sha256"]) == 64
    assert document["rules"]["lock"] == POLICY["lock"]


def test_show_two_policies_with_a_signature(area: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system = write_policy(area, {**POLICY, "organisation": "Group Security"}, name="system.toml")
    monkeypatch.setattr(config_paths, "system_policy_paths", lambda: (system,))
    env_policy = write_policy(area)
    private, public = write_keys(area)
    for path in (system, env_policy):
        assert cli(["sign", str(path), "--key", str(private)], area).exit_code == 0
    env = {"CODEKAVACH_ORG_POLICY": str(env_policy), "CODEKAVACH_ORG_POLICY_PUBKEY": str(public)}
    documents = json.loads(cli(["show", "--format", "json"], area, env=env).stdout)
    assert [d["origin"] for d in documents] == ["system", "env"]
    assert [d["signature"] for d in documents] == ["valid", "valid"]
    text = cli(["show"], area, env=env).stdout
    assert f"valid (key {public})" in text


def test_show_fails_on_an_expired_policy(area: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_paths, "system_policy_paths", lambda: ())
    expired = write_policy(area, {**POLICY, "expires": "2020-01-01"})
    result = cli(["show"], area, env={"CODEKAVACH_ORG_POLICY": str(expired)})
    assert result.exit_code == ExitCode.USAGE
    assert "CK-CFG-056" in result.stderr
