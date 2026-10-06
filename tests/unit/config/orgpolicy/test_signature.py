"""Detached Ed25519 signatures of organisation policies (E03-31).

Every key is generated inside the tests; no key material is committed.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import paths as config_paths
from codekavach.config import toml_source
from codekavach.config.errors import OrgPolicyError
from codekavach.config.orgpolicy import discovery, signature
from codekavach.config.orgpolicy.signature import (
    PUBKEY_ENV,
    find_public_key,
    load_private_key,
    load_public_key,
    sign_policy,
    verify_policy,
)
from tests.support.config import ConfigSandbox, to_toml

POLICY = {"policy_version": 1, "organisation": "Example Bank Ltd", "privacy": {"min_level": "L3"}}
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
PRIVATE = Ed25519PrivateKey.generate()
PUBLIC = PRIVATE.public_key()


def codes(error: pytest.ExceptionInfo[OrgPolicyError]) -> set[str]:
    return {issue.code.value for issue in error.value.issues}


def write_public_key(path: Path, key: Any = PUBLIC) -> Path:
    path.write_bytes(
        key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return path


def write_private_key(path: Path, key: Any = PRIVATE, passphrase: bytes | None = None) -> Path:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    )
    path.chmod(0o600)
    return path


def signed_policy(sandbox: ConfigSandbox, *, key: Ed25519PrivateKey = PRIVATE) -> Path:
    path = sandbox.write_policy(to_toml(POLICY))
    signature.signature_path(path).write_text(sign_policy(path.read_bytes(), key) + "\n")
    sandbox.env[PUBKEY_ENV] = str(write_public_key(sandbox.outside / "policy.pub"))
    return path


# --- sign and verify ------------------------------------------------------------------------


def test_round_trip() -> None:
    data = b"policy_version = 1\n"
    text = sign_policy(data, PRIVATE)
    assert len(base64.b64decode(text)) == 64
    verify_policy(data, text, PUBLIC)
    verify_policy(data, text + "\n", PUBLIC)  # an optional trailing newline


@pytest.mark.parametrize(
    "case", ["tampered policy", "tampered signature", "wrong key", "bad base64", "short", "long"]
)
def test_failures_are_054(case: str) -> None:
    data = b"policy_version = 1\n"
    good = sign_policy(data, PRIVATE)
    raw = bytearray(base64.b64decode(good))
    raw[0] ^= 1
    signatures = {
        "tampered policy": (data + b" ", good, PUBLIC),
        "tampered signature": (data, base64.b64encode(bytes(raw)).decode(), PUBLIC),
        "wrong key": (data, good, Ed25519PrivateKey.generate().public_key()),
        "bad base64": (data, "not*base64!", PUBLIC),
        "short": (data, base64.b64encode(bytes(32)).decode(), PUBLIC),
        "long": (data, base64.b64encode(bytes(65)).decode(), PUBLIC),
    }
    policy_bytes, text, key = signatures[case]
    with pytest.raises(OrgPolicyError) as info:
        verify_policy(policy_bytes, text, key)
    assert codes(info) == {"CK-CFG-054"}


@given(st.binary(max_size=200), st.integers(min_value=0), st.booleans())
def test_any_single_bit_flip_fails(data: bytes, position: int, in_signature: bool) -> None:
    text = sign_policy(data, PRIVATE)
    raw = bytearray(base64.b64decode(text))
    if in_signature or not data:
        raw[position % len(raw)] ^= 1 << (position % 8)
        mutated_data, mutated_text = data, base64.b64encode(bytes(raw)).decode()
    else:
        flipped = bytearray(data)
        flipped[position % len(flipped)] ^= 1 << (position % 8)
        mutated_data, mutated_text = bytes(flipped), text
    with pytest.raises(OrgPolicyError):
        verify_policy(mutated_data, mutated_text, PUBLIC)


# --- keys -------------------------------------------------------------------------------------


def test_public_key_discovery_order(tmp_path: Path) -> None:
    system = tmp_path / "etc"
    system.mkdir()
    write_public_key(system / "policy.pub")
    named = write_public_key(tmp_path / "named.pub")
    assert find_public_key({PUBKEY_ENV: str(named)}, [system]) == named
    assert find_public_key({}, [tmp_path / "missing", system]) == system / "policy.pub"
    assert find_public_key({}, [tmp_path / "missing"]) is None


def test_public_key_must_be_ed25519(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = write_public_key(tmp_path / "rsa.pub", rsa_key.public_key())
    with pytest.raises(OrgPolicyError, match="not an Ed25519 key"):
        load_public_key(path)
    (tmp_path / "junk.pub").write_text("not a key")
    with pytest.raises(OrgPolicyError, match="not a PEM public key"):
        load_public_key(tmp_path / "junk.pub")


def test_private_key_with_passphrase(tmp_path: Path) -> None:
    path = write_private_key(tmp_path / "signing.pem", passphrase=b"right horse battery")
    assert isinstance(load_private_key(path, b"right horse battery"), Ed25519PrivateKey)
    with pytest.raises(OrgPolicyError, match="cannot be decrypted"):
        load_private_key(path, b"wrong")
    with pytest.raises(OrgPolicyError, match="needs a passphrase"):
        load_private_key(path, None)


def test_private_key_must_be_ed25519(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = write_private_key(tmp_path / "rsa.pem", rsa_key)
    with pytest.raises(OrgPolicyError, match="not an Ed25519 key"):
        load_private_key(path, None)


@posix_only
def test_private_key_readable_by_others_is_refused(tmp_path: Path) -> None:
    path = write_private_key(tmp_path / "signing.pem")
    path.chmod(0o644)
    with pytest.raises(OrgPolicyError, match="readable by group or others") as info:
        load_private_key(path, None)
    assert codes(info) == {"CK-CFG-054"}


# --- discovery and loading --------------------------------------------------------------------


def test_signed_policy_loads_as_valid(config_sandbox: ConfigSandbox) -> None:
    signed_policy(config_sandbox)
    loaded = config_sandbox.load()
    assert [policy.signature for policy in loaded.org_policies] == ["valid"]


@pytest.mark.parametrize("damage", ["policy byte", "signature byte", "missing sig"])
def test_tampering_fails_closed(config_sandbox: ConfigSandbox, damage: str) -> None:
    path = signed_policy(config_sandbox)
    sig = signature.signature_path(path)
    if damage == "policy byte":
        path.write_bytes(path.read_bytes().replace(b"L3", b"L4"))
    elif damage == "signature byte":
        raw = bytearray(base64.b64decode(sig.read_text()))
        raw[10] ^= 1
        sig.write_text(base64.b64encode(bytes(raw)).decode())
    else:
        sig.unlink()
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert codes(info) == {"CK-CFG-054"}


def test_oversized_signature_file(config_sandbox: ConfigSandbox) -> None:
    path = signed_policy(config_sandbox)
    signature.signature_path(path).write_text("A" * 300)
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert codes(info) == {"CK-CFG-054"}


def test_unverified_signature_file_warns(config_sandbox: ConfigSandbox) -> None:
    path = config_sandbox.write_policy(to_toml(POLICY))
    assert config_sandbox.load().warnings == ()
    signature.signature_path(path).write_text(sign_policy(path.read_bytes(), PRIVATE))
    loaded = config_sandbox.load()
    (warning,) = loaded.warnings
    assert (warning.code.value, warning.severity) == ("CK-CFG-054", "warning")
    assert [policy.signature for policy in loaded.org_policies] == ["not-checked"]


def test_key_inside_the_project_root_is_051(config_sandbox: ConfigSandbox) -> None:
    signed_policy(config_sandbox)
    config_sandbox.env[PUBKEY_ENV] = str(write_public_key(config_sandbox.root / "policy.pub"))
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert codes(info) == {"CK-CFG-051"}


@posix_only
def test_group_writable_key_is_052(config_sandbox: ConfigSandbox) -> None:
    signed_policy(config_sandbox)
    Path(config_sandbox.env[PUBKEY_ENV]).chmod(0o664)
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert codes(info) == {"CK-CFG-052"}


def test_missing_configured_key_is_054(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(to_toml(POLICY))
    config_sandbox.env[PUBKEY_ENV] = str(config_sandbox.outside / "absent.pub")
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert codes(info) == {"CK-CFG-054"}


def test_system_policy_uses_policy_pub_next_to_it(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_dir = config_sandbox.outside / "etc"
    system_dir.mkdir()
    policy_path = system_dir / "policy.toml"
    policy_path.write_text(to_toml(POLICY))
    monkeypatch.setattr(config_paths, "system_policy_paths", lambda: (policy_path,))
    write_public_key(system_dir / "policy.pub")
    with pytest.raises(OrgPolicyError):  # the key is there, the signature is not
        config_sandbox.load()
    signature.signature_path(policy_path).write_text(sign_policy(policy_path.read_bytes(), PRIVATE))
    assert [p.signature for p in config_sandbox.load().org_policies] == ["valid"]


def test_policy_is_read_once(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = signed_policy(config_sandbox)
    reads: list[bytes] = []
    parsed: list[bytes] = []
    real_read, real_parse = toml_source.read_bounded_bytes, toml_source.parse_toml_bytes

    def counting_read(target: Path, **kwargs: Any) -> bytes:
        data = real_read(target, **kwargs)
        if target == path:
            reads.append(data)
        return data

    def recording_parse(raw: bytes, target: Path) -> Any:
        parsed.append(raw)
        return real_parse(raw, target)

    monkeypatch.setattr(discovery, "read_bounded_bytes", counting_read)
    monkeypatch.setattr(discovery, "parse_toml_bytes", recording_parse)
    config_sandbox.load()
    assert len(reads) == 1
    assert parsed == reads  # the verified bytes are the parsed bytes, not a second read


def test_load_without_a_key_does_not_import_cryptography(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    program = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from codekavach.config import load_settings\n"
        f"load_settings(target=Path({str(root)!r}), env={{'CODEKAVACH_HOME': {str(tmp_path)!r}}})\n"
        "print(json.dumps('cryptography' in sys.modules))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True
    ).stdout
    assert json.loads(out.strip().splitlines()[-1]) is False
