"""The structural validators of the pattern pack: a valid and an invalid input each."""

import base64
import json

import pytest

from codekavach.privacy.detect.secrets.patterns import (
    valid_connection_string,
    valid_docker_auth,
    valid_gcp_service_account,
    valid_jwt,
    valid_private_key_block,
)


def b64url(document: object) -> str:
    raw = json.dumps(document).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


HEADER = b64url({"alg": "HS256", "typ": "JWT"})
PAYLOAD = b64url({"sub": "synthetic"})


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        (f"{HEADER}.{PAYLOAD}.signature", True),
        (f"{HEADER}.{PAYLOAD}.", True),  # an unsecured token has an empty signature
        (f"{HEADER}.{PAYLOAD}", False),  # two segments
        (f"{HEADER}.{PAYLOAD}.a.b", False),  # four segments
        (f"{b64url({'typ': 'JWT'})}.{PAYLOAD}.sig", False),  # no alg
        (f"{b64url(['alg'])}.{PAYLOAD}.sig", False),  # JSON, but not an object
        (f"eyJabcdefghijklm.{PAYLOAD}.sig", False),  # header is not JSON
        (f".{PAYLOAD}.sig", False),
        (f"{HEADER}..sig", False),
        (f"{HEADER}.!!!.sig", False),  # payload is not base64url
    ],
)
def test_jwt(value: str, ok: bool) -> None:
    assert valid_jwt(value) is ok


def pem(begin: str, end: str, body: str = "QUJDREVGRw==") -> str:
    return f"-----BEGIN {begin}-----\n{body}\n-----END {end}-----"


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        (pem("RSA PRIVATE KEY", "RSA PRIVATE KEY"), True),
        (pem("PRIVATE KEY", "PRIVATE KEY"), True),
        (pem("PGP PRIVATE KEY BLOCK", "PGP PRIVATE KEY BLOCK"), True),
        (pem("RSA PRIVATE KEY", "EC PRIVATE KEY"), False),  # labels differ
        (pem("PRIVATE KEY", "PRIVATE KEY", body="  "), False),  # nothing between the lines
        (pem("PRIVATE KEY", "PRIVATE KEY").rsplit("\n", 1)[0], False),  # no END line
    ],
)
def test_private_key_block(value: str, ok: bool) -> None:
    assert valid_private_key_block(value) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("postgres://svc:pw1234@db.internal/app", True),  # pragma: allowlist secret
        ("mongodb+srv://svc:pw1234@cluster.example.test/db", True),  # pragma: allowlist secret
        ("postgres://svc@db.internal/app", False),  # no password
        ("postgres://svc:@db.internal/app", False),  # empty password
        ("postgres://db.internal/app", False),
        ("postgres://[::1", False),  # does not parse as a URL
    ],
)
def test_connection_string(value: str, ok: bool) -> None:
    assert valid_connection_string(value) is ok


def key_file(**fields: object) -> str:
    document: dict[str, object] = {"type": "service_account", **fields}
    return json.dumps(document)


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        (key_file(private_key="k", client_email="a@b.test"), True),
        (key_file(private_key="k"), False),  # no client_email
        (key_file(client_email="a@b.test"), False),  # no private_key
        (key_file(private_key=1, client_email="a@b.test"), False),  # not a string
        ('{"type": "service_account", ', False),  # not JSON
        ("[]", False),  # not an object
        ("{" + " " * 17_000 + "}", False),  # over the size cap
    ],
)
def test_gcp_service_account(value: str, ok: bool) -> None:
    assert valid_gcp_service_account(value) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        (base64.b64encode(b"svc:abcdefghijkl").decode(), True),
        (base64.b64encode(b"svc:").decode(), False),  # no password
        (base64.b64encode(b":password").decode(), False),  # no user
        (base64.b64encode(b"secretsecretsecret").decode(), False),  # no colon
        ("!!!notbase64!!!", False),
        (base64.b64encode(b"\xff\xfe:\xff").decode(), False),  # not UTF-8
    ],
)
def test_docker_auth(value: str, ok: bool) -> None:
    assert valid_docker_auth(value) is ok
