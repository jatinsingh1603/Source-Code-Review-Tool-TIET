"""The key-management source and the policy of its client (E10-03, ADR-0003 exception).

The service is an in-process fake on ``httpx.MockTransport``; no test opens a socket (the process
blocks them, and one test proves the blocking reaches this client).
"""

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pytest_socket import SocketBlockedError

from codekavach.config import Settings
from codekavach.privacy.vault.errors import KeySourceUnavailable, VaultKeyError
from codekavach.privacy.vault.keys import KeySource
from codekavach.privacy.vault.kms import (
    MAX_RESPONSE_BYTES,
    KmsKeySource,
    KmsPolicyError,
    TransitKmsAdapter,
)
from codekavach.privacy.vault.lifecycle import rotate_key
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import Vault
from tests.unit.privacy.vault.test_lifecycle import NAMES, batch

HOST = "kms.example.test"
ENDPOINT = f"https://{HOST}"
SECRET = "service-credential-value"  # pragma: allowlist secret
DATA_KEY = bytes(range(32))


class FakeService:
    """The transit API of a key-management service, recording what it was sent."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.loads(request.content)
        if request.url.path.startswith("/v1/transit/encrypt/"):
            sealed = (
                "svc:v1:" + base64.b64encode(base64.b64decode(body["plaintext"])[::-1]).decode()
            )
            return httpx.Response(200, json={"data": {"ciphertext": sealed}})
        raw = base64.b64decode(body["ciphertext"].removeprefix("svc:v1:"))[::-1]
        return httpx.Response(200, json={"data": {"plaintext": base64.b64encode(raw).decode()}})


def adapter(
    handler: Any,
    *,
    allow: tuple[str, ...] = (HOST,),
    endpoint: str = ENDPOINT,
    timeout: float = 5.0,
) -> TransitKmsAdapter:
    return TransitKmsAdapter(
        endpoint=endpoint,
        key_id="vault-key",
        token=SECRET,
        host_allowlist=allow,
        timeout_seconds=timeout,
        transport=httpx.MockTransport(handler),
    )


def test_a_data_key_round_trips_through_the_service() -> None:
    service = FakeService()
    client = adapter(service)
    blob = client.wrap(DATA_KEY)
    assert client.unwrap(blob) == DATA_KEY
    assert [r.url.path for r in service.requests] == [
        "/v1/transit/encrypt/vault-key",
        "/v1/transit/decrypt/vault-key",
    ]


def test_only_the_data_key_and_the_credential_leave() -> None:
    service = FakeService()
    adapter(service).wrap(DATA_KEY)
    (request,) = service.requests
    body = json.loads(request.content)
    assert set(body) == {"plaintext"}
    assert base64.b64decode(body["plaintext"]) == DATA_KEY
    assert request.headers["X-Vault-Token"] == SECRET
    assert request.url.scheme == "https"
    assert request.url.host == HOST


def test_a_host_outside_the_allow_list_is_refused_before_anything_is_sent() -> None:
    service = FakeService()
    with pytest.raises(KmsPolicyError, match="host_allowlist"):
        adapter(service, allow=("other.example.test",)).wrap(DATA_KEY)
    assert service.requests == []


def test_an_empty_allow_list_refuses_every_host() -> None:
    service = FakeService()
    with pytest.raises(KmsPolicyError, match="host_allowlist"):
        adapter(service, allow=()).unwrap(b"svc:v1:AAAA")
    assert service.requests == []


def test_the_allow_list_compares_whole_host_names_without_case() -> None:
    service = FakeService()
    adapter(service, allow=(HOST.upper(),)).wrap(DATA_KEY)
    with pytest.raises(KmsPolicyError):
        adapter(service, allow=("example.test",)).wrap(DATA_KEY)
    with pytest.raises(KmsPolicyError):
        adapter(service, allow=(f"x.{HOST}",)).wrap(DATA_KEY)


@pytest.mark.parametrize("endpoint", ["http://kms.example.test", "ftp://kms.example.test", "kms"])
def test_plain_http_and_other_schemes_are_refused(endpoint: str) -> None:
    with pytest.raises(KmsPolicyError, match="https"):
        adapter(FakeService(), endpoint=endpoint)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_an_error_and_is_not_followed(status: int) -> None:
    calls: list[httpx.Request] = []

    def redirecting(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(status, headers={"Location": "https://elsewhere.example.test/x"})

    with pytest.raises(KmsPolicyError, match="redirect"):
        adapter(redirecting).wrap(DATA_KEY)
    assert len(calls) == 1


def test_the_client_is_built_with_a_timeout_no_redirects_and_no_ambient_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}
    real = httpx.Client

    def recording(**kwargs: Any) -> httpx.Client:
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(httpx, "Client", recording)
    adapter(FakeService(), timeout=2.5).wrap(DATA_KEY)
    assert seen["timeout"] == 2.5
    assert seen["follow_redirects"] is False
    assert seen["trust_env"] is False
    assert seen["verify"] is True


def test_a_timeout_is_an_error() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    with pytest.raises(KmsPolicyError, match="in time"):
        adapter(slow).wrap(DATA_KEY)


def test_a_refusal_by_the_service_is_an_error_without_its_body() -> None:
    def refusing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text=f"permission denied for {SECRET}")

    with pytest.raises(KmsPolicyError) as raised:
        adapter(refusing).wrap(DATA_KEY)
    assert SECRET not in str(raised.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"data": {}}),
        httpx.Response(200, json={"data": {"ciphertext": 7}}),
        httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)),
    ],
)
def test_an_answer_of_the_wrong_shape_or_size_is_an_error(response: httpx.Response) -> None:
    with pytest.raises(KmsPolicyError):
        adapter(lambda request: response).wrap(DATA_KEY)


def test_a_key_of_the_wrong_length_never_leaves() -> None:
    service = FakeService()
    with pytest.raises(KmsPolicyError, match="32-byte"):
        adapter(service).wrap(b"short")
    assert service.requests == []


def test_a_key_of_the_wrong_length_coming_back_is_refused() -> None:
    def short(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"plaintext": base64.b64encode(b"short").decode()}}
        )

    with pytest.raises(KmsPolicyError, match="wrong length"):
        adapter(short).unwrap(b"svc:v1:AAAA")


def test_the_adapter_hides_its_credential() -> None:
    client = adapter(FakeService())
    assert SECRET not in repr(client)
    assert SECRET not in repr(KmsKeySource(client))


def test_a_real_connection_is_blocked_in_tests() -> None:
    real = TransitKmsAdapter(
        endpoint=ENDPOINT,
        key_id="k",
        token=SECRET,
        host_allowlist=(HOST,),
        timeout_seconds=1.0,
    )
    with pytest.raises((SocketBlockedError, KmsPolicyError)):
        real.wrap(DATA_KEY)


# --- the source from the configuration ------------------------------------------------------


def kms_settings(**overrides: Any) -> Settings:
    section: dict[str, Any] = {
        "endpoint": ENDPOINT,
        "key_id": "vault-key",
        "token": "env:KMS_TOKEN",
        "host_allowlist": [HOST],
    }
    section.update(overrides)
    return Settings.model_validate({"privacy": {"vault": {"key_source": "kms", "kms": section}}})


def test_the_source_reads_its_credential_through_a_secret_reference() -> None:
    service = FakeService()
    source = KmsKeySource.from_settings(
        kms_settings(), env={"KMS_TOKEN": SECRET}, transport=httpx.MockTransport(service)
    )
    assert source.unwrap(source.wrap(DATA_KEY)) == DATA_KEY
    assert service.requests[0].headers["X-Vault-Token"] == SECRET


def test_an_unresolvable_credential_names_the_setting_and_not_the_value() -> None:
    with pytest.raises(KeySourceUnavailable, match=r"privacy\.vault\.kms\.token"):
        KmsKeySource.from_settings(kms_settings(), env={})


def test_an_incomplete_section_is_unavailable() -> None:
    incomplete = Settings.model_validate({"privacy": {"vault": {"key_source": "kms"}}})
    with pytest.raises(KeySourceUnavailable):
        KmsKeySource.from_settings(incomplete)


def test_a_vault_can_be_made_opened_and_rotated_to_and_from_the_service(tmp_path: Path) -> None:
    service = FakeService()
    transport = httpx.MockTransport(service)
    config = kms_settings()
    env = {"KMS_TOKEN": SECRET}
    client = KmsKeySource.from_settings(config, env=env, transport=transport)
    state = tmp_path / "state"
    with Vault(vault_path(state), KeySource.KMS, settings=config, kms=client) as vault:
        vault.put(batch("scan_1", *NAMES))
    raw = vault_path(state).read_bytes()
    assert DATA_KEY not in raw
    with Vault(vault_path(state), KeySource.KMS, kms=client, create=False) as vault:
        assert vault.lookup("fn_1", scan_id="scan_1") == "alpha_name"
    result = rotate_key(
        state,
        kms=client,
        new_backend="passphrase",
        new_prompt=lambda: "a new passphrase",  # pragma: allowlist secret
    )
    assert result.old_source == "kms"
    with Vault(
        vault_path(state),
        KeySource.PASSPHRASE,
        prompt=lambda: "a new passphrase",  # pragma: allowlist secret
        create=False,
    ) as vault:
        assert vault.lookup("var_2", scan_id="scan_1") == "bravo_value"
    assert {r.url.host for r in service.requests} == {HOST}


def test_a_vault_of_this_source_does_not_open_with_another(tmp_path: Path) -> None:
    client = adapter(FakeService())
    state = tmp_path / "state"
    with Vault(vault_path(state), KeySource.KMS, kms=KmsKeySource(client)) as vault:
        vault.put(batch("scan_1", *NAMES))
    with pytest.raises(VaultKeyError):
        Vault(vault_path(state), KeySource.EPHEMERAL, create=False)
