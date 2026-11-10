"""The external key-management source of the vault (E10-03).

Owning epic: E10. Governed by ADR-0003 and its exception record
``docs/adr/ADR-0003-exception-kms.md``: this is the only module of the vault package, and one of
two modules in the whole of ``codekavach``, that may import a network client library.

**What crosses the connection.** One 32-byte vault data key (on ``wrap``, so the service can seal
it) or its sealed form (on ``unwrap``), over TLS, to a host the operator listed in
``privacy.vault.kms.host_allowlist``. No client code, no mapping, no pseudonym and no original ever
goes through this module: its only inputs are key bytes. The service credential is resolved through
``resolve_secret`` and never logged.

**What the client refuses**, each case asserted against an in-process fake (no test opens a socket):

- a host that is not in the allow-list, including every host while the list is empty;
- any scheme but ``https``;
- a redirect of any kind (``follow_redirects`` is off and a 3xx answer is an error);
- an answer that takes longer than ``privacy.vault.kms.timeout_seconds``;
- an answer larger than 64 KiB, or one that is not the expected shape.

Ambient proxy and netrc settings are not read (``trust_env`` is off), so the destination is the
configured endpoint and nothing the environment adds.

The shipped adapter speaks the HashiCorp Vault *transit* API (``/v1/transit/encrypt/<key>`` and
``/decrypt``), which is an openly documented wire format that several services implement. Other
services plug in by implementing ``KmsClient``.
"""

import base64
import binascii
from collections.abc import Mapping
from typing import Any, Final, Self
from urllib.parse import quote, urlsplit

import httpx

from codekavach.config import Settings
from codekavach.config.errors import ConfigError
from codekavach.config.keys import resolve_secret
from codekavach.core.log import get_logger
from codekavach.privacy.vault.crypto import KEY_BYTES
from codekavach.privacy.vault.errors import KeySourceUnavailable
from codekavach.privacy.vault.keys import KmsClient

_LOG = get_logger("codekavach.privacy.vault.kms")
MAX_RESPONSE_BYTES: Final = 64 * 1024
_TOKEN_HEADER: Final = "X-Vault-Token"  # noqa: S105 - a header name, not a secret


class KmsPolicyError(KeySourceUnavailable):
    """The request was refused by the client's own policy; nothing was sent."""


class TransitKmsAdapter:
    """The transit API of a key-management service, behind the host and transport policy."""

    def __init__(
        self,
        *,
        endpoint: str,
        key_id: str,
        token: str,
        host_allowlist: tuple[str, ...],
        timeout_seconds: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.hostname:
            raise KmsPolicyError("the key-management endpoint must be an https URL")
        self._base = f"https://{parts.netloc}{parts.path.rstrip('/')}"
        self._host = parts.hostname.lower()
        self._key = quote(key_id, safe="")
        self._token = token
        self._allowed = frozenset(host.lower() for host in host_allowlist)
        self._timeout = timeout_seconds
        self._transport = transport

    def __repr__(self) -> str:
        return "TransitKmsAdapter(<redacted>)"

    def wrap(self, data_key: bytes) -> bytes:
        """The data key sealed by the service."""
        if len(data_key) != KEY_BYTES:
            raise KmsPolicyError("only a 32-byte data key goes to the key-management service")
        body = {"plaintext": base64.b64encode(data_key).decode("ascii")}
        sealed = self._post("encrypt", body, "ciphertext")
        return sealed.encode("ascii")

    def unwrap(self, blob: bytes) -> bytes:
        """The data key behind ``blob``."""
        try:
            sealed = blob.decode("ascii")
        except UnicodeDecodeError:
            raise KmsPolicyError("the sealed key is not what the service produces") from None
        encoded = self._post("decrypt", {"ciphertext": sealed}, "plaintext")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise KmsPolicyError("the service answered with an unexpected shape") from None
        if len(key) != KEY_BYTES:
            raise KmsPolicyError("the service answered with a key of the wrong length")
        return key

    def _post(self, operation: str, body: Mapping[str, str], field: str) -> str:
        if self._host not in self._allowed:
            raise KmsPolicyError(
                "the key-management host is not in privacy.vault.kms.host_allowlist"
            )
        url = f"{self._base}/v1/transit/{operation}/{self._key}"
        try:
            with httpx.Client(
                transport=self._transport,
                follow_redirects=False,
                timeout=self._timeout,
                trust_env=False,
                verify=True,
            ) as client:
                response = client.post(url, json=dict(body), headers={_TOKEN_HEADER: self._token})
        except httpx.TimeoutException:
            raise KmsPolicyError("the key-management service did not answer in time") from None
        except httpx.HTTPError:
            raise KmsPolicyError("the key-management service could not be reached") from None
        if response.is_redirect or 300 <= response.status_code < 400:
            raise KmsPolicyError("the key-management service answered with a redirect")
        if response.status_code != 200:
            _LOG.info("kms_refused", operation=operation, status=response.status_code)
            raise KmsPolicyError("the key-management service refused the request")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise KmsPolicyError("the key-management answer is larger than expected")
        try:
            document: Any = response.json()
            value = document["data"][field]
        except (ValueError, KeyError, TypeError):
            raise KmsPolicyError("the service answered with an unexpected shape") from None
        if not isinstance(value, str) or not value:
            raise KmsPolicyError("the service answered with an unexpected shape")
        _LOG.info("kms_call", operation=operation, host=self._host)
        return value


class KmsKeySource:
    """Seals and opens the vault data key through an external key-management service."""

    def __init__(self, client: KmsClient) -> None:
        self._client = client

    def __repr__(self) -> str:
        return "KmsKeySource(<redacted>)"

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        env: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> Self:
        """The source named by ``privacy.vault.kms``; the credential is resolved here."""
        section = settings.privacy.vault.kms
        if section.endpoint is None or section.key_id is None or section.token is None:
            raise KeySourceUnavailable("privacy.vault.kms is not fully configured")
        try:
            token = resolve_secret(str(section.token), env=env).get_secret_value()
        except ConfigError:
            raise KeySourceUnavailable("privacy.vault.kms.token could not be resolved") from None
        return cls(
            TransitKmsAdapter(
                endpoint=section.endpoint,
                key_id=section.key_id,
                token=token,
                host_allowlist=tuple(section.host_allowlist),
                timeout_seconds=section.timeout_seconds,
                transport=transport,
            )
        )

    def wrap(self, data_key: bytes) -> bytes:
        """The data key sealed by the service."""
        return self._client.wrap(data_key)

    def unwrap(self, blob: bytes) -> bytes:
        """The data key behind ``blob``."""
        return self._client.unwrap(blob)
