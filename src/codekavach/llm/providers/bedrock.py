"""The AWS Bedrock adapter: the Converse API, signed with Signature Version 4 (E22-02).

Owning epic: E22.

``POST https://bedrock-runtime.<region>.amazonaws.com/model/<model-id>/converse``. Structured
output uses a forced tool (``toolConfig.toolChoice.tool``) whose ``inputSchema.json`` is the verdict
schema; the answer is the ``toolUse.input`` of the reply, which ``extract_content`` reads.

**Signing.** No AWS SDK: it would bring its own HTTP client, and ADR-0003 allows one. The request
is signed here with SigV4 (HMAC-SHA256 from the standard library) at prepare time; the transport
sends the headers unchanged. Credentials come from ``AWS_ACCESS_KEY_ID``,
``AWS_SECRET_ACCESS_KEY`` and, if set, ``AWS_SESSION_TOKEN`` (profiles, SSO and instance roles
are not resolved: export the variables, for example with ``aws configure export-credentials``).
A signature is valid for about five minutes, which is far longer than the guard and the
transport take; a retry prepares, and therefore signs, again.

``sign_v4`` is tested against the published AWS example request, so the algorithm is checked
offline; a live Bedrock call has not been verified from this repository.
"""

import datetime
import hashlib
import hmac
import os
from collections.abc import Callable, Mapping
from typing import Any, ClassVar, Final
from urllib.parse import quote, urlsplit

from pydantic import SecretStr

from codekavach.config.models.llm import ProviderKind, ProviderSettings
from codekavach.llm.providers.base import ProviderCapabilities, ProviderError, StructuredMode
from codekavach.llm.providers.http import (
    SYSTEM_PROMPT,
    TOOL_DESCRIPTION,
    TOOL_NAME,
    HttpProvider,
)
from codekavach.llm.tasks.base import ReviewTask

SERVICE: Final = "bedrock"
ALGORITHM: Final = "AWS4-HMAC-SHA256"


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        name, _, value = part.partition("=")
        pairs.append((quote(name, safe="-_.~"), quote(value, safe="-_.~")))
    return "&".join(f"{name}={value}" for name, value in sorted(pairs))


def sign_v4(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    now: datetime.datetime,
) -> dict[str, str]:
    """The SigV4 headers for a request: ``authorization``, ``x-amz-date`` and the body hash.

    ``headers`` are the headers that will be sent besides ``host``; all of them are signed.
    The canonical URI encodes each path segment once more, as AWS requires for every service
    except S3.
    """
    parts = urlsplit(url)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    signed: dict[str, str] = {name.lower(): value.strip() for name, value in headers.items()}
    signed["host"] = parts.netloc
    signed["x-amz-date"] = amz_date
    if session_token:
        signed["x-amz-security-token"] = session_token
    names = sorted(signed)
    canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in names)
    signed_names = ";".join(names)
    path = parts.path or "/"
    canonical_uri = "/".join(quote(segment, safe="-_.~") for segment in path.split("/"))
    canonical = "\n".join(
        (
            method.upper(),
            canonical_uri,
            _canonical_query(parts.query),
            canonical_headers,
            signed_names,
            payload_hash,
        )
    )
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        (ALGORITHM, amz_date, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    )
    key = _hmac(
        _hmac(_hmac(_hmac(f"AWS4{secret_key}".encode(), date), region), service), "aws4_request"
    )
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    result = {
        "authorization": (
            f"{ALGORITHM} Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={signature}"
        ),
        "x-amz-date": amz_date,
    }
    if session_token:
        result["x-amz-security-token"] = session_token
    return result


class BedrockProvider(HttpProvider):
    """Bedrock Converse with a forced tool for the verdict."""

    kind: ClassVar[ProviderKind] = ProviderKind.BEDROCK
    capabilities = ProviderCapabilities(
        structured_output=True,
        context_window=200_000,
        tool_calling=True,
        structured_modes=(StructuredMode.TOOL, StructuredMode.PROMPT),
    )
    needs_key: ClassVar[bool] = False

    def __init__(
        self,
        provider_id: str,
        settings: ProviderSettings,
        *,
        api_key: SecretStr | None = None,
        model: str | None = None,
        env: Mapping[str, str] | None = None,
        clock: Callable[[], datetime.datetime] | None = None,
    ) -> None:
        if not settings.region:
            raise ProviderError("bedrock_needs_region")
        self._region = settings.region
        if settings.base_url is None:
            settings = settings.model_copy(
                update={"base_url": f"https://bedrock-runtime.{settings.region}.amazonaws.com"}
            )
        super().__init__(provider_id, settings, api_key=api_key, model=model)
        environ = os.environ if env is None else env
        access = environ.get("AWS_ACCESS_KEY_ID", "")
        secret = environ.get("AWS_SECRET_ACCESS_KEY", "")
        if not access or not secret:
            raise ProviderError("aws_credentials_not_available")
        self._access = SecretStr(access)
        self._secret = SecretStr(secret)
        token = environ.get("AWS_SESSION_TOKEN")
        self._token = SecretStr(token) if token else None
        self._clock = clock or (lambda: datetime.datetime.now(datetime.UTC))

    def url(self) -> str:
        """``<base>/model/<model-id>/converse``; the model id is percent-encoded."""
        return f"{self._base}/model/{quote(self._model, safe='')}/converse"

    def body(self, task: ReviewTask, prompt: str) -> dict[str, Any]:
        """One user message, the system text and a forced tool; ``converse`` does not stream."""
        return {
            "system": [{"text": SYSTEM_PROMPT}],
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {
                "maxTokens": self._max_tokens,
                "temperature": 0.0 if self._temperature is None else self._temperature,
            },
            "toolConfig": {
                "tools": [
                    {
                        "toolSpec": {
                            "name": TOOL_NAME,
                            "description": TOOL_DESCRIPTION,
                            "inputSchema": {"json": task.output_schema()},
                        }
                    }
                ],
                "toolChoice": {"tool": {"name": TOOL_NAME}},
            },
        }

    def auth_headers(self, method: str, url: str, body: bytes) -> dict[str, str]:
        """SigV4 headers over the content type, the accept header and the body."""
        base = {
            "content-type": "application/json",
            "accept": "application/json",
            "x-amz-content-sha256": hashlib.sha256(body).hexdigest(),
        }
        signed = sign_v4(
            method=method,
            url=url,
            headers=base,
            body=body,
            region=self._region,
            service=SERVICE,
            access_key=self._access.get_secret_value(),
            secret_key=self._secret.get_secret_value(),
            session_token=self._token.get_secret_value() if self._token else None,
            now=self._clock(),
        )
        return {"x-amz-content-sha256": base["x-amz-content-sha256"], **signed}
