"""Shared machinery of the hosted adapters: one request shape, many wire formats (E22-02).

Owning epic: E22.

Every hosted adapter does the same three things: it renders the task prompt for a
``SanitisedPayload`` (never anything else, invariant I2), serialises a vendor-specific body around
it, and adds the authentication and fixed headers. It never sends: the ``PreparedRequest`` goes to
the egress session, which runs the guard, writes the ledger and hands it to the transport (I1).
No module here imports a network library.

**Bodies are canonical JSON** (sorted keys, compact separators) so that the same payload gives the
same bytes, the golden-file tests compare them byte for byte, and the schema text the task reports
as static occurs in the body exactly as the task serialises it.

**Requests are non-streaming.** The guard and the ledger reason about one complete request and one
complete response; every adapter sets the vendor's non-streaming form and a test asserts it.

**Keys live in headers only.** The key is a ``SecretStr`` resolved when the adapter is built; it
goes into the ``authorization``-style header of the prepared request, whose ``repr`` shows no
header, and is never put into a body, a URL or a log line.
"""

import json
from collections.abc import Mapping
from typing import Any, ClassVar, Final

from pydantic import SecretStr

from codekavach.config.models.llm import ProviderKind, ProviderSettings
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.base import (
    PreparedRequest,
    ProviderCapabilities,
    ProviderError,
    RawResponse,
    parse_response,
)
from codekavach.llm.tasks.base import CandidateFacts, ReviewTask

SYSTEM_PROMPT: Final = (
    "You are a meticulous application security reviewer. Follow the user's instructions exactly "
    "and answer only with the JSON object they describe."
)
TOOL_NAME: Final = "record_verdict"
TOOL_DESCRIPTION: Final = "Record the security verdict for the code under review."
HEADER_OPTION_PREFIX: Final = "header:"
DEFAULT_MAX_OUTPUT_TOKENS: Final = 4096


def canonical_json(document: Mapping[str, Any]) -> bytes:
    """The body bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def schema_name(task: ReviewTask) -> str:
    """The name of the structured-output schema of ``task`` (``triage_verdict``)."""
    return f"{task.name}_verdict"


class HttpProvider:
    """Base class of the hosted adapters; subclasses supply the URL, the body and the auth."""

    kind: ClassVar[ProviderKind]
    capabilities: ProviderCapabilities
    default_base_url: ClassVar[str | None] = None
    needs_key: ClassVar[bool] = True

    def __init__(
        self,
        provider_id: str,
        settings: ProviderSettings,
        *,
        api_key: SecretStr | None = None,
        model: str | None = None,
    ) -> None:
        chosen = model or settings.model
        if chosen is None:
            raise ProviderError("model_not_configured")
        base = str(settings.base_url) if settings.base_url is not None else self.default_base_url
        if base is None:
            raise ProviderError("base_url_not_configured")
        if self.needs_key and api_key is None:
            raise ProviderError("api_key_not_available")
        self.id = provider_id
        self._settings = settings
        self._model = chosen
        self._base = base.rstrip("/")
        self._key = api_key
        options = settings.options
        self._options = options
        self._extra_headers = {
            name[len(HEADER_OPTION_PREFIX) :].lower(): str(value)
            for name, value in options.items()
            if name.startswith(HEADER_OPTION_PREFIX)
        }
        tokens = options.get("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS)
        self._max_tokens = (
            int(tokens) if isinstance(tokens, int | float) else DEFAULT_MAX_OUTPUT_TOKENS
        )
        temperature = options.get("temperature")
        self._temperature: float | None = (
            float(temperature)
            if isinstance(temperature, int | float) and not isinstance(temperature, bool)
            else None
        )

    @property
    def model(self) -> str:
        """The model this adapter asks."""
        return self._model

    # -- what subclasses provide -----------------------------------------------------------

    def url(self) -> str:
        """The endpoint URL of one request."""
        raise NotImplementedError

    def body(self, task: ReviewTask, prompt: str) -> dict[str, Any]:
        """The vendor body around ``prompt``."""
        raise NotImplementedError

    def auth_headers(self, method: str, url: str, body: bytes) -> dict[str, str]:
        """The authentication headers (bearer token unless a subclass says otherwise)."""
        if self._key is None:
            return {}
        return {"authorization": f"Bearer {self._key.get_secret_value()}"}

    # -- the protocol ----------------------------------------------------------------------

    def prepare(self, task: ReviewTask, payload: SanitisedPayload) -> PreparedRequest:
        """The request for ``payload``; does not send."""
        facts = CandidateFacts.from_payload(payload)
        prompt = task.render(payload, facts)
        body = canonical_json(self.body(task, prompt))
        url = self.url()
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            **self._extra_headers,
            **self.auth_headers("POST", url, body),
        }
        return PreparedRequest(
            provider=self.id,
            model=self._model,
            method="POST",
            url=url,
            headers=headers,
            body=body,
            payload_hash=payload.payload_hash,
            task=task.name,
            prompt_version=task.prompt_version,
            prompt_hash=task.prompt_hash,
            candidate_id=str(payload.candidate_id),
        )

    def parse(self, raw: RawResponse) -> LLMVerdict:
        """The verdict in ``raw``."""
        return parse_response(raw)

    def static_text(self) -> tuple[str, ...]:
        """Fixed text this adapter adds to every body; none of it derives from client code."""
        return (SYSTEM_PROMPT, TOOL_NAME, TOOL_DESCRIPTION)
