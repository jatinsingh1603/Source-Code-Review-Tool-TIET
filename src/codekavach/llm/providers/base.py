"""The provider protocol: build a request from a sanitised payload, parse a response.

Owning epic: E13. MVP; extended by E22, which adds the hosted adapters, token budgets, cost
estimation and response caching.

**A provider prepares and parses; it does not send.** ``prepare`` takes a
``SanitisedPayload`` (never a slice or a candidate, invariant I2) and returns a
``PreparedRequest``: the serialised body that the egress guard will scan and the transport will
send. ``parse`` turns a ``RawResponse`` into an ``LLMVerdict``. Opening a connection belongs to
``codekavach.privacy.egress.transport`` alone (I1), and a provider cannot send because it never
holds a ticket. The two offline providers, ``mock`` and
``replay``, add a ``respond`` method that answers from memory or from disk; the stage calls it only
for a provider whose settings say it is not remote.

``PreparedRequest`` carries what a ledger entry and a provenance record need (provider, model,
payload hash, task, prompt version and hash) and nothing from the client's code.
"""

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol, runtime_checkable

from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.llm import ProviderKind
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.tasks.base import ReviewTask

MAX_RESPONSE_BYTES: Final = 1_048_576
OFFLINE_KINDS: Final = frozenset({ProviderKind.MOCK, ProviderKind.REPLAY})
# The kinds that have an adapter in this build; E22 adds the hosted ones.
SUPPORTED_KINDS: Final = OFFLINE_KINDS | {ProviderKind.OLLAMA}


class ProviderError(Exception):
    """A provider could not prepare a request or parse a response; ``reason`` is the message."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ProviderParseError(ProviderError):
    """The response is not a schema-valid verdict. The message never repeats the response text."""


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """What a provider can do, read by the stage and by the policy."""

    structured_output: bool
    context_window: int
    tool_calling: bool = False
    batch: bool = False
    local: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class PreparedRequest:
    """The request a provider built: structurally an ``OutboundRequest`` for the transport."""

    provider: str
    model: str
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes
    payload_hash: str
    task: str
    prompt_version: str
    prompt_hash: str
    candidate_id: str = field(default="")

    def __repr__(self) -> str:
        return (
            f"PreparedRequest(provider={self.provider!r}, task={self.task!r}, "
            f"payload={self.payload_hash[:12]}, bytes={len(self.body)})"
        )

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class RawResponse:
    """What came back, before parsing."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"RawResponse(status={self.status}, bytes={len(self.body)})"

    __str__ = __repr__


@runtime_checkable
class LLMProvider(Protocol):
    """An adapter for one provider kind."""

    id: str
    capabilities: ProviderCapabilities

    def prepare(self, task: ReviewTask, payload: SanitisedPayload) -> PreparedRequest:
        """Build the request for ``payload``; does not send."""
        ...

    def parse(self, raw: RawResponse) -> LLMVerdict:
        """The verdict in ``raw``.

        Raises:
            ProviderParseError: the response is malformed or violates the schema.
        """
        ...


@runtime_checkable
class OfflineProvider(LLMProvider, Protocol):
    """A provider that answers without a network: ``mock`` and ``replay``."""

    def respond(self, request: PreparedRequest) -> RawResponse:
        """The answer to ``request``, computed or read locally."""
        ...


def _responses_text(output: list[object]) -> str | None:
    """The answer text of an OpenAI Responses ``output`` array (``message`` items only)."""
    texts: list[str] = []
    for item in output:
        if isinstance(item, dict) and item.get("type") == "message":
            texts.extend(
                part["text"]
                for part in item.get("content") or []
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            )
    return "".join(texts) or None


def extract_content(body: bytes) -> str:
    """The model's text from the usual response envelopes.

    Understands ``{"content": ...}``, ``{"message": {"content": ...}}`` (Ollama) and
    ``{"choices": [{"message": {"content": ...}}]}`` (OpenAI-compatible). The content may itself be
    the JSON object (already decoded) or a string holding it.

    Raises:
        ProviderParseError: not JSON, not an envelope, or the content is missing.
    """
    if len(body) > MAX_RESPONSE_BYTES:
        raise ProviderParseError("response_too_large")
    try:
        document = json.loads(body)
    except ValueError:
        raise ProviderParseError("response_not_json") from None
    content: object = None
    if isinstance(document, dict):
        message = document.get("message")
        choices = document.get("choices")
        output = document.get("output")
        if "content" in document:
            content = document["content"]
        elif isinstance(output, list):
            content = _responses_text(output)
        elif isinstance(message, dict):
            content = message.get("content")
        elif isinstance(choices, list) and choices and isinstance(choices[0], dict):
            inner = choices[0].get("message")
            content = inner.get("content") if isinstance(inner, dict) else None
    if isinstance(content, dict):
        return json.dumps(content)
    if not isinstance(content, str) or not content.strip():
        raise ProviderParseError("response_without_content")
    return content


def verdict_from_text(text: str) -> LLMVerdict:
    """Validate ``text`` as an ``LLMVerdict``; the error names the failure, never the text.

    Raises:
        ProviderParseError: not JSON, or it breaks the verdict schema.
    """
    try:
        return LLMVerdict.model_validate_json(text)
    except ValidationError:
        raise ProviderParseError("verdict_violates_schema") from None
    except ValueError:
        raise ProviderParseError("verdict_not_json") from None


def parse_response(raw: RawResponse) -> LLMVerdict:
    """The verdict in a successful response (shared by the adapters)."""
    if not 200 <= raw.status < 300:
        raise ProviderParseError(f"http_status_{raw.status}")
    return verdict_from_text(extract_content(raw.body))


class ProviderRegistry:
    """Providers by id; iteration is in id order so nothing depends on registration order."""

    def __init__(self, providers: Mapping[str, LLMProvider] | None = None) -> None:
        self._providers: dict[str, LLMProvider] = dict(providers or {})

    def register(self, provider: LLMProvider) -> None:
        """Add ``provider``; a second provider with the same id is an error."""
        if provider.id in self._providers:
            raise ValueError(f"provider {provider.id!r} is already registered")
        self._providers[provider.id] = provider

    def get(self, provider_id: str) -> LLMProvider:
        """The provider with ``provider_id``.

        Raises:
            KeyError: there is none.
        """
        return self._providers[provider_id]

    @property
    def ids(self) -> tuple[str, ...]:
        """The registered ids, sorted."""
        return tuple(sorted(self._providers))

    def __iter__(self) -> Iterator[LLMProvider]:
        return (self._providers[provider_id] for provider_id in self.ids)

    def __len__(self) -> int:
        return len(self._providers)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of checking a provider without sending client data."""

    provider_id: str
    kind: str
    ok: bool
    reason: str
    network: bool


def probe_provider(provider_id: str, settings: Settings) -> ProbeResult:
    """Whether ``provider_id`` is configured and has an adapter in this build; opens no connection.

    A reachability check against a hosted endpoint needs the egress transport and a ledger entry
    (``Transport.probe``); this function is the offline half: it reports a missing or disabled
    provider and a kind with no adapter, and says whether a real probe would use the network.
    """
    provider = settings.llm.providers.get(provider_id)
    if provider is None:
        return ProbeResult(provider_id, "unknown", False, "provider_not_configured", False)
    network = provider.kind not in OFFLINE_KINDS
    if not provider.enabled:
        return ProbeResult(provider_id, provider.kind.value, False, "provider_disabled", network)
    if provider.kind not in SUPPORTED_KINDS:
        return ProbeResult(provider_id, provider.kind.value, False, "adapter_unavailable", network)
    return ProbeResult(provider_id, provider.kind.value, True, "ready", network)


def chat_body(
    *,
    model: str,
    prompt: str,
    schema: dict[str, object],
    temperature: float,
    max_tokens: int,
    extra: Mapping[str, object] | None = None,
) -> bytes:
    """The JSON body of a one-turn request: the instruction text, the schema and the sampling."""
    document: dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_schema", "json_schema": schema},
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if extra:
        document.update(extra)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
