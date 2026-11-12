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
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.llm import ProviderKind
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.tasks.base import ReviewTask

MAX_RESPONSE_BYTES: Final = 1_048_576
OFFLINE_KINDS: Final = frozenset({ProviderKind.MOCK, ProviderKind.REPLAY})
# The kinds that have an adapter in this build; the command bridge has none (see registry).
SUPPORTED_KINDS: Final = frozenset(ProviderKind) - {ProviderKind.CLI_BRIDGE}


class ProviderError(Exception):
    """A provider could not prepare a request or parse a response; ``reason`` is the message."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ProviderParseError(ProviderError):
    """The response is not a schema-valid verdict. The message never repeats the response text."""


class ProviderRefused(ProviderParseError):  # noqa: N818 - the name is the issue's wording
    """The model declined to answer (a content-policy refusal); never retried or repaired."""


class ProviderUnavailable(ProviderParseError):  # noqa: N818 - the name is the issue's wording
    """The provider answered with an error status (unauthorised, rate limited, server error)."""

    def __init__(self, reason: str, status: int = 0) -> None:
        super().__init__(reason)
        self.status = status


class StructuredMode:
    """How an adapter asks for a verdict-shaped answer, strongest first."""

    JSON_SCHEMA: Final = "json_schema"  # strict schema-constrained decoding
    TOOL: Final = "tool"  # a forced tool call whose input is the verdict
    JSON_OBJECT: Final = "json_object"  # any JSON object, validated afterwards
    PROMPT: Final = "prompt"  # the schema is stated in the prompt only

    ORDER: Final = (JSON_SCHEMA, TOOL, JSON_OBJECT, PROMPT)


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """What a provider can do, read by the stage and by the policy."""

    structured_output: bool
    context_window: int
    tool_calling: bool = False
    batch: bool = False
    local: bool = False
    structured_modes: tuple[str, ...] = (StructuredMode.PROMPT,)
    streaming: bool = False

    @property
    def best_structured_mode(self) -> str:
        """The strongest structured-output mode this adapter supports."""
        for mode in StructuredMode.ORDER:
            if mode in self.structured_modes:
                return mode
        return StructuredMode.PROMPT


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


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _from_parts(parts: list[Any]) -> object:
    """The text (or tool input) of a list of content parts; a refusal part raises."""
    texts: list[str] = []
    for part in parts:
        item = _dict(part)
        kind = item.get("type")
        if kind == "refusal" or ("refusal" in item and item.get("refusal")):
            raise ProviderRefused("model_refused")
        if kind in {"tool_use", "function_call"} and isinstance(item.get("input"), dict):
            return item["input"]
        tool = _dict(item.get("toolUse"))  # Bedrock Converse
        if isinstance(tool.get("input"), dict):
            return tool["input"]
        call = _dict(item.get("functionCall"))  # Gemini
        if isinstance(call.get("args"), dict):
            return call["args"]
        if isinstance(item.get("text"), str) and not item.get("thought"):
            texts.append(item["text"])
    return "".join(texts) if texts else None


def _content_of(document: dict[str, Any]) -> object:  # noqa: PLR0911, PLR0912
    message = document.get("message")
    choices = document.get("choices")
    if document.get("stop_reason") == "refusal":  # Anthropic
        raise ProviderRefused("model_refused")
    if "content" in document:
        content = document["content"]
        return _from_parts(content) if isinstance(content, list) else content
    if isinstance(message, dict):
        if message.get("refusal"):
            raise ProviderRefused("model_refused")
        content = message.get("content")
        return _from_parts(content) if isinstance(content, list) else content
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        inner = _dict(choices[0].get("message"))
        if inner.get("refusal") or choices[0].get("finish_reason") == "content_filter":
            raise ProviderRefused("model_refused")
        for call in _list(inner.get("tool_calls")):
            arguments = _dict(_dict(call).get("function")).get("arguments")
            if isinstance(arguments, str):
                return arguments
        return inner.get("content")
    if isinstance(document.get("output"), list):  # OpenAI Responses API
        for item in document["output"]:
            entry = _dict(item)
            if entry.get("type") == "message":
                found = _from_parts(_list(entry.get("content")))
                if found is not None:
                    return found
            if entry.get("type") == "function_call" and isinstance(entry.get("arguments"), str):
                return entry["arguments"]
        return document.get("output_text")
    if isinstance(document.get("output"), dict):  # Bedrock Converse
        content = _dict(_dict(document["output"]).get("message")).get("content")
        if document.get("stopReason") == "content_filtered":
            raise ProviderRefused("model_refused")
        return _from_parts(_list(content))
    if "candidates" in document or "promptFeedback" in document:  # Gemini
        if _dict(document.get("promptFeedback")).get("blockReason"):
            raise ProviderRefused("model_refused")
        candidates = _list(document.get("candidates"))
        if not candidates:
            raise ProviderRefused("model_refused")
        first = _dict(candidates[0])
        if first.get("finishReason") in {"SAFETY", "RECITATION", "PROHIBITED_CONTENT", "BLOCKLIST"}:
            raise ProviderRefused("model_refused")
        return _from_parts(_list(_dict(first.get("content")).get("parts")))
    if "output_text" in document:
        return document["output_text"]
    return None


def _document(body: bytes) -> object:
    if len(body) > MAX_RESPONSE_BYTES:
        raise ProviderParseError("response_too_large")
    try:
        return json.loads(body)
    except ValueError:
        raise ProviderParseError("response_not_json") from None


def extract_content(body: bytes) -> str:
    """The model's text from the usual response envelopes.

    Understands ``{"content": ...}``, ``{"message": {"content": ...}}`` (Ollama),
    ``{"choices": [{"message": {"content": ...}}]}`` (OpenAI Chat Completions and compatible
    servers, including tool calls), ``{"output": [{"type": "message", ...}]}`` (OpenAI Responses),
    a list of content parts (Anthropic Messages, including a forced ``tool_use``),
    ``{"candidates": [...]}`` (Gemini) and ``{"output": {"message": ...}}`` (Bedrock Converse).
    The content may itself be the JSON object (already decoded) or a string holding it.

    Raises:
        ProviderRefused: the envelope says the model refused or a safety filter blocked it.
        ProviderParseError: not JSON, not an envelope, or the content is missing.
    """
    document = _document(body)
    content: object = None
    if isinstance(document, dict):
        content = _content_of(document)
    if isinstance(content, dict):
        return json.dumps(content)
    if not isinstance(content, str) or not content.strip():
        raise ProviderParseError("response_without_content")
    return content


@dataclass(frozen=True, slots=True)
class Usage:
    """Token counts reported by the provider (zero when it reports none)."""

    input_tokens: int = 0
    output_tokens: int = 0


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def usage_of(body: bytes) -> Usage:
    """The token usage in a response envelope, from whichever field the vendor uses."""
    try:
        document = json.loads(body)
    except ValueError:
        return Usage()
    if not isinstance(document, dict):
        return Usage()
    usage = _dict(document.get("usage")) or _dict(document.get("usageMetadata"))
    input_tokens = (
        _int(usage.get("input_tokens"))
        or _int(usage.get("prompt_tokens"))
        or _int(usage.get("inputTokens"))
        or _int(usage.get("promptTokenCount"))
        or _int(document.get("prompt_eval_count"))
    )
    output_tokens = (
        _int(usage.get("output_tokens"))
        or _int(usage.get("completion_tokens"))
        or _int(usage.get("outputTokens"))
        or _int(usage.get("candidatesTokenCount"))
        or _int(document.get("eval_count"))
    )
    return Usage(input_tokens, output_tokens)


_FENCE = re.compile(r"^```[a-zA-Z0-9_-]*\s*\n(?P<body>.*?)\n?```$", re.DOTALL)


def unwrap_json(text: str) -> str:
    """``text`` without one surrounding Markdown code fence; anything else is left alone.

    Prose before or after the object is not stripped: an answer that mixes the two is rejected by
    validation, because which object to trust would be a guess.
    """
    stripped = text.strip()
    match = _FENCE.match(stripped)
    return match.group("body").strip() if match else stripped


def verdict_from_text(text: str) -> LLMVerdict:
    """Validate ``text`` as an ``LLMVerdict``; the error names the failure, never the text.

    A single surrounding Markdown code fence is accepted and removed.

    Raises:
        ProviderParseError: not JSON, or it breaks the verdict schema.
    """
    try:
        return LLMVerdict.model_validate_json(unwrap_json(text))
    except ValidationError:
        raise ProviderParseError("verdict_violates_schema") from None
    except ValueError:
        raise ProviderParseError("verdict_not_json") from None


def parse_response(raw: RawResponse) -> LLMVerdict:
    """The verdict in a successful response (shared by the adapters).

    Raises:
        ProviderUnavailable: the status is not 2xx (the reason names the status only).
        ProviderRefused: the model refused.
        ProviderParseError: the answer is not a schema-valid verdict.
    """
    if not 200 <= raw.status < 300:
        raise ProviderUnavailable(f"http_status_{raw.status}", raw.status)
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
