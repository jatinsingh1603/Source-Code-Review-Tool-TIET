"""OpenAI wire formats: the Responses API, Chat Completions and their compatible servers (E22-02).

Owning epic: E22.

* ``OpenAIResponsesProvider``: ``POST <base>/responses`` with ``instructions``, one user ``input``
  message and ``text.format`` set to a strict JSON schema. It is the default for kind ``openai``
  and the wire format of the ``agentrouter`` preset (``options.wire_api = "responses"``).
* ``OpenAIChatProvider``: ``POST <base>/chat/completions`` with a system and a user message and
  ``response_format`` set to a strict JSON schema (``options.structured_mode = "json_object"``
  asks for any JSON object instead, for servers without schema support). It serves kind
  ``openai`` with ``options.wire_api = "chat"``, ``openai-compatible`` (vLLM, LM Studio, Ollama's
  ``/v1``, OpenRouter), ``litellm`` and ``xai``.
* ``AzureOpenAIProvider``: Chat Completions on an Azure deployment, keyed with ``api-key``.

The answer text lives in ``output[].content[].text`` of a ``message`` item (Responses) or in
``choices[0].message.content`` (Chat); ``extract_content`` reads both, and a ``refusal`` part or
field raises ``ProviderRefused``.
"""

from typing import Any, ClassVar, Final

from codekavach.config.models.llm import ProviderKind
from codekavach.llm.providers.base import ProviderCapabilities, ProviderError, StructuredMode
from codekavach.llm.providers.http import SYSTEM_PROMPT, HttpProvider, schema_name
from codekavach.llm.tasks.base import ReviewTask

AZURE_DEFAULT_API_VERSION: Final = "2024-10-21"
_STRICT_MODES: Final = (
    StructuredMode.JSON_SCHEMA,
    StructuredMode.JSON_OBJECT,
    StructuredMode.PROMPT,
)


class OpenAIResponsesProvider(HttpProvider):
    """The OpenAI Responses API (``/responses``)."""

    kind: ClassVar[ProviderKind] = ProviderKind.OPENAI
    capabilities = ProviderCapabilities(
        structured_output=True,
        context_window=400_000,
        tool_calling=True,
        structured_modes=_STRICT_MODES,
    )
    default_base_url: ClassVar[str | None] = "https://api.openai.com/v1"

    def url(self) -> str:
        """``<base>/responses``."""
        return f"{self._base}/responses"

    def body(self, task: ReviewTask, prompt: str) -> dict[str, Any]:
        """Instructions, one user message and a strict schema; not streamed, not stored."""
        document: dict[str, Any] = {
            "model": self._model,
            "instructions": SYSTEM_PROMPT,
            "input": [{"role": "user", "content": prompt}],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": schema_name(task),
                    "strict": True,
                    "schema": task.output_schema(),
                }
            },
            "max_output_tokens": self._max_tokens,
            "stream": False,
            "store": False,
        }
        if self._temperature is not None:
            document["temperature"] = self._temperature
        effort = self._options.get("reasoning_effort")
        if isinstance(effort, str) and effort:
            document["reasoning"] = {"effort": effort}
        return document


class OpenAIChatProvider(HttpProvider):
    """Chat Completions (``/chat/completions``), for OpenAI and every compatible server."""

    kind: ClassVar[ProviderKind] = ProviderKind.OPENAI_COMPATIBLE
    capabilities = ProviderCapabilities(
        structured_output=True,
        context_window=128_000,
        tool_calling=True,
        structured_modes=_STRICT_MODES,
    )
    default_base_url: ClassVar[str | None] = None
    needs_key: ClassVar[bool] = False

    def url(self) -> str:
        """``<base>/chat/completions``."""
        return f"{self._base}/chat/completions"

    def _response_format(self, task: ReviewTask) -> dict[str, Any]:
        mode = str(self._options.get("structured_mode", StructuredMode.JSON_SCHEMA))
        if mode == StructuredMode.JSON_OBJECT:
            return {"type": "json_object"}
        if mode != StructuredMode.JSON_SCHEMA:
            raise ProviderError("structured_mode_not_supported")
        return {
            "type": "json_schema",
            "json_schema": {
                "name": schema_name(task),
                "strict": True,
                "schema": task.output_schema(),
            },
        }

    def body(self, task: ReviewTask, prompt: str) -> dict[str, Any]:
        """A system and a user message with a strict ``response_format``; not streamed."""
        return {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": self._response_format(task),
            "max_tokens": self._max_tokens,
            "temperature": 0.0 if self._temperature is None else self._temperature,
            "stream": False,
        }


class OpenAIHostedChatProvider(OpenAIChatProvider):
    """Chat Completions on api.openai.com (``options.wire_api = "chat"``)."""

    kind: ClassVar[ProviderKind] = ProviderKind.OPENAI
    default_base_url: ClassVar[str | None] = "https://api.openai.com/v1"
    needs_key: ClassVar[bool] = True


class XaiProvider(OpenAIChatProvider):
    """xAI's OpenAI-compatible Chat Completions endpoint."""

    kind: ClassVar[ProviderKind] = ProviderKind.XAI
    default_base_url: ClassVar[str | None] = "https://api.x.ai/v1"
    needs_key: ClassVar[bool] = True


class LiteLlmProvider(OpenAIChatProvider):
    """A LiteLLM proxy, which speaks Chat Completions."""

    kind: ClassVar[ProviderKind] = ProviderKind.LITELLM


class AzureOpenAIProvider(OpenAIChatProvider):
    """Chat Completions on an Azure OpenAI deployment."""

    kind: ClassVar[ProviderKind] = ProviderKind.AZURE_OPENAI
    needs_key: ClassVar[bool] = True

    def url(self) -> str:
        """``<base>/openai/deployments/<deployment>/chat/completions?api-version=<v>``."""
        deployment = self._settings.azure_deployment or self._model
        version = self._settings.api_version or AZURE_DEFAULT_API_VERSION
        return (
            f"{self._base}/openai/deployments/{deployment}/chat/completions?api-version={version}"
        )

    def auth_headers(self, method: str, url: str, body: bytes) -> dict[str, str]:
        """Azure keys go in ``api-key``."""
        if self._key is None:
            return {}
        return {"api-key": self._key.get_secret_value()}
