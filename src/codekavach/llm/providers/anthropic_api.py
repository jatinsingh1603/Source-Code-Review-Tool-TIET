"""The Anthropic Messages API adapter (E22-02).

Owning epic: E22.

``POST <base>/v1/messages`` with ``x-api-key`` and ``anthropic-version``. Structured output uses a
forced tool call: the verdict schema is the ``input_schema`` of one tool, ``record_verdict``, and
``tool_choice`` names it, so the answer arrives as the ``input`` object of a ``tool_use`` content
block, which ``extract_content`` reads. ``stop_reason = "refusal"`` raises ``ProviderRefused``.
"""

from typing import Any, ClassVar, Final

from codekavach.config.models.llm import ProviderKind
from codekavach.llm.providers.base import ProviderCapabilities, StructuredMode
from codekavach.llm.providers.http import (
    TOOL_DESCRIPTION,
    TOOL_NAME,
    HttpProvider,
)
from codekavach.llm.tasks.base import ReviewTask

ANTHROPIC_VERSION: Final = "2023-06-01"


class AnthropicProvider(HttpProvider):
    """Anthropic Messages with a forced tool call for the verdict."""

    kind: ClassVar[ProviderKind] = ProviderKind.ANTHROPIC
    capabilities = ProviderCapabilities(
        structured_output=True,
        context_window=200_000,
        tool_calling=True,
        structured_modes=(StructuredMode.TOOL, StructuredMode.PROMPT),
    )
    default_base_url: ClassVar[str | None] = "https://api.anthropic.com"

    def url(self) -> str:
        """``<base>/v1/messages`` (a base that already ends in ``/v1`` is accepted)."""
        base = self._base[: -len("/v1")] if self._base.endswith("/v1") else self._base
        return f"{base}/v1/messages"

    def body(self, task: ReviewTask, system: str, prompt: str) -> dict[str, Any]:
        """System text, one user message and the forced ``record_verdict`` tool; not streamed."""
        return {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [
                {
                    "name": TOOL_NAME,
                    "description": TOOL_DESCRIPTION,
                    "input_schema": task.output_schema(),
                }
            ],
            "tool_choice": {"type": "tool", "name": TOOL_NAME},
            "temperature": 0.0 if self._temperature is None else self._temperature,
            "stream": False,
        }

    def auth_headers(self, method: str, url: str, body: bytes) -> dict[str, str]:
        """``x-api-key`` and the API version header."""
        headers = {"anthropic-version": ANTHROPIC_VERSION}
        if self._key is not None:
            headers["x-api-key"] = self._key.get_secret_value()
        return headers
