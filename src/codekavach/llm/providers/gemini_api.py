"""Google Gemini adapters: the Gemini API and Vertex AI (E22-02).

Owning epic: E22.

Both use ``generateContent`` with ``generationConfig.responseMimeType = "application/json"`` and
the verdict schema as ``responseJsonSchema``. The answer is the text of the first candidate's
parts; a ``promptFeedback.blockReason`` or a safety ``finishReason`` raises ``ProviderRefused``.

* ``GeminiProvider``: ``POST <base>/models/<model>:generateContent`` with ``x-goog-api-key``.
* ``VertexProvider``: ``POST https://<location>-aiplatform.googleapis.com/v1/projects/<project>/
  locations/<location>/publishers/google/models/<model>:generateContent`` with a bearer access
  token (``api_key`` names where the token is; minting one from a service account is outside this
  adapter). ``options.project`` and ``options.location`` are required.

Generation is not streamed: ``generateContent``, not ``streamGenerateContent``.
"""

from typing import Any, ClassVar

from codekavach.config.models.llm import ProviderKind
from codekavach.llm.providers.base import ProviderCapabilities, ProviderError, StructuredMode
from codekavach.llm.providers.http import SYSTEM_PROMPT, HttpProvider
from codekavach.llm.tasks.base import ReviewTask


class GeminiProvider(HttpProvider):
    """The Gemini API (``generativelanguage.googleapis.com``)."""

    kind: ClassVar[ProviderKind] = ProviderKind.GEMINI
    capabilities = ProviderCapabilities(
        structured_output=True,
        context_window=1_000_000,
        tool_calling=True,
        structured_modes=(StructuredMode.JSON_SCHEMA, StructuredMode.PROMPT),
    )
    default_base_url: ClassVar[str | None] = "https://generativelanguage.googleapis.com/v1beta"

    def url(self) -> str:
        """``<base>/models/<model>:generateContent``."""
        return f"{self._base}/models/{self._model}:generateContent"

    def body(self, task: ReviewTask, prompt: str) -> dict[str, Any]:
        """System instruction, one user turn and a JSON-schema generation config."""
        return {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseJsonSchema": task.output_schema(),
                "temperature": 0.0 if self._temperature is None else self._temperature,
                "maxOutputTokens": self._max_tokens,
            },
        }

    def auth_headers(self, method: str, url: str, body: bytes) -> dict[str, str]:
        """The key goes in ``x-goog-api-key``, never in the URL."""
        if self._key is None:
            return {}
        return {"x-goog-api-key": self._key.get_secret_value()}


class VertexProvider(GeminiProvider):
    """Gemini on Vertex AI, addressed by project and location."""

    kind: ClassVar[ProviderKind] = ProviderKind.VERTEX
    default_base_url: ClassVar[str | None] = "https://aiplatform.googleapis.com"

    def url(self) -> str:
        """The regional ``generateContent`` URL of the publisher model."""
        project = self._options.get("project")
        location = self._options.get("location")
        if not isinstance(project, str) or not isinstance(location, str):
            raise ProviderError("vertex_needs_project_and_location")
        host = f"https://{location}-aiplatform.googleapis.com"
        if self._settings.base_url is not None:
            host = self._base
        return (
            f"{host}/v1/projects/{project}/locations/{location}"
            f"/publishers/google/models/{self._model}:generateContent"
        )

    def auth_headers(self, method: str, url: str, body: bytes) -> dict[str, str]:
        """A bearer access token."""
        return HttpProvider.auth_headers(self, method, url, body)
