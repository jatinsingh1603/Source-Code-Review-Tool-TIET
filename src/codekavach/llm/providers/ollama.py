"""The local-model provider (Ollama-style servers): a request for a server on this machine.

Owning epic: E13. MVP; extended by E22.

**Self-hosted is not local.** Ollama can route a model tag to a vendor's cloud: a tag that ends in
``-cloud`` (or ``:cloud``) is served by Ollama's hosted service, not by the local runner, so
sending a payload to it sends the payload to a third party while the settings still say "local".
This provider refuses such tags and any base URL on Ollama's own domain, so ``local = True`` is a
statement about where the bytes go and not about the product name
(``docs/research/INSIGHTS.md`` insight 6 and section 7). The trust tier of the provider is derived
from the kind and the host in the settings (E03), and the egress guard applies the tier's floor.

The request goes to ``<base_url>/api/chat`` with the schema as ``format``, which Ollama uses for
structured output. Sending is the transport's job.
"""

import json
import re
from typing import Final

from codekavach.config.models.llm import ProviderSettings
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

CHAT_PATH: Final = "/api/chat"
_CLOUD_TAG: Final = re.compile(r"(?:^|[:/_-])cloud$", re.IGNORECASE)
_CLOUD_HOSTS: Final = ("ollama.com", "ollama.ai")


class CloudModelRefused(ProviderError):  # noqa: N818 - the name is the issue's wording
    """The model tag or the endpoint would be served by a vendor's cloud."""


def check_local(model: str, host: str | None) -> None:
    """Refuse a model tag or a host that routes to a vendor's cloud.

    Raises:
        CloudModelRefused: the tag ends in ``cloud`` or the host is on Ollama's domain.
    """
    if _CLOUD_TAG.search(model.strip()):
        raise CloudModelRefused("cloud_model_tag_refused")
    lowered = (host or "").lower().strip(".")
    if any(lowered == domain or lowered.endswith("." + domain) for domain in _CLOUD_HOSTS):
        raise CloudModelRefused("cloud_endpoint_refused")


class OllamaProvider:
    """Builds requests for a local inference server."""

    capabilities = ProviderCapabilities(
        structured_output=True, context_window=32_768, tool_calling=False, local=True
    )

    def __init__(self, provider_id: str, settings: ProviderSettings) -> None:
        if settings.model is None or settings.base_url is None:
            raise ProviderError("ollama_needs_model_and_base_url")
        check_local(settings.model, settings.host)
        self.id = provider_id
        self._model = settings.model
        self._base = str(settings.base_url).rstrip("/")

    def prepare(self, task: ReviewTask, payload: SanitisedPayload) -> PreparedRequest:
        """The ``/api/chat`` request for ``payload``."""
        facts = CandidateFacts.from_payload(payload)
        document = {
            "model": self._model,
            "messages": [{"role": "user", "content": task.render(payload, facts)}],
            "stream": False,
            "format": task.output_schema(),
            "options": {"temperature": 0},
        }
        return PreparedRequest(
            provider=self.id,
            model=self._model,
            method="POST",
            url=self._base + CHAT_PATH,
            headers={"content-type": "application/json"},
            body=json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            payload_hash=payload.payload_hash,
            task=task.name,
            prompt_version=task.prompt_version,
            prompt_hash=task.prompt_hash,
            candidate_id=str(payload.candidate_id),
        )

    def parse(self, raw: RawResponse) -> LLMVerdict:
        """The verdict in an Ollama chat response."""
        return parse_response(raw)
