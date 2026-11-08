"""Build the provider a settings entry names (E13-02).

Owning epic: E13. MVP; extended by E22, which adds the hosted adapters here.
"""

from codekavach.config.models.llm import ProviderKind, ProviderSettings
from codekavach.llm.providers.base import LLMProvider, ProviderError
from codekavach.llm.providers.mock import MockProvider
from codekavach.llm.providers.ollama import OllamaProvider
from codekavach.llm.providers.replay import ReplayProvider


def build_provider(provider_id: str, settings: ProviderSettings) -> LLMProvider:
    """The adapter for ``settings.kind``.

    Raises:
        ProviderError: the kind has no adapter in this build (the hosted ones arrive with E22) or
            the settings are unusable for it; the message is a reason code and nothing else.
    """
    if settings.kind is ProviderKind.MOCK:
        return MockProvider(provider_id, settings)
    if settings.kind is ProviderKind.REPLAY:
        return ReplayProvider(provider_id, settings)
    if settings.kind is ProviderKind.OLLAMA:
        return OllamaProvider(provider_id, settings)
    raise ProviderError("adapter_unavailable")
