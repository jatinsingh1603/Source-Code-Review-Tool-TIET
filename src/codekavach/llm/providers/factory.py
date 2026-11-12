"""Build the provider a settings entry names (E13-02, E22-01).

Owning epic: E13. Extended by E22: every kind is served through ``registry.build_adapter``.
"""

from codekavach.config.models.llm import ProviderSettings
from codekavach.llm.providers.base import LLMProvider
from codekavach.llm.providers.registry import build_adapter


def build_provider(
    provider_id: str, settings: ProviderSettings, *, model: str | None = None
) -> LLMProvider:
    """The adapter for ``settings.kind``.

    Raises:
        ProviderError: the kind has no adapter in this build, its key does not resolve, or the
            settings are unusable for it; the message is a reason code and nothing else.
    """
    return build_adapter(provider_id, settings, model=model)
