"""Provider selection: what ``llm.default_provider`` and ``--provider`` resolve to (E22-01).

Owning epic: E22.

``select_provider`` is the one answer to "which provider does this run use". A named provider must
be configured (``ProviderNotConfigured`` otherwise, naming the configured ids). ``auto`` is the
rule of ``LLMSettings.select_provider``: the first enabled, non-offline provider that
``allow_remote`` permits and whose key reference resolves; otherwise ``mock`` with a
``fallback_reason`` (``no_provider_configured``, ``remote_not_allowed`` or ``no_key_available``).
"""

from dataclasses import dataclass

from codekavach.config import Settings
from codekavach.config.models.llm import AUTO, ProviderSettings


class ProviderNotConfigured(LookupError):  # noqa: N818 - the name is the issue's wording
    """The requested provider id is not in ``llm.providers``."""

    def __init__(self, provider_id: str, configured: tuple[str, ...]) -> None:
        super().__init__(
            f"provider {provider_id!r} is not configured; configured providers: "
            f"{', '.join(configured)}"
        )
        self.provider_id = provider_id
        self.configured = configured


@dataclass(frozen=True, slots=True)
class Selection:
    """The provider a run uses, and why ``mock`` was chosen when it was a fallback."""

    provider_id: str
    settings: ProviderSettings
    model: str | None
    fallback_reason: str | None = None


def select_provider(settings: Settings, requested: str | None = None) -> Selection:
    """The provider for ``requested`` (a provider id, ``auto`` or ``None`` for the default).

    Raises:
        ProviderNotConfigured: ``requested`` names no configured provider.
    """
    llm = settings.llm
    if requested is not None and requested != AUTO:
        provider = llm.providers.get(requested)
        if provider is None:
            raise ProviderNotConfigured(requested, tuple(sorted(llm.providers)))
        return Selection(requested, provider, llm.model or provider.model)
    if requested == AUTO and llm.default_provider != AUTO:
        llm = llm.model_copy(update={"default_provider": AUTO})
    provider_id, provider, reason = llm.select_provider()
    return Selection(provider_id, provider, llm.model or provider.model, reason)


def resolve_default_provider(settings: Settings) -> str:
    """The id of the provider a scan would use (``codekavach providers list`` shows it)."""
    return select_provider(settings).provider_id
