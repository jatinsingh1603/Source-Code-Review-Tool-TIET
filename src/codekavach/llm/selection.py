"""Provider selection: what ``llm.default_provider`` and ``--provider`` resolve to (E22-01).

Owning epic: E22.

``select_provider`` is the one answer to "which provider does this run use". A named provider must
be configured (``ProviderNotConfigured`` otherwise, naming the configured ids). ``auto`` is the
rule of ``LLMSettings.select_provider``: the first enabled, non-offline provider that
``allow_remote`` permits and whose key reference resolves; otherwise ``mock`` with a
``fallback_reason`` (``no_provider_configured``, ``remote_not_allowed`` or ``no_key_available``).
"""

from dataclasses import dataclass
from typing import Any

from codekavach.config import Settings
from codekavach.config.models.llm import (
    AUTO,
    BUILTIN_PROVIDERS,
    PRESETS,
    ProviderSettings,
    key_available,
)
from codekavach.llm.providers.registry import REGISTRY, load_provider_metadata


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


def settings_for_provider(
    settings: Settings, provider_id: str, *, model: str | None = None
) -> Settings:
    """``settings`` with ``provider_id`` (and ``model``) chosen for one run, validated again.

    Validating again (not ``model_copy``) is what adds a built-in provider such as
    ``agentrouter`` when it is named, and what rejects an unknown id.

    Raises:
        ProviderNotConfigured: ``provider_id`` is neither configured nor built in.
    """
    document = settings.model_dump(mode="python", exclude_none=False)
    llm = dict(document.get("llm", {}))
    llm["default_provider"] = provider_id
    if model is not None:
        llm["model"] = model
    document["llm"] = llm
    try:
        return Settings.model_validate(document)
    except ValueError:
        raise ProviderNotConfigured(provider_id, tuple(sorted(settings.llm.providers))) from None


def _name(provider: ProviderSettings, fallback: str) -> str:
    preset = PRESETS.get(provider.preset or "")
    return preset.description if preset is not None and preset.description else fallback


def provider_catalogue(settings: Settings) -> list[dict[str, Any]]:
    """Every provider a run could use, as plain data for the API and the dashboard.

    One row per configured provider, plus each built-in provider that is not configured yet
    (``configured`` false until its key variable is set). Rows carry no key material: only
    whether a key reference resolves.
    """
    metadata = load_provider_metadata()
    providers = dict(settings.llm.providers)
    for builtin in BUILTIN_PROVIDERS:
        if builtin not in providers:
            providers[builtin] = ProviderSettings.model_validate({"preset": builtin})
    default = resolve_default_provider(settings)
    rows: list[dict[str, Any]] = []
    for provider_id, provider in providers.items():
        kind = provider.kind.value
        spec = REGISTRY.get(kind)
        row = metadata.get(kind)
        caps = spec.capabilities if spec is not None else None
        tier = provider.effective_trust_tier
        rows.append(
            {
                "id": provider_id,
                "name": _name(provider, row.display_name if row is not None else kind),
                "kind": kind,
                "models": [provider.model] if provider.model else [],
                "default_model": provider.model,
                "local": not provider.is_remote,
                "configured": provider.enabled and key_available(provider),
                "enabled": provider.enabled,
                "default": provider_id == default,
                "host": provider.host,
                "trust_tier": tier.value,
                "min_privacy_level": settings.privacy.floor_for_tier(tier).value,
                "adapter": spec is not None,
                "capabilities": {
                    "structured_output": bool(caps and caps.structured_output),
                    "structured_modes": list(caps.structured_modes) if caps else [],
                    "tool_calling": bool(caps and caps.tool_calling),
                    "context_window": caps.context_window if caps else None,
                    "streaming": False,
                },
                "retention_note": row.retention_note if row is not None else "",
            }
        )
    return rows
