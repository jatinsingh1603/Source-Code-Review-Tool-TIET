"""The adapter registry: which kind is served by which adapter, and what each one is (E22-01).

Owning epic: E22.

Every member of ``ProviderKind`` has a metadata row (``load_provider_metadata``): its wire format,
whether it runs on this machine, whether it needs a key, its structured-output modes and a
retention note for ``codekavach providers list``. A test fails when a kind is added without a
row. The retention notes state what the operator must check; they do not paraphrase any vendor's
terms, which change and differ per contract.

Adapters are published as ``codekavach.providers`` entry points whose names are the kinds; each
entry point names an ``AdapterSpec`` (callable, returning itself, because the plugin registry
calls the factory it loads). ``build_registry`` refuses two specs for the same kind and names both
entry points.

**Building is the only place a key is resolved.** ``build_adapter`` resolves the provider's key
reference (``codekavach.config.keys``) into a ``SecretStr`` held by the adapter; a missing key is a
``ProviderError`` with a reason code, never a value.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from codekavach.config.errors import SecretResolutionError
from codekavach.config.keys import resolve_provider_key
from codekavach.config.models.llm import ProviderKind, ProviderSettings
from codekavach.llm.providers.anthropic_api import AnthropicProvider
from codekavach.llm.providers.base import (
    LLMProvider,
    ProviderCapabilities,
    ProviderError,
    StructuredMode,
)
from codekavach.llm.providers.bedrock import BedrockProvider
from codekavach.llm.providers.gemini_api import GeminiProvider, VertexProvider
from codekavach.llm.providers.http import HttpProvider
from codekavach.llm.providers.mock import MockProvider
from codekavach.llm.providers.ollama import OllamaProvider
from codekavach.llm.providers.openai_api import (
    AzureOpenAIProvider,
    LiteLlmProvider,
    OpenAIChatProvider,
    OpenAIHostedChatProvider,
    OpenAIResponsesProvider,
    XaiProvider,
)
from codekavach.llm.providers.replay import ReplayProvider

PROVIDERS_GROUP: Final = "codekavach.providers"


class DuplicateAdapterError(ValueError):
    """Two adapters claim the same kind."""


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """What a kind is, for listings and documentation."""

    kind: str
    display_name: str
    wire_format: str
    local: bool
    needs_key: bool
    retention_note: str
    verification: str  # live | offline | unavailable


_VENDOR_NOTE: Final = (
    "Hosted: payloads leave the machine; check the vendor's data-retention and training terms "
    "for your account before use."
)
_LOCAL_NOTE: Final = "Runs on this machine; nothing is retained by a third party."
_DEPENDS_NOTE: Final = (
    "Retention depends on where base_url points: local servers keep nothing off the machine, "
    "hosted gateways follow their own terms."
)

_METADATA: Final[Mapping[ProviderKind, ProviderMetadata]] = MappingProxyType(
    {
        ProviderKind.ANTHROPIC: ProviderMetadata(
            "anthropic", "Anthropic", "anthropic-messages", False, True, _VENDOR_NOTE, "offline"
        ),
        ProviderKind.OPENAI: ProviderMetadata(
            "openai", "OpenAI", "openai-responses", False, True, _VENDOR_NOTE, "live"
        ),
        ProviderKind.GEMINI: ProviderMetadata(
            "gemini", "Google Gemini", "gemini-generate-content", False, True, _VENDOR_NOTE,
            "offline",
        ),
        ProviderKind.XAI: ProviderMetadata(
            "xai", "xAI", "openai-chat", False, True, _VENDOR_NOTE, "offline"
        ),
        ProviderKind.BEDROCK: ProviderMetadata(
            "bedrock", "AWS Bedrock", "bedrock-converse", False, True, _VENDOR_NOTE, "offline"
        ),
        ProviderKind.AZURE_OPENAI: ProviderMetadata(
            "azure-openai", "Azure OpenAI", "openai-chat", False, True, _VENDOR_NOTE, "offline"
        ),
        ProviderKind.OLLAMA: ProviderMetadata(
            "ollama", "Ollama (native)", "ollama-chat", True, False, _LOCAL_NOTE, "offline"
        ),
        ProviderKind.OPENAI_COMPATIBLE: ProviderMetadata(
            "openai-compatible", "OpenAI-compatible server", "openai-chat", False, False,
            _DEPENDS_NOTE, "offline",
        ),
        ProviderKind.LITELLM: ProviderMetadata(
            "litellm", "LiteLLM proxy", "openai-chat", False, False, _DEPENDS_NOTE, "offline"
        ),
        ProviderKind.CLI_BRIDGE: ProviderMetadata(
            "cli-bridge", "Local CLI bridge", "subprocess", True, False,
            "Not available in this build.", "unavailable",
        ),
        ProviderKind.MOCK: ProviderMetadata(
            "mock", "Mock (offline)", "none", True, False, _LOCAL_NOTE, "offline"
        ),
        ProviderKind.REPLAY: ProviderMetadata(
            "replay", "Replay (recorded)", "none", True, False, _LOCAL_NOTE, "offline"
        ),
        ProviderKind.VERTEX: ProviderMetadata(
            "vertex", "Google Vertex AI", "gemini-generate-content", False, True, _VENDOR_NOTE,
            "offline",
        ),
    }
)  # fmt: skip


def load_provider_metadata() -> Mapping[str, ProviderMetadata]:
    """One metadata row per ``ProviderKind`` member, by kind value."""
    return MappingProxyType({kind.value: row for kind, row in _METADATA.items()})


Builder = Callable[[str, ProviderSettings, Any], LLMProvider]


@dataclass(frozen=True, slots=True)
class AdapterSpec:
    """One adapter kind: its capabilities and how to build it from settings."""

    kind: ProviderKind
    capabilities: ProviderCapabilities
    builder: Builder = field(repr=False)
    entry_point: str = ""

    def __call__(self) -> "AdapterSpec":
        """The spec itself: the plugin registry calls what an entry point names."""
        return self

    def build(self, provider_id: str, settings: ProviderSettings, key: Any) -> LLMProvider:
        """The adapter for ``settings``."""
        return self.builder(provider_id, settings, key)


def _openai(provider_id: str, settings: ProviderSettings, key: Any) -> LLMProvider:
    wire = str(settings.options.get("wire_api", "responses"))
    if wire == "chat":
        return OpenAIHostedChatProvider(provider_id, settings, api_key=key)
    if wire != "responses":
        raise ProviderError("wire_api_not_supported")
    return OpenAIResponsesProvider(provider_id, settings, api_key=key)


def _http(cls: type[HttpProvider]) -> Builder:
    def build(provider_id: str, settings: ProviderSettings, key: Any) -> LLMProvider:
        return cls(provider_id, settings, api_key=key)

    return build


def _compatible(provider_id: str, settings: ProviderSettings, key: Any) -> LLMProvider:
    if str(settings.options.get("wire_api", "chat")) == "responses":
        return OpenAIResponsesProvider(provider_id, settings, api_key=key)
    return OpenAIChatProvider(provider_id, settings, api_key=key)


def _spec(kind: ProviderKind, capabilities: ProviderCapabilities, builder: Builder) -> AdapterSpec:
    return AdapterSpec(kind, capabilities, builder, f"{PROVIDERS_GROUP}:{kind.value}")


def _local(cls: Any) -> Builder:
    def build(provider_id: str, settings: ProviderSettings, key: Any) -> LLMProvider:
        provider: LLMProvider = cls(provider_id, settings)
        return provider

    return build


openai_spec = _spec(ProviderKind.OPENAI, OpenAIResponsesProvider.capabilities, _openai)
openai_compatible_spec = _spec(
    ProviderKind.OPENAI_COMPATIBLE, OpenAIChatProvider.capabilities, _compatible
)
xai_spec = _spec(ProviderKind.XAI, XaiProvider.capabilities, _http(XaiProvider))
litellm_spec = _spec(ProviderKind.LITELLM, LiteLlmProvider.capabilities, _http(LiteLlmProvider))
azure_openai_spec = _spec(
    ProviderKind.AZURE_OPENAI, AzureOpenAIProvider.capabilities, _http(AzureOpenAIProvider)
)
anthropic_spec = _spec(
    ProviderKind.ANTHROPIC, AnthropicProvider.capabilities, _http(AnthropicProvider)
)
gemini_spec = _spec(ProviderKind.GEMINI, GeminiProvider.capabilities, _http(GeminiProvider))
vertex_spec = _spec(ProviderKind.VERTEX, VertexProvider.capabilities, _http(VertexProvider))
bedrock_spec = _spec(ProviderKind.BEDROCK, BedrockProvider.capabilities, _http(BedrockProvider))
ollama_spec = _spec(ProviderKind.OLLAMA, OllamaProvider.capabilities, _local(OllamaProvider))
mock_spec = _spec(ProviderKind.MOCK, MockProvider.capabilities, _local(MockProvider))
replay_spec = _spec(ProviderKind.REPLAY, ReplayProvider.capabilities, _local(ReplayProvider))

BUILTIN_SPECS: Final = (
    anthropic_spec,
    openai_spec,
    gemini_spec,
    xai_spec,
    bedrock_spec,
    azure_openai_spec,
    ollama_spec,
    openai_compatible_spec,
    litellm_spec,
    mock_spec,
    replay_spec,
    vertex_spec,
)


def build_registry(specs: Iterable[AdapterSpec] = BUILTIN_SPECS) -> Mapping[str, AdapterSpec]:
    """The specs by kind value.

    Raises:
        DuplicateAdapterError: two specs claim one kind; the message names both entry points.
    """
    found: dict[str, AdapterSpec] = {}
    for spec in specs:
        previous = found.get(spec.kind.value)
        if previous is not None:
            raise DuplicateAdapterError(
                f"provider kind {spec.kind.value!r} is registered twice: "
                f"{previous.entry_point} and {spec.entry_point}"
            )
        found[spec.kind.value] = spec
    return MappingProxyType(found)


REGISTRY: Final = build_registry()


def resolve_key(provider_id: str, settings: ProviderSettings) -> Any:
    """The provider's key as a ``SecretStr``, or ``None`` when it needs none.

    Raises:
        ProviderError: ``api_key_not_available`` when a key is needed and does not resolve.
    """
    if settings.kind in {ProviderKind.MOCK, ProviderKind.REPLAY, ProviderKind.OLLAMA}:
        return None
    try:
        return resolve_provider_key(provider_id, settings)
    except SecretResolutionError:
        raise ProviderError("api_key_not_available") from None


def build_adapter(
    provider_id: str, settings: ProviderSettings, *, model: str | None = None
) -> LLMProvider:
    """The adapter for ``settings`` (with ``model`` overriding the configured one).

    Raises:
        ProviderError: no adapter for the kind (``adapter_unavailable``), a missing key or
            unusable settings; the message is a reason code.
    """
    spec = REGISTRY.get(settings.kind.value)
    if spec is None:
        raise ProviderError("adapter_unavailable")
    if model is not None:
        settings = settings.model_copy(update={"model": model})
    return spec.build(provider_id, settings, resolve_key(provider_id, settings))


def choose_strategy(capabilities: ProviderCapabilities, pinned: str | None = None) -> str:
    """The structured-output mode to use: the strongest supported, or ``pinned`` if supported.

    Raises:
        ProviderError: ``pinned`` is not a mode this adapter supports.
    """
    if pinned is None:
        return capabilities.best_structured_mode
    if pinned not in StructuredMode.ORDER or pinned not in capabilities.structured_modes:
        raise ProviderError(f"structured_mode_not_supported {pinned}")
    return pinned
