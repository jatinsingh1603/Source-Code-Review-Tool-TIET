"""The ``[llm]`` section: request settings, budget and named providers.

Owning epic: E03.

Every provider has a trust tier that the privacy policy reads (ARCHITECTURE section 6.1). An
explicit ``trust_tier`` wins; otherwise the tier is derived from the kind and, for
``openai-compatible`` and ``litellm``, from the ``base_url`` host. Host classification uses
``ipaddress`` only and never resolves DNS, because configuration loading is offline (ADR D9).

Endpoint URLs decide where payloads and keys go, so ``base_url`` rejects embedded credentials
and plain ``http`` to hosts outside the machine or the private network unless
``allow_insecure_http`` is set. Error messages name the provider id and the host, never the URL.

``default_provider = "auto"`` is resolved by E22: the first enabled provider in declaration
order, other than ``mock`` and ``replay``, that ``allow_remote`` permits and whose key resolves or
which needs none; failing that, ``mock``.
"""

import ipaddress
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Final, Self

from pydantic import AfterValidator, AnyHttpUrl, Field, field_validator, model_validator

from codekavach.config.keys import SecretRef
from codekavach.config.models.base import (
    INVALID,
    SectionModel,
    bounds,
    in_range,
    restricted,
    volatile,
)
from codekavach.core.models import TrustTier

UNKNOWN_PROVIDER = "[CK-CFG-030]"
MISSING_FIELD = "[CK-CFG-033]"
BAD_URL = "[CK-CFG-034]"
AUTO = "auto"
MOCK = "mock"
MAX_MODEL_LENGTH = 200
OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"

_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_LOCALHOST = frozenset({"localhost", "localhost."})
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


class ProviderKind(StrEnum):
    """The adapter kinds of ARCHITECTURE section 7."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"
    XAI = "xai"
    BEDROCK = "bedrock"
    AZURE_OPENAI = "azure-openai"
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai-compatible"
    LITELLM = "litellm"
    CLI_BRIDGE = "cli-bridge"
    MOCK = "mock"
    REPLAY = "replay"
    VERTEX = "vertex"


class TaskName(StrEnum):
    """The LLM tasks a scan may run."""

    TRIAGE = "triage"
    DISCOVER = "discover"
    EXPLAIN = "explain"
    REMEDIATE = "remediate"
    CLASSIFY = "classify"
    SUMMARISE = "summarise"


_ALWAYS_LOCAL = frozenset({ProviderKind.MOCK, ProviderKind.REPLAY, ProviderKind.OLLAMA})
_HOST_DERIVED = frozenset({ProviderKind.OPENAI_COMPATIBLE, ProviderKind.LITELLM})
_OFFLINE = frozenset({ProviderKind.MOCK, ProviderKind.REPLAY})
_REQUIRED_BY_KIND: dict[ProviderKind, tuple[str, ...]] = {
    ProviderKind.OPENAI_COMPATIBLE: ("base_url",),
    ProviderKind.AZURE_OPENAI: ("base_url",),
    ProviderKind.BEDROCK: ("region",),
    ProviderKind.REPLAY: ("cassette_dir",),
    ProviderKind.CLI_BRIDGE: ("command",),
}

AGENTROUTER = "agentrouter"


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    """Defaults a ``preset = "<name>"`` entry fills in; anything set explicitly wins.

    ``options`` may carry ``wire_api`` (``responses`` or ``chat``) and extra request headers as
    ``header:<name>`` keys; the transport's header allow-list still applies to them.
    """

    name: str
    kind: ProviderKind
    base_url: str | None
    model: str | None
    api_key: str | None = None
    options: Mapping[str, str | int | float | bool] = dataclass_field(default_factory=dict)
    description: str = ""


PRESETS: Mapping[str, ProviderPreset] = MappingProxyType(
    {
        AGENTROUTER: ProviderPreset(
            name=AGENTROUTER,
            kind=ProviderKind.OPENAI,
            base_url="https://agentrouter.org/v1",
            model="gpt-5.6-sol",
            api_key="env:CODEKAVACH_AGENTROUTER_API_KEY",
            options=MappingProxyType(
                {
                    "wire_api": "responses",
                    "header:user-agent": "codex_cli_rs/0.50.0",
                    "header:originator": "codex_cli_rs",
                    "reasoning_effort": "low",
                    "concurrency": 6,
                }
            ),
            description="AgentRouter gateway (OpenAI Responses API)",
        ),
        "openai": ProviderPreset(
            "openai", ProviderKind.OPENAI, "https://api.openai.com/v1", None,
            options=MappingProxyType({"wire_api": "responses"}), description="OpenAI",
        ),
        "anthropic": ProviderPreset(
            "anthropic", ProviderKind.ANTHROPIC, "https://api.anthropic.com", None,
            description="Anthropic Messages API",
        ),
        "gemini": ProviderPreset(
            "gemini", ProviderKind.GEMINI,
            "https://generativelanguage.googleapis.com/v1beta", None,
            description="Google Gemini API",
        ),
        "xai": ProviderPreset(
            "xai", ProviderKind.XAI, "https://api.x.ai/v1", None, description="xAI",
        ),
        "openrouter": ProviderPreset(
            "openrouter", ProviderKind.OPENAI_COMPATIBLE, "https://openrouter.ai/api/v1", None,
            api_key="env:OPENROUTER_API_KEY", description="OpenRouter (chat completions)",
        ),
        "lmstudio": ProviderPreset(
            "lmstudio", ProviderKind.OPENAI_COMPATIBLE, "http://127.0.0.1:1234/v1", None,
            description="LM Studio local server",
        ),
        "vllm": ProviderPreset(
            "vllm", ProviderKind.OPENAI_COMPATIBLE, "http://127.0.0.1:8000/v1", None,
            description="vLLM local server",
        ),
        "ollama-openai": ProviderPreset(
            "ollama-openai", ProviderKind.OPENAI_COMPATIBLE, "http://127.0.0.1:11434/v1", None,
            description="Ollama through its OpenAI-compatible /v1 endpoint",
        ),
    }
)  # fmt: skip
# Built-in providers, by id, with the variable that holds their key. Such a provider is added from
# its preset when it is named as ``default_provider`` (``--provider agentrouter``) or when its key
# variable (or ``<VARIABLE>_FILE``, the path of a file holding the key) is set, unless an entry
# with the same id is configured. ``auto`` never picks one: a key in the environment is not a
# decision to send code to that provider.
BUILTIN_PROVIDERS: Final[Mapping[str, str]] = MappingProxyType(
    {AGENTROUTER: "CODEKAVACH_AGENTROUTER_API_KEY"}
)


def _preset_key_ref(ref: str) -> str:
    """A preset's ``env:NAME`` key reference, or ``file:PATH`` when only ``NAME_FILE`` is set.

    ``NAME_FILE`` names a file holding the key (the container secret-file convention), so a key
    never has to be exported into the environment.
    """
    if not ref.startswith("env:"):
        return ref
    variable = ref.removeprefix("env:")
    key_file = os.environ.get(f"{variable}_FILE", "").strip()
    if key_file and not os.environ.get(variable, "").strip():
        return f"file:{key_file}"
    return ref


def _address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_loopback_host(host: str | None) -> bool:
    """True for ``localhost`` and loopback address literals (``127.0.0.0/8``, ``::1``)."""
    if not host:
        return False
    if host.lower() in _LOCALHOST:
        return True
    address = _address(host)
    return address is not None and address.is_loopback


def is_private_host(host: str | None) -> bool:
    """True for loopback hosts and RFC 1918 or unique-local address literals; no DNS lookup."""
    if is_loopback_host(host):
        return True
    address = _address(host or "")
    return address is not None and any(address in net for net in _PRIVATE_NETWORKS)


def _check_model(value: str | None) -> str | None:
    if value is not None and not 1 <= len(value) <= MAX_MODEL_LENGTH:
        raise ValueError(f"{INVALID} model must be 1 to {MAX_MODEL_LENGTH} characters")
    return value


def _check_provider_id(value: str) -> str:
    if value == AUTO or not _PROVIDER_ID.match(value):
        raise ValueError(
            f"{INVALID} llm.providers ids match ^[a-z][a-z0-9_]{{0,31}}$ and are not 'auto'"
        )
    return value


def _check_non_negative(value: float | None) -> float | None:
    if value is not None and value < 0:
        raise ValueError(f"{INVALID} llm.budget limits must not be negative")
    return value


ModelName = Annotated[str | None, AfterValidator(_check_model)]
ProviderId = Annotated[str, AfterValidator(_check_provider_id)]
NonNegativeInt = Annotated[int | None, AfterValidator(_check_non_negative)]
NonNegativeFloat = Annotated[float | None, AfterValidator(_check_non_negative)]


class BudgetSettings(SectionModel):
    """Limits for one scan; ``None`` means unlimited."""

    max_requests: NonNegativeInt = Field(default=None, description="Maximum LLM requests.")
    max_total_input_tokens: NonNegativeInt = Field(
        default=None, description="Maximum input tokens across all requests."
    )
    max_total_output_tokens: NonNegativeInt = Field(
        default=None, description="Maximum output tokens across all requests."
    )
    max_cost_usd: NonNegativeFloat = Field(
        default=None, description="Maximum estimated cost in US dollars."
    )


class ProviderSettings(SectionModel):
    """One named LLM provider."""

    kind: ProviderKind = Field(description="Adapter kind.")
    preset: str | None = Field(
        default=None,
        description="Named preset that fills base_url, model, key reference and options.",
    )
    enabled: bool = Field(default=True, description="Whether the provider may be selected.")
    model: ModelName = Field(default=None, description="Model identifier sent to the provider.")
    base_url: AnyHttpUrl | None = Field(
        default=None,
        description="Endpoint URL; where payloads and the API key are sent.",
        json_schema_extra=restricted(),
    )
    allow_insecure_http: bool = Field(
        default=False,
        description="Accept plain http to a host outside the machine or private network.",
        json_schema_extra=restricted(),
    )
    api_key: SecretRef | None = Field(default=None, description="Secret reference to the API key.")
    trust_tier: TrustTier | None = Field(
        default=None,
        description="Trust tier; derived from the kind and host when unset.",
        json_schema_extra=restricted(),
    )
    region: str | None = Field(default=None, description="Cloud region (bedrock).")
    aws_profile: str | None = Field(default=None, description="AWS profile name (bedrock).")
    azure_deployment: str | None = Field(
        default=None, description="Deployment name (azure-openai)."
    )
    api_version: str | None = Field(default=None, description="API version (azure-openai).")
    cassette_dir: Path | None = Field(
        default=None, description="Directory of recorded responses (replay)."
    )
    command: list[str] | None = Field(
        default=None,
        description="Command line of the local CLI to run (cli-bridge).",
        json_schema_extra=restricted(),
    )
    options: dict[str, str | int | float | bool] = Field(
        default_factory=dict, description="Adapter-specific options."
    )

    @model_validator(mode="before")
    @classmethod
    def _apply_preset(cls, value: Any) -> Any:
        if not isinstance(value, dict) or value.get("preset") is None:
            return value
        preset = PRESETS.get(str(value["preset"]))
        if preset is None:
            raise ValueError(f"{INVALID} preset must be one of {', '.join(sorted(PRESETS))}")
        merged: dict[str, Any] = {"kind": preset.kind}
        if preset.base_url is not None:
            merged["base_url"] = preset.base_url
        if preset.model is not None:
            merged["model"] = preset.model
        if preset.api_key is not None:
            merged["api_key"] = _preset_key_ref(preset.api_key)
        merged.update({key: item for key, item in value.items() if item is not None})
        options = dict(preset.options)
        options.update(value.get("options") or {})
        merged["options"] = options
        return merged

    @model_validator(mode="before")
    @classmethod
    def _ollama_default_url(cls, value: Any) -> Any:
        if (
            isinstance(value, dict)
            and value.get("kind") == ProviderKind.OLLAMA
            and value.get("base_url") is None
        ):
            return {**value, "base_url": OLLAMA_DEFAULT_URL}
        return value

    @field_validator("command")
    @classmethod
    def _check_command(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and (not value or not all(value)):
            raise ValueError(f"{INVALID} command must be a non-empty list of non-empty strings")
        return value

    @property
    def host(self) -> str | None:
        """The ``base_url`` host without IPv6 brackets, or ``None``."""
        if self.base_url is None or self.base_url.host is None:
            return None
        return self.base_url.host.strip("[]")

    @property
    def preset_host(self) -> str | None:
        """The host of the preset's own endpoint when ``base_url`` was not changed, else ``None``.

        Such a host ships with the release, so egress treats it as allow-listed.
        """
        preset = PRESETS.get(self.preset or "")
        if preset is None or preset.base_url is None or self.base_url is None:
            return None
        if str(self.base_url).rstrip("/") != preset.base_url.rstrip("/"):
            return None
        return self.host

    @property
    def effective_trust_tier(self) -> TrustTier:
        """The explicit tier, or the one derived from the kind and host."""
        if self.trust_tier is not None:
            return self.trust_tier
        if self.kind in _ALWAYS_LOCAL:
            return TrustTier.LOCAL
        if self.kind in _HOST_DERIVED and is_loopback_host(self.host):
            return TrustTier.LOCAL
        return TrustTier.PUBLIC

    @property
    def is_remote(self) -> bool:
        """False for ``mock``, ``replay`` and any provider whose effective tier is local."""
        return self.kind not in _OFFLINE and self.effective_trust_tier is not TrustTier.LOCAL

    def check(self, provider_id: str) -> None:
        """Raise ``ValueError`` (033 or 034) when required fields or the endpoint are unsafe."""
        key = f"llm.providers.{provider_id}"
        if self.model is None and self.kind not in _OFFLINE:
            raise ValueError(f"{MISSING_FIELD} {key}.model is required for kind {self.kind}")
        for field in _REQUIRED_BY_KIND.get(self.kind, ()):
            if getattr(self, field) is None:
                raise ValueError(f"{MISSING_FIELD} {key}.{field} is required for kind {self.kind}")
        if self.kind is ProviderKind.VERTEX:
            for option in ("project", "location"):
                if not self.options.get(option):
                    raise ValueError(
                        f"{MISSING_FIELD} {key}.options.{option} is required for kind {self.kind}"
                    )
        if self.base_url is None:
            return
        host = self.host or ""
        if self.base_url.username or self.base_url.password:
            raise ValueError(
                f"{BAD_URL} {key}.base_url for host {host} must not contain user information"
            )
        if (
            self.base_url.scheme == "http"
            and not self.allow_insecure_http
            and not is_private_host(host)
        ):
            raise ValueError(
                f"{BAD_URL} {key}.base_url for host {host} must use https "
                "(or set allow_insecure_http)"
            )


class LLMSettings(SectionModel):
    """How findings are sent to language models, and which ones."""

    enabled: bool = Field(
        default=True, description="False runs deterministic engines only; nothing leaves."
    )
    default_provider: str = Field(
        default=AUTO, description="A provider id, or auto to pick the first usable one."
    )
    model: ModelName = Field(
        default=None, description="Overrides the model of the selected provider for this run."
    )
    allow_remote: bool = Field(
        default=True, description="False forbids every provider that is remote."
    )
    tasks: list[TaskName] = Field(
        default_factory=lambda: [
            TaskName.TRIAGE,
            TaskName.EXPLAIN,
            TaskName.REMEDIATE,
            TaskName.SUMMARISE,
        ],
        description="LLM tasks to run.",
    )
    temperature: float = Field(default=0.0, description="Sampling temperature, 0.0 to 2.0.")
    max_output_tokens: Annotated[int, in_range(64, 65536, "llm.max_output_tokens")] = Field(
        default=2048,
        description="Maximum output tokens per request.",
        json_schema_extra=bounds(64, 65536),
    )
    timeout_seconds: Annotated[int, in_range(1, 3600, "llm.timeout_seconds")] = Field(
        default=120,
        description="Timeout of one request in seconds.",
        json_schema_extra=bounds(1, 3600) | volatile(),
    )
    max_retries: Annotated[int, in_range(0, 10, "llm.max_retries")] = Field(
        default=2,
        description="Retries of a failed request.",
        json_schema_extra=bounds(0, 10) | volatile(),
    )
    max_repair_attempts: Annotated[int, in_range(0, 3, "llm.max_repair_attempts")] = Field(
        default=1,
        description="Times an answer that fails to parse or validate is asked again.",
        json_schema_extra=bounds(0, 3) | volatile(),
    )
    consensus: Annotated[int, in_range(1, 5, "llm.consensus")] = Field(
        default=1,
        description="Models or samples asked per candidate.",
        json_schema_extra=bounds(1, 5),
    )
    cache: bool = Field(
        default=True,
        description="Cache responses keyed on the payload hash.",
        json_schema_extra=volatile(),
    )
    budget: BudgetSettings = Field(
        default_factory=BudgetSettings, description="Limits for one scan."
    )
    providers: dict[ProviderId, ProviderSettings] = Field(
        default_factory=dict,
        description="Named providers; mock is always present.",
        json_schema_extra=restricted(),
    )

    @model_validator(mode="before")
    @classmethod
    def _inject_mock(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        providers = value.get("providers", {})
        if not isinstance(providers, dict):
            return value
        added = dict(providers)
        if MOCK not in added:
            added[MOCK] = {"kind": ProviderKind.MOCK}
        for builtin, variable in BUILTIN_PROVIDERS.items():
            if builtin in added:
                continue
            named = value.get("default_provider") == builtin
            keyed = os.environ.get(variable, "").strip() or os.environ.get(f"{variable}_FILE", "")
            if named or keyed.strip():
                added[builtin] = {"preset": builtin}
        if len(added) == len(providers):
            return value
        return {**value, "providers": added}

    @field_validator("temperature")
    @classmethod
    def _check_temperature(cls, value: float) -> float:
        if not 0.0 <= value <= 2.0:
            raise ValueError(f"{INVALID} llm.temperature must be between 0.0 and 2.0")
        return value

    @model_validator(mode="after")
    def _check_providers(self) -> Self:
        for provider_id, provider in self.providers.items():
            provider.check(provider_id)
        if self.default_provider != AUTO:
            chosen = self.providers.get(self.default_provider)
            if chosen is None:
                raise ValueError(
                    f"{UNKNOWN_PROVIDER} llm.default_provider must be auto or a key of "
                    "llm.providers"
                )
            if not chosen.enabled:
                raise ValueError(f"{UNKNOWN_PROVIDER} llm.default_provider names a disabled one")
        return self

    def selected_provider(self) -> tuple[str, ProviderSettings]:
        """The provider this scan uses: the named default, or the first usable one for ``auto``.

        ``auto`` takes the first enabled provider in declaration order that is neither ``mock`` nor
        ``replay``, that ``allow_remote`` permits and whose key reference resolves (or which needs
        none); failing that, ``mock``. Only ``env:`` and ``file:`` references are checked here (a
        keyring reference counts as present, so selection never opens the keyring).
        """
        return self.select_provider()[:2]

    def select_provider(self) -> tuple[str, ProviderSettings, str | None]:
        """Like ``selected_provider``, with the fallback reason when ``mock`` was chosen.

        The reason is ``no_provider_configured``, ``remote_not_allowed`` or ``no_key_available``
        for an ``auto`` that fell back, and ``None`` otherwise.
        """
        if self.default_provider != AUTO:
            return self.default_provider, self.providers[self.default_provider], None
        reason = "no_provider_configured"
        for provider_id, provider in self.providers.items():
            if provider.kind in _OFFLINE or not provider.enabled:
                continue
            if provider_id in BUILTIN_PROVIDERS and provider.preset == provider_id:
                continue  # added from its preset, not configured: never chosen implicitly
            if provider.is_remote and not self.allow_remote:
                reason = "remote_not_allowed"
                continue
            if not key_available(provider):
                if reason == "no_provider_configured":
                    reason = "no_key_available"
                continue
            return provider_id, provider, None
        mock = self.providers.get(MOCK)
        return MOCK, mock if mock is not None else ProviderSettings(kind=ProviderKind.MOCK), reason


_KEYED_KINDS: Final = frozenset(
    {
        ProviderKind.ANTHROPIC,
        ProviderKind.OPENAI,
        ProviderKind.GEMINI,
        ProviderKind.XAI,
        ProviderKind.AZURE_OPENAI,
        ProviderKind.VERTEX,
        ProviderKind.BEDROCK,
    }
)
_DEFAULT_KEY_VARIABLES: Final[Mapping[ProviderKind, tuple[str, ...]]] = MappingProxyType(
    {
        ProviderKind.ANTHROPIC: ("ANTHROPIC_API_KEY",),
        ProviderKind.OPENAI: ("OPENAI_API_KEY",),
        ProviderKind.GEMINI: ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        ProviderKind.XAI: ("XAI_API_KEY",),
        ProviderKind.AZURE_OPENAI: ("AZURE_OPENAI_API_KEY",),
        ProviderKind.VERTEX: ("VERTEX_ACCESS_TOKEN",),
        ProviderKind.BEDROCK: ("AWS_ACCESS_KEY_ID",),
    }
)


def key_available(provider: ProviderSettings, env: Mapping[str, str] | None = None) -> bool:
    """Whether the provider's key reference looks resolvable, without reading any value.

    ``env:`` must be set and non-empty, ``file:`` must name an existing file, ``keyring:`` counts
    as present. A provider without a reference needs one only for the hosted kinds.
    """
    environ = os.environ if env is None else env
    refs: tuple[str, ...]
    if provider.api_key:
        refs = (provider.api_key,)
    else:
        refs = tuple(f"env:{name}" for name in _DEFAULT_KEY_VARIABLES.get(provider.kind, ()))
        if not refs:
            return provider.kind not in _KEYED_KINDS
    for ref in refs:
        scheme, _, locator = ref.partition(":")
        if scheme == "env" and environ.get(locator, "").strip():
            return True
        if scheme == "file" and Path(locator).expanduser().is_file():
            return True
        if scheme == "keyring":
            return True
    return False


def preset_hosts(llm: LLMSettings) -> tuple[str, ...]:
    """Hosts of enabled providers on their preset's unchanged endpoint (see ``preset_host``)."""
    return tuple(
        sorted(
            {
                host
                for provider in llm.providers.values()
                if provider.enabled and (host := provider.preset_host) is not None
            }
        )
    )
