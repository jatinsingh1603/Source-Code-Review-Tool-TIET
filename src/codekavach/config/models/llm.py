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
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Self

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
        if isinstance(providers, dict) and MOCK not in providers:
            return {**value, "providers": {**providers, MOCK: {"kind": ProviderKind.MOCK}}}
        return value

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
