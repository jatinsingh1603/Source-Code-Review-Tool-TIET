import tomllib
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.llm import (
    OLLAMA_DEFAULT_URL,
    LLMSettings,
    ProviderKind,
    ProviderSettings,
    TaskName,
)
from codekavach.core.models import TrustTier

EXAMPLE = """
[llm]
default_provider = "primary"

[llm.providers.primary]
kind = "anthropic"
model = "your-model-id"
api_key = "env:ANTHROPIC_API_KEY"

[llm.providers.lab]
kind = "openai-compatible"
base_url = "http://127.0.0.1:8000/v1"
model = "qwen2.5-coder-32b-instruct"
"""

# Minimal valid definition of every kind.
MINIMAL: dict[ProviderKind, dict[str, Any]] = {
    ProviderKind.ANTHROPIC: {"model": "m"},
    ProviderKind.OPENAI: {"model": "m"},
    ProviderKind.GEMINI: {"model": "m"},
    ProviderKind.XAI: {"model": "m"},
    ProviderKind.BEDROCK: {"model": "m", "region": "eu-west-1"},
    ProviderKind.AZURE_OPENAI: {"model": "m", "base_url": "https://x.openai.azure.com"},
    ProviderKind.OLLAMA: {"model": "m"},
    ProviderKind.OPENAI_COMPATIBLE: {"model": "m", "base_url": "https://llm.example.org/v1"},
    ProviderKind.LITELLM: {"model": "m"},
    ProviderKind.CLI_BRIDGE: {"model": "m", "command": ["tool", "--json"]},
    ProviderKind.MOCK: {},
    ProviderKind.REPLAY: {"cassette_dir": "cassettes"},
}


def message(error: ValidationError) -> str:
    details = error.errors()[0]
    return str(details.get("ctx", {}).get("error", details["msg"]))


def llm(**providers: dict[str, Any]) -> LLMSettings:
    return LLMSettings.model_validate({"providers": providers})


def test_defaults() -> None:
    settings = Settings().llm
    assert settings.providers.keys() == {"mock"}
    assert settings.default_provider == "auto"
    assert settings.model is None
    assert settings.enabled is True
    assert settings.allow_remote is True
    assert settings.tasks == [
        TaskName.TRIAGE,
        TaskName.EXPLAIN,
        TaskName.REMEDIATE,
        TaskName.SUMMARISE,
    ]
    assert settings.budget.max_requests is None
    mock = settings.providers["mock"]
    assert mock.effective_trust_tier is TrustTier.LOCAL
    assert mock.is_remote is False


def test_example_validates_with_stated_tiers() -> None:
    settings = Settings.model_validate(tomllib.loads(EXAMPLE))
    providers = settings.llm.providers
    assert providers.keys() == {"primary", "lab", "mock"}
    assert providers["primary"].effective_trust_tier is TrustTier.PUBLIC
    assert providers["primary"].is_remote is True
    assert providers["lab"].effective_trust_tier is TrustTier.LOCAL
    assert providers["lab"].is_remote is False


@pytest.mark.parametrize("kind", list(ProviderKind))
def test_minimal_definition_of_every_kind(kind: ProviderKind) -> None:
    assert llm(p={"kind": kind, **MINIMAL[kind]}).providers["p"].kind is kind


@pytest.mark.parametrize(
    ("kind", "missing"),
    [
        (kind, field)
        for kind, fields in MINIMAL.items()
        for field in fields
        if not (kind is ProviderKind.OLLAMA and field == "base_url")
    ],
)
def test_required_field_matrix(kind: ProviderKind, missing: str) -> None:
    fields = {key: value for key, value in MINIMAL[kind].items() if key != missing}
    with pytest.raises(ValidationError) as error:
        llm(p={"kind": kind, **fields})
    assert message(error.value).startswith("[CK-CFG-033]")
    assert f"llm.providers.p.{missing}" in message(error.value)


def test_anthropic_without_model_fails() -> None:
    with pytest.raises(ValidationError, match=r"CK-CFG-033"):
        llm(p={"kind": "anthropic"})


def test_ollama_gets_default_url() -> None:
    provider = llm(p={"kind": "ollama", "model": "m"}).providers["p"]
    assert str(provider.base_url).rstrip("/") == OLLAMA_DEFAULT_URL
    assert provider.effective_trust_tier is TrustTier.LOCAL


LOOPBACK = ["localhost", "127.0.0.1", "127.8.9.10", "[::1]", "[::ffff:127.0.0.1]"]
PRIVATE = ["10.1.2.3", "172.16.0.9", "192.168.1.20", "[fd00::1]"]
PUBLIC = ["llm.example.org", "8.8.8.8", "172.32.0.1", "[2001:db8::1]"]


@pytest.mark.parametrize("kind", list(ProviderKind))
@pytest.mark.parametrize("host", LOOPBACK + PRIVATE + PUBLIC)
def test_tier_derivation_table(kind: ProviderKind, host: str) -> None:
    fields = dict(MINIMAL[kind])
    if kind in {ProviderKind.OPENAI_COMPATIBLE, ProviderKind.LITELLM, ProviderKind.AZURE_OPENAI}:
        fields["base_url"] = f"https://{host}/v1"
    provider = llm(p={"kind": kind, **fields}).providers["p"]
    if kind in {ProviderKind.MOCK, ProviderKind.REPLAY, ProviderKind.OLLAMA}:
        expected = TrustTier.LOCAL
    elif kind in {ProviderKind.OPENAI_COMPATIBLE, ProviderKind.LITELLM}:
        expected = TrustTier.LOCAL if host in LOOPBACK else TrustTier.PUBLIC
    else:
        expected = TrustTier.PUBLIC
    assert provider.effective_trust_tier is expected
    assert provider.is_remote is (expected is TrustTier.PUBLIC)


def test_litellm_without_url_is_public() -> None:
    assert llm(p={"kind": "litellm", "model": "m"}).providers["p"].is_remote is True


def test_explicit_tier_wins() -> None:
    provider = llm(
        lan={
            "kind": "openai-compatible",
            "model": "m",
            "base_url": "http://192.168.1.20/v1",
            "trust_tier": "local",
        },
        pub={"kind": "ollama", "model": "m", "trust_tier": "public"},
    ).providers
    assert provider["lan"].effective_trust_tier is TrustTier.LOCAL
    assert provider["lan"].is_remote is False
    assert provider["pub"].is_remote is True


def compatible(url: str, **extra: Any) -> dict[str, Any]:
    return {"kind": "openai-compatible", "model": "m", "base_url": url, **extra}


@pytest.mark.parametrize("host", LOOPBACK + PRIVATE)
def test_http_accepted_for_local_and_private_hosts(host: str) -> None:
    llm(p=compatible(f"http://{host}:8000/v1"))


def test_http_to_public_host_needs_opt_in() -> None:
    with pytest.raises(ValidationError) as error:
        llm(p=compatible("http://llm.example.org/v1"))
    text = message(error.value)
    assert text.startswith("[CK-CFG-034]")
    assert "llm.providers.p" in text
    assert "llm.example.org" in text
    assert "/v1" not in text
    llm(p=compatible("http://llm.example.org/v1", allow_insecure_http=True))


@pytest.mark.parametrize("insecure", [False, True])
def test_user_information_always_fails(insecure: bool) -> None:
    with pytest.raises(ValidationError) as error:
        llm(p=compatible("https://user:pw@host/v1", allow_insecure_http=insecure))
    assert message(error.value).startswith("[CK-CFG-034]")
    assert "pw" not in str(error.value)


def test_non_http_scheme_rejected() -> None:
    with pytest.raises(ValidationError):
        llm(p=compatible("ftp://llm.example.org/v1"))


@given(
    user=st.text("abcdefghij0123456789", min_size=1, max_size=12),
    password=st.text("ABCDEFGHJK0123456789", min_size=6, max_size=24),
    host=st.sampled_from(["llm.example.org", "127.0.0.1", "10.0.0.5", "[::1]"]),
    scheme=st.sampled_from(["http", "https"]),
    insecure=st.booleans(),
)
def test_property_user_information_never_accepted_or_echoed(
    user: str, password: str, host: str, scheme: str, insecure: bool
) -> None:
    secret = f"Zq{password}"
    with pytest.raises(ValidationError) as error:
        llm(p=compatible(f"{scheme}://{user}:{secret}@{host}/v1", allow_insecure_http=insecure))
    assert "[CK-CFG-034]" in str(error.value)
    assert secret not in str(error.value)
    assert secret not in message(error.value)


@pytest.mark.parametrize("provider_id", ["Auto", "auto", "my-provider", "1x", "a" * 33, ""])
def test_bad_provider_ids(provider_id: str) -> None:
    with pytest.raises(ValidationError):
        LLMSettings.model_validate({"providers": {provider_id: {"kind": "mock"}}})


def test_good_provider_id() -> None:
    assert "azure_private" in llm(azure_private={"kind": "mock"}).providers


def test_mock_injection_keeps_user_entry() -> None:
    providers = llm(mock={"kind": "mock", "enabled": False}).providers
    assert providers["mock"].enabled is False
    assert providers.keys() == {"mock"}


def test_default_provider_must_exist_and_be_enabled() -> None:
    with pytest.raises(ValidationError) as error:
        LLMSettings.model_validate({"default_provider": "nope"})
    assert message(error.value).startswith("[CK-CFG-030]")
    with pytest.raises(ValidationError, match=r"CK-CFG-030"):
        LLMSettings.model_validate(
            {"default_provider": "p", "providers": {"p": {"kind": "mock", "enabled": False}}}
        )
    assert LLMSettings.model_validate({"default_provider": "mock"}).default_provider == "mock"


@pytest.mark.parametrize("value", ["", "   ", "x" * 201])
def test_model_override_length(value: str) -> None:
    with pytest.raises(ValidationError, match=r"CK-CFG-003"):
        LLMSettings.model_validate({"model": value})


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("temperature", -0.1),
        ("temperature", 2.1),
        ("max_output_tokens", 63),
        ("max_output_tokens", 65537),
        ("timeout_seconds", 0),
        ("max_retries", 11),
        ("consensus", 0),
        ("consensus", 6),
    ],
)
def test_ranges(key: str, value: float) -> None:
    with pytest.raises(ValidationError, match=r"CK-CFG-003"):
        LLMSettings.model_validate({key: value})


def test_negative_budget_rejected() -> None:
    with pytest.raises(ValidationError, match=r"CK-CFG-003"):
        LLMSettings.model_validate({"budget": {"max_cost_usd": -1}})


def test_empty_command_rejected() -> None:
    with pytest.raises(ValidationError, match=r"CK-CFG-003"):
        llm(p={"kind": "cli-bridge", "model": "m", "command": []})


def test_unknown_key_and_task_rejected() -> None:
    with pytest.raises(ValidationError):
        LLMSettings.model_validate({"tasks": ["guess"]})
    with pytest.raises(ValidationError):
        ProviderSettings.model_validate({"kind": "mock", "api_secret": "x"})


def test_plaintext_api_key_is_not_echoed() -> None:
    with pytest.raises(ValidationError) as error:
        llm(p={"kind": "openai", "model": "m", "api_key": "sk-NOTAREALKEY1234567890"})
    assert "NOTAREALKEY" not in str(error.value)
