"""The provider protocol and the mock, replay and local-model providers (E13-02)."""

import dataclasses
import json
import socket
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.config.models.llm import ProviderSettings
from codekavach.core.models.payload import PayloadFacts, SanitisedPayload
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.base import (
    LLMProvider,
    OfflineProvider,
    ProviderError,
    ProviderParseError,
    ProviderRegistry,
    RawResponse,
    extract_content,
    probe_provider,
    verdict_from_text,
)
from codekavach.llm.providers.mock import MockProvider, verdict_for
from codekavach.llm.providers.ollama import CloudModelRefused, OllamaProvider, check_local
from codekavach.llm.providers.replay import (
    CassetteMissingError,
    RecordRefusedError,
    ReplayProvider,
)
from codekavach.llm.tasks.triage import TriageTask
from tests.support.factories import make_payload, make_verdict

FACTS = PayloadFacts(rule="KB-VULN-001", cwe=(89,), strategy="enclosing_function")
TASK = TriageTask()


def payload() -> SanitisedPayload:
    return make_payload(facts=FACTS)


def ollama_settings(
    model: str = "llama3:8b", url: str = "http://127.0.0.1:11434"
) -> ProviderSettings:
    return ProviderSettings.model_validate({"kind": "ollama", "model": model, "base_url": url})


# --- the mock -----------------------------------------------------------------------------------


def test_the_mock_is_a_provider_and_an_offline_provider() -> None:
    mock = MockProvider()
    assert isinstance(mock, OfflineProvider)
    provider: LLMProvider = mock
    assert provider.id == "mock"
    assert mock.capabilities.local and mock.capabilities.structured_output


def test_the_mock_request_is_a_real_body_with_the_payload_in_it() -> None:
    request = MockProvider().prepare(TASK, payload())
    body = json.loads(request.body)
    assert "SELECT * FROM tbl_7" in body["messages"][0]["content"]
    assert body["response_format"]["json_schema"] == TASK.output_schema()
    assert (request.method, request.task, request.prompt_version) == ("POST", "triage", "v2")
    assert request.payload_hash == payload().payload_hash
    assert request.prompt_hash == TASK.prompt_hash


def test_the_request_repr_and_str_hold_no_body() -> None:
    request = MockProvider().prepare(TASK, payload())
    assert "SELECT" not in repr(request) and "SELECT" not in str(request)


@pytest.mark.parametrize("first", range(16))
def test_the_documented_mapping_predicts_the_answer(first: int) -> None:
    digest_hex = f"{first:08x}"
    payload_hash = digest_hex + "0" * 56
    digest = int(digest_hex, 16)
    verdict = verdict_for(payload_hash, (89, 79))
    assert verdict.is_vulnerable is (digest % 4 != 0)
    assert verdict.confidence.value == ("low", "medium", "high")[digest % 3]
    assert verdict.cwe == (89, 79)
    assert payload_hash[:12] in verdict.reasoning
    assert verdict.needs_context == ()


def test_the_mock_answers_deterministically_and_the_answer_parses() -> None:
    mock = MockProvider()
    request = mock.prepare(TASK, payload())
    first, second = mock.respond(request), mock.respond(request)
    assert first.body == second.body
    verdict = mock.parse(first)
    assert isinstance(verdict, LLMVerdict)
    assert verdict == verdict_for(payload().payload_hash, (89,))


def test_the_mock_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the mock opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    mock = MockProvider()
    mock.parse(mock.respond(mock.prepare(TASK, payload())))


# --- parsing ------------------------------------------------------------------------------------

VALID = make_verdict().model_dump(mode="json", exclude={"schema_version"})


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"content": VALID}),
        json.dumps({"content": json.dumps(VALID)}),
        json.dumps({"message": {"content": json.dumps(VALID)}}),
        json.dumps({"choices": [{"message": {"content": json.dumps(VALID)}}]}),
    ],
)
def test_every_supported_envelope_yields_the_verdict(body: str) -> None:
    raw = RawResponse(200, body.encode())
    assert MockProvider().parse(raw).is_vulnerable is True


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (RawResponse(500, b"{}"), "http_status_500"),
        (RawResponse(200, b"not json"), "response_not_json"),
        (RawResponse(200, b"[]"), "response_without_content"),
        (RawResponse(200, b'{"content": ""}'), "response_without_content"),
        (RawResponse(200, b'{"content": "not a verdict"}'), "verdict_violates_schema"),
        (RawResponse(200, b'{"content": {"is_vulnerable": "maybe"}}'), "verdict_violates_schema"),
        (RawResponse(200, b"x" * 2_000_000), "response_too_large"),
    ],
)
def test_a_malformed_or_invalid_response_is_a_parse_error_without_the_text(
    raw: RawResponse, reason: str
) -> None:
    with pytest.raises(ProviderParseError) as caught:
        MockProvider().parse(raw)
    assert caught.value.reason == reason


def test_a_verdict_with_an_unknown_key_is_rejected() -> None:
    document = {**VALID, "approved_by": "the model"}
    with pytest.raises(ProviderParseError):
        verdict_from_text(json.dumps(document))


def test_a_null_verdict_without_a_context_request_is_rejected() -> None:
    document = {**VALID, "is_vulnerable": None, "needs_context": []}
    with pytest.raises(ProviderParseError):
        verdict_from_text(json.dumps(document))


def test_extract_content_returns_the_text_of_a_string_envelope() -> None:
    assert extract_content(b'{"content": "abc"}') == "abc"


# --- the replay provider ------------------------------------------------------------------------


def test_a_cassette_miss_raises_naming_the_hash_and_never_falls_back(tmp_path: Path) -> None:
    replay = ReplayProvider(cassette_dir=tmp_path)
    request = replay.prepare(TASK, payload())
    with pytest.raises(CassetteMissingError) as caught:
        replay.respond(request)
    assert payload().payload_hash in str(caught.value)
    assert caught.value.payload_hash == payload().payload_hash


def test_a_recorded_cassette_is_replayed_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("CODEKAVACH_REPLAY_RECORD", "1")
    replay = ReplayProvider(cassette_dir=tmp_path)
    request = replay.prepare(TASK, payload())
    raw = MockProvider().respond(MockProvider().prepare(TASK, payload()))
    path = replay.record(request.payload_hash, raw)
    assert path.name == f"{request.payload_hash}.json"
    again = replay.respond(request)
    assert replay.parse(again) == MockProvider().parse(raw)


def test_recording_needs_the_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("CODEKAVACH_REPLAY_RECORD", raising=False)
    with pytest.raises(RecordRefusedError, match="record_mode_not_enabled"):
        ReplayProvider(cassette_dir=tmp_path).record("0" * 64, RawResponse(200, b"{}"))


@pytest.mark.parametrize("ci", ["1", "true", "yes"])
def test_recording_is_refused_in_continuous_integration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ci: str
) -> None:
    monkeypatch.setenv("CODEKAVACH_REPLAY_RECORD", "1")
    monkeypatch.setenv("CI", ci)
    with pytest.raises(RecordRefusedError, match="record_refused_in_ci"):
        ReplayProvider(cassette_dir=tmp_path).record("0" * 64, RawResponse(200, b"{}"))
    assert list(tmp_path.iterdir()) == []


def test_a_malformed_payload_hash_cannot_name_a_path(tmp_path: Path) -> None:
    replay = ReplayProvider(cassette_dir=tmp_path)
    request = replay.prepare(TASK, payload())
    forged = dataclasses.replace(request, payload_hash="../../outside")
    with pytest.raises(ProviderError, match="payload_hash_malformed"):
        replay.respond(forged)


def test_a_cassette_with_bad_content_is_reported_as_malformed(tmp_path: Path) -> None:
    replay = ReplayProvider(cassette_dir=tmp_path)
    request = replay.prepare(TASK, payload())
    (tmp_path / f"{request.payload_hash}.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(Exception, match="cassette_malformed"):
        replay.respond(request)


# --- the local-model provider -------------------------------------------------------------------


def test_the_local_provider_declares_local_and_builds_a_chat_request() -> None:
    provider = OllamaProvider("ollama", ollama_settings())
    assert provider.capabilities.local is True
    request = provider.prepare(TASK, payload())
    assert request.url == "http://127.0.0.1:11434/api/chat"
    body = json.loads(request.body)
    assert body["stream"] is False and body["model"] == "llama3:8b"
    assert body["format"] == TASK.output_schema()
    assert "SELECT * FROM tbl_7" in body["messages"][0]["content"]


@pytest.mark.parametrize(
    "tag", ["gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "model:cloud", "x-Cloud", "a/b_cloud"]
)
def test_a_model_tag_that_routes_to_a_vendor_cloud_is_refused(tag: str) -> None:
    with pytest.raises(CloudModelRefused):
        OllamaProvider("ollama", ollama_settings(model=tag))


@pytest.mark.parametrize("host", ["ollama.com", "api.ollama.com", "OLLAMA.AI"])
def test_an_endpoint_on_the_vendors_domain_is_refused(host: str) -> None:
    with pytest.raises(CloudModelRefused):
        check_local("llama3:8b", host)


@pytest.mark.parametrize(
    "tag", ["llama3:8b", "cloudy-model:7b", "mistral", "codellama:13b-instruct"]
)
def test_ordinary_local_tags_are_accepted(tag: str) -> None:
    check_local(tag, "127.0.0.1")


# --- the registry and the probe -----------------------------------------------------------------


def test_the_registry_lists_providers_in_id_order() -> None:
    registry = ProviderRegistry()
    registry.register(MockProvider("zeta"))
    registry.register(MockProvider("alpha"))
    assert registry.ids == ("alpha", "zeta") and len(registry) == 2
    assert [provider.id for provider in registry] == ["alpha", "zeta"]
    assert registry.get("alpha").id == "alpha"
    with pytest.raises(ValueError, match="already registered"):
        registry.register(MockProvider("alpha"))
    with pytest.raises(KeyError):
        registry.get("missing")


def test_the_probe_reports_without_opening_a_connection() -> None:
    settings = Settings.model_validate(
        {
            "llm": {
                "providers": {
                    "m": {"kind": "mock"},
                    "off": {"kind": "mock", "enabled": False},
                    "local": {"kind": "ollama", "model": "llama3:8b"},
                    "hosted": {
                        "kind": "openai",
                        "model": "m",
                        "base_url": "https://api.example.test/v1",
                    },
                    "bridge": {"kind": "cli-bridge", "model": "m", "command": ["tool"]},
                }
            }
        }
    )
    assert probe_provider("m", settings).ok and not probe_provider("m", settings).network
    assert probe_provider("off", settings).reason == "provider_disabled"
    assert probe_provider("local", settings).ok and probe_provider("local", settings).network
    assert probe_provider("hosted", settings).reason == "ready"
    assert probe_provider("bridge", settings).reason == "adapter_unavailable"
    assert probe_provider("nope", settings).reason == "provider_not_configured"
