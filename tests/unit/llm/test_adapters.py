"""The hosted adapters, the registry, selection and the request lifecycle (E22-01 to E22-03).

Offline: every test here builds requests and parses canned vendor envelopes; nothing is sent.
"""

import datetime
import json
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr

from codekavach.config import Settings
from codekavach.config.models.llm import (
    PRESETS,
    LLMSettings,
    ProviderKind,
    ProviderSettings,
    key_available,
    preset_hosts,
)
from codekavach.core.models.payload import PayloadFacts, SanitisedPayload
from codekavach.llm.budget import ScanBudget, estimate_scan, prices_for
from codekavach.llm.cache import CacheKey, ResponseCache
from codekavach.llm.lifecycle import BUDGET_EXHAUSTED, ManagedSession, retry_after
from codekavach.llm.providers.anthropic_api import AnthropicProvider
from codekavach.llm.providers.base import (
    ProviderError,
    ProviderParseError,
    ProviderRefused,
    ProviderUnavailable,
    RawResponse,
    StructuredMode,
    extract_content,
    parse_response,
    usage_of,
    verdict_from_text,
)
from codekavach.llm.providers.bedrock import BedrockProvider, sign_v4
from codekavach.llm.providers.gemini_api import GeminiProvider, VertexProvider
from codekavach.llm.providers.http import HttpProvider
from codekavach.llm.providers.openai_api import (
    AzureOpenAIProvider,
    OpenAIChatProvider,
    OpenAIResponsesProvider,
    XaiProvider,
)
from codekavach.llm.providers.registry import (
    AdapterSpec,
    DuplicateAdapterError,
    build_adapter,
    build_registry,
    choose_strategy,
    load_provider_metadata,
    mock_spec,
)
from codekavach.llm.selection import (
    ProviderNotConfigured,
    provider_catalogue,
    select_provider,
    settings_for_provider,
)
from codekavach.llm.stages import concurrency
from codekavach.llm.tasks.triage import TriageTask
from codekavach.privacy.egress.session import Dispatch
from tests.support.factories import make_payload, make_verdict

KEY = SecretStr("sk-test-SYNTHETICKEY0000")  # pragma: allowlist secret
TASK = TriageTask()
FACTS = PayloadFacts(rule="KB-VULN-001", cwe=(89,), strategy="enclosing_function")
VERDICT = make_verdict()
VERDICT_JSON = json.dumps(VERDICT.model_dump(mode="json", exclude={"schema_version"}))


def payload() -> SanitisedPayload:
    return make_payload(facts=FACTS)


def settings(kind: str, **fields: Any) -> ProviderSettings:
    return ProviderSettings.model_validate({"kind": kind, "model": "m-1", **fields})


ADAPTERS: dict[str, Callable[[], HttpProvider]] = {
    "responses": lambda: OpenAIResponsesProvider("p", settings("openai"), api_key=KEY),
    "chat": lambda: OpenAIChatProvider(
        "p", settings("openai-compatible", base_url="https://llm.example.org/v1"), api_key=KEY
    ),
    "xai": lambda: XaiProvider("p", settings("xai"), api_key=KEY),
    "azure": lambda: AzureOpenAIProvider(
        "p", settings("azure-openai", base_url="https://x.openai.azure.com"), api_key=KEY
    ),
    "anthropic": lambda: AnthropicProvider("p", settings("anthropic"), api_key=KEY),
    "gemini": lambda: GeminiProvider("p", settings("gemini"), api_key=KEY),
    "vertex": lambda: VertexProvider(
        "p",
        settings("vertex", options={"project": "proj", "location": "europe-west4"}),
        api_key=KEY,
    ),
    "bedrock": lambda: BedrockProvider(
        "p",
        settings("bedrock", region="eu-west-1"),
        env={
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
            # pragma: allowlist nextline secret
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        clock=lambda: datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC),
    ),
}


# --- request building ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_every_adapter_builds_a_non_streaming_request_with_the_payload(name: str) -> None:
    request = ADAPTERS[name]().prepare(TASK, payload())
    body = json.loads(request.body)
    assert request.method == "POST" and request.url.startswith("https://")
    assert body.get("stream", False) is False
    assert "streamGenerateContent" not in request.url
    assert "SELECT * FROM tbl_7" in request.body.decode("utf-8")
    assert request.payload_hash == payload().payload_hash
    # the key is in a header, never in the body or the URL, and never in the repr
    secret = KEY.get_secret_value()
    assert secret not in request.body.decode() and secret not in request.url
    assert secret not in repr(request)


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_the_same_payload_gives_the_same_body_apart_from_the_delimiter(name: str) -> None:
    adapter = ADAPTERS[name]()
    first = adapter.prepare(TASK, payload())
    second = adapter.prepare(TASK, payload())
    assert len(first.body) == len(second.body)
    assert first.url == second.url


def test_wire_specifics() -> None:
    responses = json.loads(ADAPTERS["responses"]().prepare(TASK, payload()).body)
    assert responses["text"]["format"]["type"] == "json_schema"
    assert responses["text"]["format"]["strict"] is True and responses["store"] is False
    assert responses["input"][0]["role"] == "user" and responses["instructions"]
    chat = json.loads(ADAPTERS["chat"]().prepare(TASK, payload()).body)
    assert chat["response_format"]["json_schema"]["strict"] is True
    anthropic = ADAPTERS["anthropic"]().prepare(TASK, payload())
    assert anthropic.url == "https://api.anthropic.com/v1/messages"
    assert anthropic.headers["anthropic-version"] and "x-api-key" in anthropic.headers
    assert json.loads(anthropic.body)["tool_choice"]["type"] == "tool"
    gemini = ADAPTERS["gemini"]().prepare(TASK, payload())
    assert gemini.url.endswith("/models/m-1:generateContent") and "x-goog-api-key" in gemini.headers
    vertex = ADAPTERS["vertex"]().prepare(TASK, payload())
    assert vertex.url.startswith("https://europe-west4-aiplatform.googleapis.com/v1/projects/proj")
    azure = ADAPTERS["azure"]().prepare(TASK, payload())
    assert "/openai/deployments/m-1/chat/completions?api-version=" in azure.url
    assert "api-key" in azure.headers
    bedrock = ADAPTERS["bedrock"]().prepare(TASK, payload())
    assert bedrock.url == "https://bedrock-runtime.eu-west-1.amazonaws.com/model/m-1/converse"
    assert bedrock.headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA")
    assert bedrock.headers["x-amz-date"] == "20260102T030405Z"


def test_preset_headers_and_options_reach_the_request() -> None:
    llm = LLMSettings.model_validate({"default_provider": "agentrouter"})
    agentrouter = llm.providers["agentrouter"]
    adapter = OpenAIResponsesProvider("agentrouter", agentrouter, api_key=KEY)
    request = adapter.prepare(TASK, payload())
    assert request.url == "https://agentrouter.org/v1/responses"
    assert request.headers["user-agent"].startswith("codex_cli_rs/")
    assert request.headers["originator"] == "codex_cli_rs"
    assert json.loads(request.body)["reasoning"] == {"effort": "low"}
    assert request.headers["authorization"] == f"Bearer {KEY.get_secret_value()}"


def test_sigv4_matches_the_published_aws_example() -> None:
    # The IAM ListUsers example of the AWS Signature Version 4 documentation.
    headers = sign_v4(
        method="GET",
        url="https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
        headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
        body=b"",
        region="us-east-1",
        service="iam",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",  # pragma: allowlist secret
        now=datetime.datetime(2015, 8, 30, 12, 36, 0, tzinfo=datetime.UTC),
    )
    assert headers["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date, "
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    )


def test_a_missing_key_or_model_is_a_reason_code() -> None:
    with pytest.raises(ProviderError, match="api_key_not_available"):
        OpenAIResponsesProvider("p", settings("openai"))
    with pytest.raises(ProviderError, match="aws_credentials_not_available"):
        BedrockProvider("p", settings("bedrock", region="eu-west-1"), env={})
    with pytest.raises(ProviderError, match="api_key_not_available"):
        build_adapter("p", settings("anthropic", api_key="env:CK_TEST_UNSET_VARIABLE_0"))


# --- response parsing ---------------------------------------------------------------------------

ENVELOPES = {
    "responses": {"output": [{"type": "reasoning"}, {"type": "message", "content": [
        {"type": "output_text", "text": VERDICT_JSON}]}]},
    "chat": {"choices": [{"message": {"content": VERDICT_JSON}}]},
    "chat_tool": {"choices": [{"message": {"tool_calls": [
        {"function": {"arguments": VERDICT_JSON}}]}}]},
    "anthropic_tool": {"content": [{"type": "tool_use", "input": json.loads(VERDICT_JSON)}]},
    "gemini": {"candidates": [{"content": {"parts": [{"text": VERDICT_JSON}]}}]},
    "bedrock": {"output": {"message": {"content": [{"toolUse": {
        "input": json.loads(VERDICT_JSON)}}]}}},
    "ollama": {"message": {"content": VERDICT_JSON}},
    "fenced": {"choices": [{"message": {"content": f"```json\n{VERDICT_JSON}\n```"}}]},
}  # fmt: skip
REFUSALS = {
    "responses": {"output": [
        {"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]},
    "chat": {"choices": [{"message": {"refusal": "I can't help with that."}}]},
    "anthropic": {"stop_reason": "refusal", "content": []},
    "gemini": {"promptFeedback": {"blockReason": "SAFETY"}},
    "bedrock": {"stopReason": "content_filtered", "output": {"message": {"content": []}}},
}  # fmt: skip


@pytest.mark.parametrize("name", sorted(ENVELOPES))
def test_every_envelope_parses_into_the_same_verdict(name: str) -> None:
    raw = RawResponse(200, json.dumps(ENVELOPES[name]).encode())
    assert parse_response(raw) == VERDICT


@pytest.mark.parametrize("name", sorted(REFUSALS))
def test_a_refusal_raises_provider_refused(name: str) -> None:
    with pytest.raises(ProviderRefused):
        extract_content(json.dumps(REFUSALS[name]).encode())


def test_status_errors_and_trailing_prose() -> None:
    with pytest.raises(ProviderUnavailable) as caught:
        parse_response(RawResponse(429, b"{}"))
    assert caught.value.status == 429 and not isinstance(caught.value, ProviderRefused)
    with pytest.raises(ProviderParseError):
        verdict_from_text(VERDICT_JSON + "\nHope this helps!")


def test_usage_is_read_from_every_vendor_shape() -> None:
    assert usage_of(b'{"usage": {"input_tokens": 3, "output_tokens": 4}}').output_tokens == 4
    assert usage_of(b'{"usage": {"prompt_tokens": 5, "completion_tokens": 6}}').input_tokens == 5
    assert usage_of(b'{"usageMetadata": {"promptTokenCount": 7}}').input_tokens == 7
    assert usage_of(b"not json").input_tokens == 0


# --- registry, metadata, selection -------------------------------------------------------------


def test_metadata_covers_every_kind() -> None:
    assert set(load_provider_metadata()) == {kind.value for kind in ProviderKind}


def test_two_adapters_for_one_kind_name_both_entry_points() -> None:
    other = AdapterSpec(ProviderKind.MOCK, mock_spec.capabilities, mock_spec.builder, "x:other")
    with pytest.raises(DuplicateAdapterError, match=r"codekavach.providers:mock and x:other"):
        build_registry([mock_spec, other])


def test_choose_strategy() -> None:
    assert choose_strategy(OpenAIResponsesProvider.capabilities) == StructuredMode.JSON_SCHEMA
    assert choose_strategy(AnthropicProvider.capabilities) == StructuredMode.TOOL
    with pytest.raises(ProviderError, match="json_schema"):
        choose_strategy(AnthropicProvider.capabilities, StructuredMode.JSON_SCHEMA)


def test_selection_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEKAVACH_AGENTROUTER_API_KEY", raising=False)
    empty = select_provider(Settings())
    assert (empty.provider_id, empty.fallback_reason) == ("mock", "no_provider_configured")
    remote = Settings.model_validate(
        {
            "llm": {
                "allow_remote": False,
                "providers": {"hosted": {"kind": "openai", "model": "m"}},
            }
        }
    )
    assert select_provider(remote).fallback_reason == "remote_not_allowed"
    with pytest.raises(ProviderNotConfigured, match=r"'nope'.*mock"):
        select_provider(Settings(), requested="nope")


def test_agentrouter_is_added_when_named_and_never_chosen_by_auto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CODEKAVACH_AGENTROUTER_API_KEY", raising=False)
    assert "agentrouter" not in LLMSettings().providers
    named = LLMSettings.model_validate({"default_provider": "agentrouter"})
    assert named.selected_provider()[0] == "agentrouter"
    assert preset_hosts(named) == ("agentrouter.org",)
    monkeypatch.setenv("CODEKAVACH_AGENTROUTER_API_KEY", "synthetic")
    listed = LLMSettings()
    assert "agentrouter" in listed.providers and listed.selected_provider()[0] == "mock"
    assert key_available(listed.providers["agentrouter"])


def test_an_overridden_preset_url_is_not_implicitly_allowed() -> None:
    moved = ProviderSettings.model_validate(
        {"preset": "agentrouter", "base_url": "https://elsewhere.example/v1"}
    )
    assert moved.preset_host is None
    assert PRESETS["agentrouter"].kind is ProviderKind.OPENAI


def test_vertex_needs_project_and_location() -> None:
    with pytest.raises(ValueError, match=r"CK-CFG-033.*options.project"):
        LLMSettings.model_validate({"providers": {"v": {"kind": "vertex", "model": "m"}}})


def test_concurrency_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEKAVACH_LLM_CONCURRENCY", raising=False)
    preset = ProviderSettings.model_validate({"preset": "agentrouter"})
    assert concurrency(preset, offline=False) == 1  # the gateway serves one request at a time
    assert concurrency(preset, offline=True) == 1
    monkeypatch.setenv("CODEKAVACH_LLM_CONCURRENCY", "3")
    assert concurrency(preset, offline=False) == 3
    monkeypatch.setenv("CODEKAVACH_LLM_CONCURRENCY", "99")
    assert concurrency(preset, offline=False) == 16


# --- the lifecycle --------------------------------------------------------------------------------


class FakeSession:
    """Answers dispatches from a script and records them."""

    def __init__(self, *answers: Dispatch) -> None:
        self.answers = list(answers)
        self.calls = 0

    def dispatch(self, request: Any, **_: Any) -> Dispatch:
        self.calls += 1
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


OK_BODY = json.dumps(ENVELOPES["chat"]).encode()


def managed(
    session: FakeSession, sleeps: list[float], *, cache: ResponseCache | None = None, **limits: Any
) -> ManagedSession:
    from codekavach.config.models.llm import BudgetSettings  # noqa: PLC0415

    return ManagedSession(
        session,  # type: ignore[arg-type]
        provider_settings=settings("openai-compatible", base_url="https://llm.example.org/v1"),
        budget=ScanBudget(BudgetSettings(**limits), prices_for(settings("openai"))),
        cache=cache,
        max_retries=2,
        sleep=sleeps.append,
    )


def send(session: ManagedSession) -> Dispatch:
    adapter = ADAPTERS["chat"]()
    request = adapter.prepare(TASK, payload())
    return session.dispatch(request, provider="p", model="m-1", task="triage", payload=payload())


def test_a_429_with_retry_after_is_retried_after_that_delay() -> None:
    fake = FakeSession(
        Dispatch("answered", status=429, headers={"retry-after": "2"}),
        Dispatch("answered", status=200, body=OK_BODY),
    )
    sleeps: list[float] = []
    result = send(managed(fake, sleeps))
    assert (result.status, fake.calls, sleeps) == (200, 2, [2.0])


def test_a_400_is_not_retried() -> None:
    fake = FakeSession(Dispatch("answered", status=400))
    sleeps: list[float] = []
    assert send(managed(fake, sleeps)).status == 400
    assert (fake.calls, sleeps) == (1, [])


def test_a_timeout_is_retried_and_gives_up_after_max_retries() -> None:
    fake = FakeSession(Dispatch("failed", error_kind="timeout"))
    sleeps: list[float] = []
    assert send(managed(fake, sleeps)).error_kind == "timeout"
    assert fake.calls == 3 and len(sleeps) == 2


def test_the_cache_answers_a_repeated_request_without_egress(tmp_path: Any) -> None:
    cache = ResponseCache(tmp_path / "cache")
    fake = FakeSession(Dispatch("answered", status=200, body=OK_BODY))
    first = managed(fake, [], cache=cache)
    send(first)
    second = managed(fake, [], cache=cache)
    hit = send(second)
    assert (fake.calls, hit.body, second.budget.cache_hits) == (1, OK_BODY, 1)


def test_a_refusal_or_an_error_is_never_cached(tmp_path: Any) -> None:
    cache = ResponseCache(tmp_path / "cache")
    refusal = json.dumps(REFUSALS["chat"]).encode()
    fake = FakeSession(Dispatch("answered", status=200, body=refusal))
    send(managed(fake, [], cache=cache))
    send(managed(fake, [], cache=cache))
    assert fake.calls == 2


def test_the_cache_key_changes_with_model_prompt_and_sample() -> None:
    base = CacheKey("openai", "h", "m", "triage", "v1", "abc", "f" * 64)
    assert base.digest == CacheKey("openai", "h", "m", "triage", "v1", "abc", "f" * 64).digest
    for changed in (
        CacheKey("openai", "h", "m2", "triage", "v1", "abc", "f" * 64),
        CacheKey("openai", "h", "m", "triage", "v2", "abc", "f" * 64),
        CacheKey("openai", "h", "m", "triage", "v1", "abc", "f" * 64, sample=1),
    ):
        assert changed.digest != base.digest


def test_an_exhausted_budget_sends_nothing() -> None:
    fake = FakeSession(Dispatch("answered", status=200, body=OK_BODY))
    session = managed(fake, [], max_requests=1)
    assert send(session).status == 200
    assert send(session).error_kind == BUDGET_EXHAUSTED
    assert fake.calls == 1


def test_retry_after_parsing() -> None:
    assert retry_after({"Retry-After": "3"}) == 3.0
    assert retry_after({"retry-after": "9999"}) == 60.0
    assert retry_after({"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}) is None


def test_estimate_says_cost_unknown_without_prices() -> None:
    unknown = estimate_scan([1000, 2000], settings("openai"))
    assert unknown.cost_usd is None and "cost unknown" in unknown.describe()
    priced = settings("openai", options={"price_input_per_mtok": 1.0, "price_output_per_mtok": 2.0})
    assert estimate_scan([1000], priced).cost_usd is not None


def test_settings_for_provider_adds_the_builtin_and_rejects_an_unknown_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CODEKAVACH_AGENTROUTER_API_KEY", raising=False)
    chosen = settings_for_provider(Settings(), "agentrouter", model="gpt-test")
    assert chosen.llm.selected_provider()[0] == "agentrouter"
    assert chosen.llm.model == "gpt-test"
    with pytest.raises(ProviderNotConfigured):
        settings_for_provider(Settings(), "nope")


def test_the_catalogue_lists_builtins_without_key_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CODEKAVACH_AGENTROUTER_API_KEY", "sk-test-PLANTED0000")
    rows = {row["id"]: row for row in provider_catalogue(Settings())}
    assert rows["agentrouter"]["configured"] is True
    assert rows["agentrouter"]["min_privacy_level"] == "L3"
    assert rows["mock"]["default"] is True
    assert "PLANTED" not in json.dumps(rows)


def test_concurrent_candidates_never_overshoot_max_requests() -> None:
    import threading  # noqa: PLC0415

    gate = threading.Barrier(6, timeout=1)
    sent: list[int] = []

    class SlowSession(FakeSession):
        def dispatch(self, request: Any, **_: Any) -> Dispatch:
            sent.append(1)
            return Dispatch("answered", status=200, body=OK_BODY)

    session = managed(SlowSession(), [], max_requests=2)
    results: list[Dispatch] = []

    def worker() -> None:
        gate.wait()
        results.append(send(session))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(sent) == 2
    assert sum(result.error_kind == BUDGET_EXHAUSTED for result in results) == 4


def test_the_agentrouter_key_may_come_from_a_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    key_file = tmp_path / "agentrouter.key"
    key_file.write_text("sk-test-FILEKEY0000\n", encoding="utf-8")  # pragma: allowlist secret
    monkeypatch.delenv("CODEKAVACH_AGENTROUTER_API_KEY", raising=False)
    monkeypatch.setenv("CODEKAVACH_AGENTROUTER_API_KEY_FILE", str(key_file))
    llm = LLMSettings()
    assert llm.providers["agentrouter"].api_key == f"file:{key_file}"
    assert key_available(llm.providers["agentrouter"])
    assert llm.selected_provider()[0] == "mock"  # a key on disk is not a decision to send code


def test_an_explicit_preset_entry_also_takes_the_key_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    key_file = tmp_path / "agentrouter.key"
    key_file.write_text("sk-test-FILEKEY0000\n", encoding="utf-8")  # pragma: allowlist secret
    monkeypatch.delenv("CODEKAVACH_AGENTROUTER_API_KEY", raising=False)
    monkeypatch.setenv("CODEKAVACH_AGENTROUTER_API_KEY_FILE", str(key_file))
    entry = ProviderSettings.model_validate({"preset": "agentrouter"})
    assert entry.api_key == f"file:{key_file}"
    monkeypatch.setenv("CODEKAVACH_AGENTROUTER_API_KEY", "sk-test-ENVKEY0000")
    explicit = ProviderSettings.model_validate({"preset": "agentrouter"})
    assert explicit.api_key == "env:CODEKAVACH_AGENTROUTER_API_KEY"


def test_the_combined_review_is_cached_and_keyed_apart_from_triage(tmp_path: Any) -> None:
    from codekavach.llm.tasks import build_task  # noqa: PLC0415

    cache = ResponseCache(tmp_path / "cache")
    fake = FakeSession(Dispatch("answered", status=200, body=OK_BODY))
    review = build_task("review")
    adapter = ADAPTERS["chat"]()

    def ask(session: ManagedSession, task: str) -> Dispatch:
        request = adapter.prepare(review if task == "review" else TASK, payload())
        return session.dispatch(request, provider="p", model="m-1", task=task, payload=payload())

    ask(managed(fake, [], cache=cache), "review")
    second = managed(fake, [], cache=cache)
    hit = ask(second, "review")
    assert (fake.calls, hit.body, second.budget.cache_hits) == (1, OK_BODY, 1)
    ask(managed(fake, [], cache=cache), "triage")  # another task is another question
    assert fake.calls == 2
