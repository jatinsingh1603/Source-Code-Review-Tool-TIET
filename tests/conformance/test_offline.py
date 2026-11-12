"""Offline conformance: every registered adapter kind against the same contract (E22-04).

No key, no network: requests are built for the bundled synthetic probe payload and canned
envelopes of each wire format are parsed. Runs in CI as ``pytest tests/conformance -m conformance``.
"""

import json

import pytest

from codekavach.config.models.llm import ProviderKind
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.providers.base import (
    LLMProvider,
    OfflineProvider,
    ProviderRefused,
    RawResponse,
)
from codekavach.llm.providers.registry import REGISTRY, choose_strategy, load_provider_metadata
from codekavach.llm.tasks.triage import TriageTask
from codekavach.privacy.egress.probe import PROBE_SNIPPET, probe_payload
from tests.conformance.support import (
    AWS_ENV,
    REFUSALS,
    SYNTHETIC_KEY,
    envelope,
    offline_kinds,
    provider_settings,
    registered_kinds,
    verdict_json,
    wire_format,
)
from tests.support.factories import make_verdict

pytestmark = pytest.mark.conformance

TASK = TriageTask()
KINDS = registered_kinds()
NETWORK_KINDS = [kind for kind in KINDS if kind not in offline_kinds()]


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in AWS_ENV.items():
        monkeypatch.setenv(name, value)


def adapter(kind: str) -> LLMProvider:
    return REGISTRY[kind].build("conformance", provider_settings(kind), SYNTHETIC_KEY)


def test_every_kind_has_an_adapter_or_is_documented_unavailable() -> None:
    metadata = load_provider_metadata()
    for kind in ProviderKind:
        if kind.value not in REGISTRY:
            assert metadata[kind.value].verification == "unavailable", kind


@pytest.mark.parametrize("kind", KINDS)
def test_the_request_is_non_streaming_and_carries_the_payload(kind: str) -> None:
    payload = probe_payload()
    request = adapter(kind).prepare(TASK, payload)
    assert request.method == "POST"
    assert request.payload_hash == payload.payload_hash
    body = json.loads(request.body)
    assert body.get("stream", False) is False
    assert "streamGenerateContent" not in request.url
    text = request.body.decode("utf-8")
    assert "request.args.get" in text  # the payload is in the body (JSON-escaped as needed)
    assert PROBE_SNIPPET.splitlines()[0] in text


@pytest.mark.parametrize("kind", NETWORK_KINDS)
def test_the_key_is_only_in_a_header(kind: str) -> None:
    request = adapter(kind).prepare(TASK, probe_payload())
    secret = SYNTHETIC_KEY.get_secret_value()
    assert secret not in request.body.decode("utf-8")
    assert secret not in request.url
    assert secret not in repr(request)
    local = load_provider_metadata()[kind].local
    assert request.url.startswith("http://127.0.0.1" if local else "https://")


@pytest.mark.parametrize("kind", NETWORK_KINDS)
def test_the_envelope_of_the_wire_format_parses_into_the_same_verdict(kind: str) -> None:
    verdict = make_verdict()
    body = json.dumps(envelope(wire_format(kind), verdict_json(verdict))).encode()
    assert adapter(kind).parse(RawResponse(200, body)) == verdict


@pytest.mark.parametrize("kind", [k for k in NETWORK_KINDS if wire_format(k) in REFUSALS])
def test_a_vendor_refusal_is_provider_refused(kind: str) -> None:
    body = json.dumps(REFUSALS[wire_format(kind)]).encode()
    with pytest.raises(ProviderRefused):
        adapter(kind).parse(RawResponse(200, body))


@pytest.mark.parametrize("kind", KINDS)
def test_the_strongest_structured_mode_is_supported(kind: str) -> None:
    capabilities = REGISTRY[kind].capabilities
    assert choose_strategy(capabilities) in capabilities.structured_modes or (
        choose_strategy(capabilities) == "prompt"
    )


def test_the_mock_answers_in_process_with_a_valid_verdict() -> None:
    mock = adapter(ProviderKind.MOCK.value)
    assert isinstance(mock, OfflineProvider)
    request = mock.prepare(TASK, probe_payload())
    assert isinstance(mock.parse(mock.respond(request)), LLMVerdict)


def test_the_replay_adapter_serves_the_recorded_probe_cassette() -> None:
    replay = adapter(ProviderKind.REPLAY.value)
    assert isinstance(replay, OfflineProvider)
    request = replay.prepare(TASK, probe_payload())
    assert isinstance(replay.parse(replay.respond(request)), LLMVerdict)
