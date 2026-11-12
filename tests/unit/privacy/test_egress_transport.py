"""The egress transport (E12-04): ticket binding, connection policy, headers, proxy, retries.

The HTTP layer is ``httpx.MockTransport``, so no socket is opened (the suite disables them). A
handler that counts its calls is how "nothing was sent" is asserted.
"""

import inspect
import json
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from structlog.testing import capture_logs

import codekavach.privacy.egress.transport as transport_module
from codekavach.config import Settings
from codekavach.config.merge import deep_merge
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.guard import EgressGuard, ScannerRegistry
from codekavach.privacy.egress.models import EgressBlocked, EgressMeta, EgressTicket, LeakHit
from codekavach.privacy.egress.transport import (
    ALLOWED_HEADERS,
    Delivery,
    DryRunTransport,
    OutboundResponse,
    Refusal,
    SimpleRequest,
    Transport,
    TransportError,
    TransportRefused,
    describe,
    path_template,
)

PAYLOAD = 'def fn_1(var_1):\n    return "é" + var_1\n'
PAYLOAD_HASH = sha256_hex(PAYLOAD)
BODY = json.dumps(
    {"system": "Review this.", "payload": PAYLOAD, "payload_hash": PAYLOAD_HASH}
).encode("utf-8")
GRANTED = ConsentDecision(granted=True, source="flag")
AUTH_VALUE = "Bearer " + "sk-test" + "-0123456789"
URL = "https://api.example.test/v1/messages"
BASE: dict[str, Any] = {
    "llm": {
        "allow_remote": True,
        "timeout_seconds": 30,
        "max_retries": 2,
        "providers": {
            "hosted": {"kind": "openai-compatible", "model": "m", "base_url": URL},
            "corp": {
                "kind": "openai-compatible",
                "model": "m",
                "base_url": "https://llm.corp.test/v1",
                "trust_tier": "private",
            },
            "literal": {
                "kind": "openai-compatible",
                "model": "m",
                "base_url": "https://203.0.113.9/v1",
            },
            "ollama": {"kind": "ollama", "model": "m", "base_url": "http://127.0.0.1:11434"},
            "mock": {"kind": "mock"},
        },
    },
    "privacy": {
        "egress": {"provider_host_allowlist": ["api.example.test", "llm.corp.test", "203.0.113.9"]}
    },
}
SETTINGS = Settings.model_validate(BASE)
RESOLUTION = {"api.example.test": ["93.184.216.34"], "llm.corp.test": ["10.1.2.3"]}


def resolver(table: dict[str, list[str]] | None = None) -> Callable[[str], Sequence[str]]:
    names = RESOLUTION if table is None else table

    def resolve(host: str) -> Sequence[str]:
        if host not in names:
            raise OSError("no such host")
        return names[host]

    return resolve


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Clean:
    id = "clean"

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        return ()


class Wire:
    """The fake network: records what reaches it, answers from a script."""

    def __init__(self, *answers: Any) -> None:
        self.requests: list[httpx.Request] = []
        self.answers = list(answers) or [httpx.Response(200, content=b'{"ok": true}')]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer  # type: ignore[no-any-return]


class Rig:
    """A guard, a transport on a fake wire and a way to get tickets."""

    def __init__(
        self,
        wire: Wire | None = None,
        settings_: Settings = SETTINGS,
        table: dict[str, list[str]] | None = None,
    ) -> None:
        self.clock = Clock()
        self.guard = EgressGuard(ScannerRegistry([Clean()]), clock=self.clock)
        self.settings = settings_
        self.wire = wire or Wire()
        self.sleeps: list[float] = []
        self.transport = Transport(
            self.guard,
            settings_,
            http_transport=httpx.MockTransport(self.wire),
            resolver=resolver(table),
            sleep=self.sleeps.append,
        )

    def ticket(self, provider: str = "hosted", body: bytes = BODY) -> EgressTicket:
        meta = EgressMeta(
            provider=provider, model="m", level=PrivacyLevel.L3, payload_hash=PAYLOAD_HASH
        )
        decision = self.guard.evaluate(
            body, meta, settings=self.settings, consent=GRANTED, payload_text=PAYLOAD
        )
        assert decision.ticket is not None, decision.block_code
        return decision.ticket


def request(url: str = URL, **overrides: Any) -> SimpleRequest:
    fields: dict[str, Any] = {
        "method": "POST",
        "url": url,
        "headers": {"content-type": "application/json", "authorization": AUTH_VALUE},
        "body": BODY,
    }
    return SimpleRequest(**(fields | overrides))


# --- the happy path and the ticket ---------------------------------------------------------


def test_a_ticketed_request_is_sent_and_the_response_returned() -> None:
    rig = Rig()
    response = rig.transport.send(request(), rig.ticket())
    assert response.status == 200
    assert response.body == b'{"ok": true}'
    assert len(rig.wire.requests) == 1
    sent = rig.wire.requests[0]
    assert sent.content == BODY
    assert sent.headers["authorization"] == AUTH_VALUE
    assert str(sent.url) == URL


def test_a_ticket_is_single_use() -> None:
    rig = Rig()
    ticket = rig.ticket()
    rig.transport.send(request(), ticket)
    with pytest.raises(EgressBlocked) as caught:
        rig.transport.send(request(), ticket)
    assert caught.value.block_code == "ticket_expired"
    assert len(rig.wire.requests) == 1


def test_an_expired_ticket_sends_nothing() -> None:
    rig = Rig()
    ticket = rig.ticket()
    rig.clock.advance(3600)
    with pytest.raises(EgressBlocked) as caught:
        rig.transport.send(request(), ticket)
    assert caught.value.block_code == "ticket_expired"
    assert rig.wire.requests == []


def test_a_ticket_from_another_guard_is_refused() -> None:
    rig, other = Rig(), Rig()
    foreign = other.ticket()
    with pytest.raises(EgressBlocked) as caught:
        rig.transport.send(request(), foreign)
    assert caught.value.block_code == "ticket_expired"
    assert rig.wire.requests == []


def test_a_forged_ticket_with_a_made_up_tag_is_refused() -> None:
    rig = Rig()
    real = rig.ticket()
    forged = real.model_copy(update={"tag": "0" * 32})
    with pytest.raises(EgressBlocked):
        rig.transport.send(request(), forged)
    assert rig.wire.requests == []


def test_an_altered_ticket_is_refused() -> None:
    rig = Rig()
    real = rig.ticket()
    altered = real.model_copy(update={"level": PrivacyLevel.L1})
    with pytest.raises(EgressBlocked) as caught:
        rig.transport.send(request(), altered)
    assert caught.value.block_code == "hash_mismatch"
    assert rig.wire.requests == []


def test_a_body_that_does_not_hold_the_payload_hash_is_refused_and_keeps_the_ticket() -> None:
    rig = Rig()
    ticket = rig.ticket()
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request(body=b'{"other": 1}'), ticket)
    assert caught.value.reason == Refusal.BODY_HASH
    assert rig.wire.requests == []
    rig.transport.send(request(), ticket)  # the refusal did not burn it
    assert len(rig.wire.requests) == 1


def test_the_payload_text_binds_the_body_when_the_caller_has_it() -> None:
    rig = Rig()
    rig.transport.send(request(), rig.ticket(), payload_text=PAYLOAD)
    swapped = json.dumps({"payload": "something else"}).encode()
    with pytest.raises(TransportRefused):
        rig.transport.send(request(body=swapped), rig.ticket(), payload_text=PAYLOAD)


@settings(max_examples=60, deadline=None)
@given(
    prefix=st.binary(max_size=40),
    suffix=st.binary(max_size=40),
    present=st.booleans(),
)
def test_send_proceeds_only_when_the_body_holds_the_ticket_hash(
    prefix: bytes, suffix: bytes, present: bool
) -> None:
    rig = Rig()
    ticket = rig.ticket()
    middle = PAYLOAD_HASH.encode() if present else b"no digest here"
    body = prefix + middle + suffix
    if present or PAYLOAD_HASH.encode() in body:
        rig.transport.send(request(body=body), ticket)
        assert len(rig.wire.requests) == 1
    else:
        with pytest.raises(TransportRefused):
            rig.transport.send(request(body=body), ticket)
        assert rig.wire.requests == []


# --- the connection policy -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "url", "reason"),
    [
        ("hosted", "http://api.example.test/v1", Refusal.SCHEME),
        ("hosted", "ftp://api.example.test/v1", Refusal.SCHEME),
        ("hosted", "https://other.example.test/v1", Refusal.HOST),
        ("hosted", "https://" + "user" + ":" + "x" + "@api.example.test/v1", Refusal.URL),
        ("hosted", "https://api.example.test/v1#frag", Refusal.URL),
        ("hosted", "https://api.example.test:notaport/v1", Refusal.URL),
        ("hosted", "https:///v1", Refusal.URL),
        ("literal", "https://203.0.113.9/v1", Refusal.IP_LITERAL),
        ("hosted", "http://127.0.0.1:11434/v1", Refusal.IP_LITERAL),
        ("mock", "https://api.example.test/v1", Refusal.PROVIDER),
        ("missing", "https://api.example.test/v1", Refusal.PROVIDER),
    ],
)
def test_the_connection_policy_refuses_and_sends_nothing(
    provider: str, url: str, reason: str
) -> None:
    rig = Rig()
    ticket = _ticket_or_forged(rig, provider)
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request(url), ticket)
    assert caught.value.reason == reason
    assert caught.value.block_code == "provider_not_allowed"
    assert rig.wire.requests == []


def _ticket_or_forged(rig: Rig, provider: str) -> EgressTicket:
    """A ticket for ``provider``; the guard refuses some providers, so build one by hand."""
    try:
        return rig.ticket(provider)
    except AssertionError:
        real = rig.ticket()
        return real.model_copy(update={"provider": provider})


def test_a_public_provider_that_resolves_to_a_private_address_is_refused() -> None:
    rig = Rig(table={"api.example.test": ["10.0.0.5"]})
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request(), rig.ticket())
    assert caught.value.reason == Refusal.PRIVATE_ADDRESS
    assert rig.wire.requests == []


def test_one_private_address_among_public_ones_is_refused_too() -> None:
    rig = Rig(table={"api.example.test": ["93.184.216.34", "169.254.169.254"]})
    with pytest.raises(TransportRefused):
        rig.transport.send(request(), rig.ticket())


def test_a_private_tier_provider_may_resolve_to_a_private_address() -> None:
    rig = Rig()
    response = rig.transport.send(request("https://llm.corp.test/v1"), rig.ticket("corp"))
    assert response.status == 200


def test_a_host_that_does_not_resolve_is_refused() -> None:
    rig = Rig(table={})
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request(), rig.ticket())
    assert caught.value.reason == Refusal.HOST


def test_a_declared_local_provider_may_use_http_on_loopback() -> None:
    rig = Rig()
    response = rig.transport.send(request("http://127.0.0.1:11434/api/chat"), rig.ticket("ollama"))
    assert response.status == 200
    assert str(rig.wire.requests[0].url) == "http://127.0.0.1:11434/api/chat"


def test_a_local_provider_on_a_name_that_is_not_loopback_may_not_use_http() -> None:
    rig = Rig(table={"ollama.internal": ["10.0.0.7"]})
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request("http://ollama.internal:11434/api"), rig.ticket("ollama"))
    assert caught.value.reason == Refusal.SCHEME


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_never_followed(status: int) -> None:
    wire = Wire(httpx.Response(status, headers={"location": "https://evil.example.test/"}))
    rig = Rig(wire)
    with pytest.raises(TransportError) as caught:
        rig.transport.send(request(), rig.ticket())
    assert caught.value.kind == "redirect"
    assert len(wire.requests) == 1  # the body went once, to the allowed host only


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "TRACE"])
def test_only_post_and_get_are_sent(method: str) -> None:
    rig = Rig()
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request(method=method), rig.ticket())
    assert caught.value.reason == Refusal.METHOD


def test_a_response_over_the_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "MAX_RESPONSE_BYTES", 10)
    rig = Rig(Wire(httpx.Response(200, content=b"x" * 100)))
    with pytest.raises(TransportError) as caught:
        rig.transport.send(request(), rig.ticket())
    assert caught.value.kind == "response_too_large"


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (httpx.ConnectError("refused"), "connect"),
        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] bad"), "tls"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.ConnectTimeout("slow"), "timeout"),
        (httpx.RemoteProtocolError("garbled"), "protocol"),
    ],
)
def test_network_failures_have_a_kind_and_no_message(error: Exception, kind: str) -> None:
    rig = Rig(Wire(error))
    with pytest.raises(TransportError) as caught:
        rig.transport.send(request(), rig.ticket())
    assert caught.value.kind == kind
    assert str(caught.value) == kind
    assert caught.value.__cause__ is None


# --- headers -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["X-Repository", "x-forwarded-for", "X-Machine-Id", "cookie", "host", "referer", "origin"],
)
def test_a_header_off_the_allow_list_is_refused(name: str) -> None:
    rig = Rig()
    headers = {"content-type": "application/json", name: "kavachbank/ledger"}
    with pytest.raises(TransportRefused) as caught:
        rig.transport.send(request(headers=headers), rig.ticket())
    assert caught.value.reason == Refusal.HEADER
    assert rig.wire.requests == []


@pytest.mark.parametrize(
    "name", ["Authorization", "X-API-Key", "api-key", "Accept", "User-Agent", "anthropic-version"]
)
def test_the_allow_listed_headers_and_version_headers_pass(name: str) -> None:
    rig = Rig()
    rig.transport.send(request(headers={name: "v"}), rig.ticket())
    assert len(rig.wire.requests) == 1


def test_the_allow_list_is_the_documented_set() -> None:
    assert {
        "authorization",
        "x-api-key",
        "api-key",
        "content-type",
        "accept",
        "user-agent",
        "originator",
        "x-goog-api-key",
        "x-amz-date",
        "x-amz-content-sha256",
        "x-amz-security-token",
    } == ALLOWED_HEADERS


# --- the client: verification, redirects, proxy ---------------------------------------------


class RecordingClient:
    """Stands in for ``httpx.Client`` to see how the transport builds it."""

    instances: ClassVar[list["RecordingClient"]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        RecordingClient.instances.append(self)

    def close(self) -> None:
        return None


def built_clients(settings_: Settings, monkeypatch: pytest.MonkeyPatch, *providers: str) -> list:  # type: ignore[type-arg]
    RecordingClient.instances = []
    monkeypatch.setattr(httpx, "Client", RecordingClient)
    rig = Rig(settings_=settings_)
    for name in providers:
        rig.transport._client(rig.transport._policy.provider_of(rig.ticket(name)))
    return RecordingClient.instances


def test_the_client_verifies_certificates_ignores_the_environment_and_follows_no_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        monkeypatch.setenv(name, "http://ambient.example.test:8080")
    (client,) = built_clients(SETTINGS, monkeypatch, "hosted")
    assert "verify" not in client.kwargs  # httpx verifies by default; nothing turns it off
    assert client.kwargs["trust_env"] is False
    assert client.kwargs["follow_redirects"] is False
    assert client.kwargs["proxy"] is None
    assert client.kwargs["http2"] is False


def test_an_explicit_proxy_is_used_for_remote_providers_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = Settings.model_validate(
        deep_merge(
            BASE,
            {"privacy": {"egress": {"proxy_url": "http://proxy.example.test:3128"}}},
        )
    )
    remote, local = built_clients(configured, monkeypatch, "hosted", "ollama")
    assert remote.kwargs["proxy"] == "http://proxy.example.test:3128"
    assert local.kwargs["proxy"] is None


def test_the_attestation_names_a_proxy_and_its_trust() -> None:
    plain = Transport(EgressGuard(), SETTINGS).attestation()
    assert (plain.proxy_configured, plain.proxy_trust) == (False, "none")
    configured = Settings.model_validate(
        deep_merge(
            BASE,
            {
                "privacy": {
                    "egress": {
                        "proxy_url": "http://proxy.example.test:3128",
                        "proxy_trust": "inspect",
                    }
                }
            },
        )
    )
    attested = Transport(EgressGuard(), configured).attestation()
    assert (attested.proxy_configured, attested.proxy_trust) == (True, "inspect")


def test_no_public_function_can_turn_certificate_verification_off() -> None:
    names = ("verify", "ssl", "cert", "insecure", "context")
    for member in (Transport.__init__, Transport.send, Transport.deliver, Transport.probe):
        for parameter in inspect.signature(member).parameters:
            assert not any(word in parameter.lower() for word in names), (member, parameter)
    source = inspect.getsource(transport_module)
    assert not re.search(r"verify\s*=", source)
    assert "ssl._create_unverified_context" not in source


# --- retries -------------------------------------------------------------------------------


def test_a_retry_takes_a_fresh_ticket_each_time_and_backs_off_with_jitter() -> None:
    wire = Wire(httpx.Response(503), httpx.Response(503), httpx.Response(200, content=b"fine"))
    rig = Rig(wire)
    tickets: list[EgressTicket] = []

    def issue() -> EgressTicket:
        tickets.append(rig.ticket())
        return tickets[-1]

    response = rig.transport.send_with_retries(request(), issue)
    assert response.body == b"fine"
    assert len(tickets) == len({t.tag for t in tickets}) == 3
    assert len(rig.sleeps) == 2
    assert 0.25 <= rig.sleeps[0] <= 0.75
    assert 0.5 <= rig.sleeps[1] <= 1.5


def test_a_connection_error_is_retried_and_the_last_one_is_raised() -> None:
    rig = Rig(Wire(httpx.ConnectError("refused")))
    with pytest.raises(TransportError) as caught:
        rig.transport.send_with_retries(request(), rig.ticket)
    assert caught.value.kind == "connect"
    assert len(rig.wire.requests) == 3  # one try and two retries


def test_a_status_that_is_not_transient_is_not_retried() -> None:
    rig = Rig(Wire(httpx.Response(400, content=b"bad request")))
    response = rig.transport.send_with_retries(request(), rig.ticket)
    assert response.status == 400
    assert len(rig.wire.requests) == 1
    assert rig.sleeps == []


def test_a_content_policy_refusal_is_never_retried() -> None:
    rig = Rig(Wire(httpx.Response(503, content=b"refused by policy")))
    response = rig.transport.send_with_retries(
        request(), rig.ticket, is_refusal=lambda r: b"policy" in r.body
    )
    assert response.status == 503
    assert len(rig.wire.requests) == 1


def test_the_last_transient_response_is_returned_when_retries_run_out() -> None:
    rig = Rig(Wire(httpx.Response(429)))
    response = rig.transport.send_with_retries(request(), rig.ticket, max_retries=1)
    assert response.status == 429
    assert len(rig.wire.requests) == 2


def test_a_retry_whose_body_is_now_blocked_stops() -> None:
    rig = Rig(Wire(httpx.Response(503)))
    calls = 0

    def issue() -> EgressTicket:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise EgressBlocked("residual_secret")
        return rig.ticket()

    with pytest.raises(EgressBlocked):
        rig.transport.send_with_retries(request(), issue)
    assert len(rig.wire.requests) == 1


# --- probe, dry run -------------------------------------------------------------------------


def test_a_probe_is_ticketed_and_reported_for_the_ledger() -> None:
    rig = Rig()
    seen: list[tuple[bytes, str]] = []
    deliveries: list[Delivery] = []

    def issue(body: bytes, digest: str) -> EgressTicket:
        seen.append((body, digest))
        meta = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash=digest)
        decision = rig.guard.evaluate(
            body, meta, settings=rig.settings, consent=GRANTED, payload_text=None
        )
        assert decision.ticket is not None
        return decision.ticket

    response = rig.transport.probe("hosted", issue, record=deliveries.append)
    assert response.status == 200
    assert len(seen) == 1
    assert sha256_hex(transport_module.PROBE_TEXT) == seen[0][1]
    assert [d.provider for d in deliveries] == ["hosted"]
    assert deliveries[0].status == 200 and not deliveries[0].dry_run


def test_a_probe_that_cannot_connect_is_still_reported() -> None:
    rig = Rig(Wire(httpx.ConnectError("refused")))
    deliveries: list[Delivery] = []

    def issue(body: bytes, digest: str) -> EgressTicket:
        meta = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash=digest)
        decision = rig.guard.evaluate(
            body, meta, settings=rig.settings, consent=GRANTED, payload_text=None
        )
        assert decision.ticket is not None
        return decision.ticket

    with pytest.raises(TransportError):
        rig.transport.probe("hosted", issue, record=deliveries.append)
    assert deliveries[0].error_kind == "connect" and deliveries[0].status is None


def test_a_probe_of_a_provider_without_an_endpoint_is_refused() -> None:
    rig = Rig()
    with pytest.raises(TransportRefused):
        rig.transport.probe("mock", lambda body, digest: rig.ticket(), record=lambda _d: None)


def test_the_dry_run_sends_nothing_and_runs_the_same_checks() -> None:
    rig = Rig()
    dry = DryRunTransport(rig.guard, rig.settings, resolver=resolver())
    response = dry.send(request(), rig.ticket())
    assert response.dry_run and response.status == 204
    assert len(dry.deliveries) == 1 and dry.deliveries[0].dry_run
    assert dry.deliveries[0].bytes_out == len(BODY)
    assert rig.wire.requests == []


@pytest.mark.parametrize(
    "case",
    [
        {"url": "http://api.example.test/v1"},
        {"url": "https://other.example.test/v1"},
        {"headers": {"x-repository": "kavachbank"}},
        {"body": b"no digest"},
        {"method": "DELETE"},
    ],
)
def test_the_dry_run_refuses_what_the_real_transport_refuses(case: dict[str, Any]) -> None:
    rig = Rig()
    dry = DryRunTransport(rig.guard, rig.settings, resolver=resolver())
    with pytest.raises(TransportRefused):
        dry.send(request(**case), rig.ticket())
    with pytest.raises(TransportRefused):
        rig.transport.send(request(**case), rig.ticket())


def test_the_dry_run_consumes_the_ticket_like_a_real_send() -> None:
    rig = Rig()
    dry = DryRunTransport(rig.guard, rig.settings, resolver=resolver())
    ticket = rig.ticket()
    dry.send(request(), ticket)
    with pytest.raises(EgressBlocked):
        dry.send(request(), ticket)


# --- nothing sensitive in logs, errors or reprs --------------------------------------------


def test_no_header_value_and_no_body_byte_reaches_a_log_line_an_error_or_a_repr() -> None:
    rig = Rig()
    outputs: list[str] = []
    with capture_logs() as logs:
        response = rig.transport.send(request(), rig.ticket())
        outputs.append(repr(response))
        outputs.append(repr(request()))
        outputs.append(describe(request()))
        for bad in (request("http://api.example.test/v1"), request(headers={"cookie": "c"})):
            try:
                rig.transport.send(bad, rig.ticket())
            except TransportRefused as refused:
                outputs.extend([str(refused), repr(refused)])
        failing = Rig(Wire(httpx.ConnectError(f"refused {AUTH_VALUE}")))
        try:
            failing.transport.send(request(), failing.ticket())
        except TransportError as error:
            outputs.extend([str(error), repr(error)])
    outputs.append(json.dumps(logs, default=str))
    joined = "\n".join(outputs)
    assert AUTH_VALUE not in joined
    assert "sk-test" not in joined
    assert "Review this" not in joined
    assert "fn_1" not in joined
    sent = [entry for entry in logs if entry["event"] == "egress_send"]
    assert sent and sent[0]["status"] == 200 and sent[0]["host"] == "api.example.test"
    assert sent[0]["payload_hash_prefix"] == PAYLOAD_HASH[:12]
    assert sent[0]["path"] == "/v1/messages"


@pytest.mark.parametrize(
    ("path", "template"),
    [
        ("/v1/messages", "/v1/messages"),
        ("/v1/accounts/42/items", "/v1/accounts/{}/items"),
        ("/deployments/gpt4o/chat", "/deployments/{}/chat"),
        ("", "/"),
    ],
)
def test_path_values_are_templated(path: str, template: str) -> None:
    assert path_template(path) == template


def test_the_response_repr_shows_sizes_not_content() -> None:
    response = OutboundResponse(200, {"x-secret": "v"}, b"sensitive body", 12.0)
    assert "sensitive" not in repr(response)
    assert "x-secret" not in repr(response)
