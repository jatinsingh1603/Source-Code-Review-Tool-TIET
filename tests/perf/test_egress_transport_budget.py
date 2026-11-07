"""Performance budgets of the egress transport (E12-04).

Overhead outside the network call stays under 2 ms (policy checks, ticket redemption and the
request log line, with an HTTP layer that answers at once), and a dry-run evaluation stays under
5 ms. Both are scaled by the performance factor.
"""

from collections.abc import Sequence

import httpx
import pytest

from codekavach.config import Settings
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.guard import EgressGuard, LeakHit, ScannerRegistry
from codekavach.privacy.egress.models import EgressMeta, EgressTicket
from codekavach.privacy.egress.transport import DryRunTransport, SimpleRequest, Transport
from tests.support.perf import assert_within_budget, measure

PAYLOAD = "x = 1\n" * 2000
DIGEST = sha256_hex(PAYLOAD)
BODY = (PAYLOAD + DIGEST).encode("utf-8")
URL = "https://api.example.test/v1/messages"
SETTINGS = Settings.model_validate(
    {
        "llm": {
            "allow_remote": True,
            "providers": {"hosted": {"kind": "openai-compatible", "model": "m", "base_url": URL}},
        },
        "privacy": {"egress": {"provider_host_allowlist": ["api.example.test"]}},
    }
)
META = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash=DIGEST)
REQUEST = SimpleRequest("POST", URL, {"content-type": "text/plain"}, BODY)
SEND_BUDGET_SECONDS = 0.002
DRY_BUDGET_SECONDS = 0.005


class Instant:
    id = "instant"

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        return ()


def _ticket(guard: EgressGuard) -> EgressTicket:
    decision = guard.evaluate(
        BODY,
        META,
        settings=SETTINGS,
        consent=ConsentDecision(granted=True, source="flag"),
        payload_text=None,
    )
    assert decision.ticket is not None
    return decision.ticket


def _resolve(_host: str) -> Sequence[str]:
    return ["93.184.216.34"]


@pytest.mark.perf
def test_transport_overhead_outside_the_network_call_is_under_two_milliseconds() -> None:
    guard = EgressGuard(ScannerRegistry([Instant()]))
    transport = Transport(
        guard,
        SETTINGS,
        http_transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=b"ok")),
        resolver=_resolve,
    )
    tickets = [_ticket(guard) for _ in range(60)]
    iterator = iter(tickets)
    transport.send(REQUEST, next(iterator))  # warm the connection pool and the address cache

    def one() -> None:
        transport.send(REQUEST, next(iterator))

    assert_within_budget(measure(one, repeat=50), SEND_BUDGET_SECONDS)


@pytest.mark.perf
def test_a_dry_run_send_is_under_five_milliseconds() -> None:
    guard = EgressGuard(ScannerRegistry([Instant()]))
    dry = DryRunTransport(guard, SETTINGS, resolver=_resolve)
    tickets = iter([_ticket(guard) for _ in range(60)])
    dry.send(REQUEST, next(tickets))

    def one() -> None:
        dry.send(REQUEST, next(tickets))

    assert_within_budget(measure(one, repeat=50), DRY_BUDGET_SECONDS)
