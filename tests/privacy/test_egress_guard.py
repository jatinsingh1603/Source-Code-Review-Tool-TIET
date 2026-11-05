"""The egress guard fails closed (I4) and a ticket stands for exactly what was checked (E12-01).

Each test fails if the guarantee is weakened: a scanner failure that passes, a request with no
scanner behind it that passes, a setting that grants consent, a ticket that survives a second use,
or a body byte that reaches a message, a log line or a JSON rendering (I6).
"""

import ast
import json
import threading
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError
from structlog.testing import capture_logs

from codekavach.config import Settings
from codekavach.config.merge import deep_merge
from codekavach.config.models.privacy import PrivacySettings
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress import guard as guard_module
from codekavach.privacy.egress.guard import EgressGuard, LeakScanner, ScannerRegistry
from codekavach.privacy.egress.models import (
    BLOCK_CODE_ORDER,
    BLOCK_CODES,
    EgressBlocked,
    EgressDecision,
    EgressMeta,
    EgressTicket,
    LeakHit,
)

SRC = Path(guard_module.__file__).resolve().parents[3]
EGRESS = SRC / "codekavach" / "privacy" / "egress"

PAYLOAD = 'def fn_1(var_1):\n    return "é" + var_1\n'
PAYLOAD_HASH = sha256_hex(PAYLOAD)
BODY = json.dumps({"system": "Review this.", "payload": PAYLOAD}).encode("utf-8")
GRANTED = ConsentDecision(granted=True, source="flag")
REFUSED = ConsentDecision(granted=False, source="none")
HOSTED_URL = "https://api.example.test/v1"
BASE: dict[str, Any] = {
    "llm": {
        "providers": {
            "hosted": {"kind": "openai-compatible", "model": "m", "base_url": HOSTED_URL},
            "no_url": {"kind": "anthropic", "model": "m"},
            "off": {"kind": "mock", "enabled": False},
            "mock": {"kind": "mock"},
            "replay": {"kind": "replay", "cassette_dir": "cassettes"},
            "ollama": {"kind": "ollama", "model": "m"},
        }
    },
    "privacy": {"egress": {"provider_host_allowlist": ["api.example.test"]}},
}
SETTINGS = Settings.model_validate(BASE)


def configured(**overrides: Any) -> Settings:
    """``SETTINGS`` with ``overrides``, each a section name mapped to its nested keys."""
    return Settings.model_validate(deep_merge(BASE, overrides))


FAST = configured(privacy={"egress": {"scanner_timeout_seconds": 0.05}})


def meta(provider: str = "mock", level: PrivacyLevel = PrivacyLevel.L3) -> EgressMeta:
    return EgressMeta(provider=provider, model="m", level=level, payload_hash=PAYLOAD_HASH)


class Clock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Scripted:
    """A scanner that does what the test tells it to, and counts its calls."""

    def __init__(
        self,
        scanner_id: str = "clean",
        action: Callable[[bytes, EgressMeta], Any] = lambda _body, _meta: (),
    ) -> None:
        self.id = scanner_id
        self.action = action
        self.calls = 0

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        self.calls += 1
        result: Sequence[LeakHit] = self.action(body, meta)
        return result


def hit(scanner_id: str, code: str = "residual_secret", count: int = 1) -> LeakHit:
    return LeakHit(scanner_id=scanner_id, block_code=code, count=count, first_offset=3)


def hitting(scanner_id: str, code: str = "residual_secret") -> Scripted:
    return Scripted(scanner_id, lambda _body, _meta: [hit(scanner_id, code)])


def make_guard(*scanners: LeakScanner, clock: Callable[[], datetime] | None = None) -> EgressGuard:
    registry = ScannerRegistry(scanners or (Scripted(),))
    return EgressGuard(registry, clock=clock) if clock else EgressGuard(registry)


def evaluate(
    guard: EgressGuard,
    request: EgressMeta | None = None,
    *,
    settings: Settings = SETTINGS,
    consent: ConsentDecision | None = None,
    body: bytes = BODY,
    payload_text: str | None = PAYLOAD,
) -> EgressDecision:
    return guard.evaluate(
        body,
        request or meta(),
        settings=settings,
        consent=consent,
        payload_text=payload_text,
    )


def ticket_of(guard: EgressGuard, request: EgressMeta | None = None) -> EgressTicket:
    decision = evaluate(guard, request, consent=GRANTED)
    assert decision.ticket is not None
    return decision.ticket


# ---------------------------------------------------------------- models


def a_ticket() -> EgressTicket:
    return EgressTicket(
        payload_hash=PAYLOAD_HASH,
        provider="mock",
        level=PrivacyLevel.L3,
        expires_at=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
        tag="0" * 32,
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"allowed": True},
        {"allowed": False},
        {"allowed": True, "block_code": "scanner_error"},
        {"allowed": False, "ticket": "ticket"},
        {"allowed": False, "ticket": "ticket", "block_code": "scanner_error"},
        {"allowed": True, "ticket": "ticket", "block_code": "scanner_error"},
        {"allowed": True, "ticket": "ticket", "hits": [hit("x")]},
        {"allowed": False, "block_code": "not_a_code"},
    ],
)
def test_a_decision_is_a_ticket_or_a_code_and_never_both_or_neither(fields: dict[str, Any]) -> None:
    built = {**fields, "ticket": a_ticket()} if "ticket" in fields else fields
    with pytest.raises(ValidationError):
        EgressDecision(**built)


@pytest.mark.parametrize(
    "fields",
    [
        {"count": 0},
        {"first_offset": -1},
        {"block_code": "not_a_code"},
        {"scanner_id": "Not An Id"},
    ],
)
def test_a_leak_hit_is_validated(fields: dict[str, Any]) -> None:
    good: dict[str, Any] = {
        "scanner_id": "x",
        "block_code": "residual_secret",
        "count": 1,
        "first_offset": 0,
    }
    with pytest.raises(ValidationError):
        LeakHit(**(good | fields))


def test_a_leak_hit_has_no_field_that_could_hold_matched_text() -> None:
    assert set(LeakHit.model_fields) == {"scanner_id", "block_code", "count", "first_offset"}


def test_meta_holds_a_hash_and_not_a_payload() -> None:
    with pytest.raises(ValidationError):
        EgressMeta(provider="mock", model="m", level=PrivacyLevel.L3, payload_hash=PAYLOAD)


def test_the_models_are_frozen() -> None:
    ticket = a_ticket()
    with pytest.raises(ValidationError):
        ticket.provider = "other"  # type: ignore[misc]


def test_the_ticket_tag_stays_out_of_its_repr() -> None:
    assert a_ticket().tag not in repr(a_ticket())


def test_the_code_order_names_every_code_once() -> None:
    assert len(BLOCK_CODE_ORDER) == len(BLOCK_CODES) == 14


def _callee(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    return node.func.attr if isinstance(node.func, ast.Attribute) else None


def _strings(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def block_codes_in_source() -> set[str]:
    """Every string the package passes or returns as a block code."""
    found: set[str] = set()
    for path in sorted(EGRESS.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and _callee(node) == "EgressBlocked":
                found |= _strings(node.args[0])
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "block_code" and isinstance(keyword.value, ast.Constant):
                        found |= _strings(keyword.value)
            elif isinstance(node, ast.FunctionDef) and node.name in (
                "_preconditions",
                "_block_code",
            ):
                for item in ast.walk(node):
                    if isinstance(item, ast.Return):
                        found |= _strings(item.value)
    return found


def test_every_block_code_used_in_the_package_is_in_the_vocabulary() -> None:
    used = block_codes_in_source()
    assert {"consent_missing", "hash_mismatch", "scanner_error", "ticket_expired"} <= used
    assert used <= BLOCK_CODES


# ---------------------------------------------------------------- EgressBlocked


@pytest.mark.parametrize("code", BLOCK_CODE_ORDER)
def test_egress_blocked_renders_the_code_only(code: str) -> None:
    error = EgressBlocked(code)
    assert str(error) == code
    assert error.block_code == code
    assert error.args == (code,)


TOKENS = st.text("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", min_size=12, max_size=24)


@given(TOKENS)
def test_egress_blocked_cannot_carry_text_it_is_handed(token: str) -> None:
    error = EgressBlocked(token)
    assert token not in str(error)
    assert token not in repr(error)
    assert error.block_code == "scanner_error"


def test_the_cli_finds_the_exception_where_it_looks() -> None:
    assert guard_module.EgressBlocked is EgressBlocked


# ---------------------------------------------------------------- preconditions


@pytest.mark.parametrize(
    ("provider", "settings"),
    [
        ("unknown", SETTINGS),
        ("off", SETTINGS),
        ("hosted", configured(llm={"allow_remote": False})),
        ("mock", configured(llm={"enabled": False})),
        ("hosted", configured(privacy={"egress": {"provider_host_allowlist": ["other.test"]}})),
        ("hosted", configured(privacy={"egress": {"provider_host_allowlist": []}})),
        ("no_url", SETTINGS),
    ],
    ids=["unknown", "disabled", "remote-off", "llm-off", "host-off-list", "empty-list", "no-host"],
)
def test_a_provider_that_is_not_allowed_blocks(provider: str, settings: Settings) -> None:
    scanner = Scripted()
    decision = evaluate(make_guard(scanner), meta(provider), settings=settings, consent=GRANTED)
    assert decision.block_code == "provider_not_allowed"
    assert scanner.calls == 0


@pytest.mark.parametrize(
    ("url", "entry", "allowed"),
    [
        ("https://api.example.test/v1", "api.example.test", True),
        ("https://API.Example.test/v1", "api.example.TEST", True),
        ("https://eu.api.example.test/v1", "*.api.example.test", True),
        ("https://api.example.test/v1", "*.api.example.test", False),
        ("https://evilapi.example.test/v1", "*.api.example.test", False),
        ("https://api.example.test.evil.test/v1", "api.example.test", False),
        ("https://api.example.test.evil.test/v1", "*.example.test", False),
    ],
)
def test_the_allow_list_matches_whole_hosts(url: str, entry: str, allowed: bool) -> None:
    settings = configured(
        llm={"providers": {"hosted": {"base_url": url}}},
        privacy={"egress": {"provider_host_allowlist": [entry]}},
    )
    decision = evaluate(make_guard(), meta("hosted"), settings=settings, consent=GRANTED)
    assert decision.allowed is allowed


def test_l0_never_goes_to_a_remote_provider() -> None:
    decision = evaluate(make_guard(), meta("hosted", PrivacyLevel.L0), consent=GRANTED)
    assert decision.block_code == "level_not_permitted"


def test_l0_may_use_a_local_model() -> None:
    assert evaluate(make_guard(), meta("ollama", PrivacyLevel.L0)).allowed


def test_a_level_below_the_tier_floor_blocks() -> None:
    decision = evaluate(make_guard(), meta("hosted", PrivacyLevel.L1), consent=GRANTED)
    assert decision.block_code == "level_not_permitted"


@pytest.mark.parametrize("consent", [None, REFUSED], ids=["absent", "refused"])
def test_a_remote_provider_needs_granted_consent(consent: ConsentDecision | None) -> None:
    scanner = Scripted()
    decision = evaluate(make_guard(scanner), meta("hosted"), consent=consent)
    assert decision.block_code == "consent_missing"
    assert scanner.calls == 0


def test_granted_consent_lets_a_remote_request_through() -> None:
    assert evaluate(make_guard(), meta("hosted"), consent=GRANTED).allowed


@pytest.mark.parametrize("provider", ["mock", "replay", "ollama"])
def test_a_provider_inside_the_trust_boundary_needs_no_consent(provider: str) -> None:
    assert evaluate(make_guard(), meta(provider), consent=None).allowed


def boolean_keys(model: type[BaseModel], prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """The dotted path of every boolean field of ``model``, nested sections included."""
    keys: list[tuple[str, ...]] = []
    for name, field in model.model_fields.items():
        kind: Any = field.annotation
        if kind is bool:
            keys.append((*prefix, name))
        elif isinstance(kind, type) and issubclass(kind, BaseModel):
            keys += boolean_keys(kind, (*prefix, name))
    return keys


def nested(path: tuple[str, ...], value: object) -> dict[str, Any]:
    tree: Any = value
    for part in reversed(path):
        tree = {part: tree}
    return dict(tree)


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("key", boolean_keys(PrivacySettings), ids=".".join)
def test_no_privacy_setting_can_grant_consent(key: tuple[str, ...], value: bool) -> None:
    settings = configured(privacy=nested(key, value))
    assert evaluate(make_guard(), meta("hosted"), settings=settings).block_code == "consent_missing"


def test_the_consent_sweep_is_not_empty() -> None:
    assert ("egress", "encrypt_at_rest") in boolean_keys(PrivacySettings)


def field_names(model: type[BaseModel]) -> Iterator[str]:
    for name, field in model.model_fields.items():
        yield name
        for kind in (field.annotation, *get_args(field.annotation)):
            if isinstance(kind, type) and issubclass(kind, BaseModel):
                yield from field_names(kind)


def test_no_setting_anywhere_is_named_for_consent() -> None:
    assert not [name for name in field_names(Settings) if "consent" in name]


def test_a_body_without_the_claimed_payload_blocks() -> None:
    scanner = Scripted()
    decision = evaluate(make_guard(scanner), body=b'{"payload": "something else"}')
    assert decision.block_code == "hash_mismatch"
    assert scanner.calls == 0


def test_text_that_is_in_the_body_but_not_the_claimed_payload_blocks() -> None:
    text = "Review this."
    assert text.encode("utf-8") in BODY
    assert evaluate(make_guard(), payload_text=text).block_code == "hash_mismatch"


@pytest.mark.parametrize(
    "encoded",
    [
        PAYLOAD.encode("utf-8"),
        json.dumps({"p": PAYLOAD}).encode("utf-8"),
        json.dumps({"p": PAYLOAD}, ensure_ascii=False).encode("utf-8"),
    ],
    ids=["raw", "json-ascii", "json-unicode"],
)
def test_the_payload_is_found_however_the_body_encodes_it(encoded: bytes) -> None:
    assert evaluate(make_guard(), body=encoded).allowed


def test_without_the_text_the_body_must_carry_the_digest() -> None:
    assert evaluate(make_guard(), payload_text=None).block_code == "hash_mismatch"
    body = json.dumps({"digest": PAYLOAD_HASH}).encode("utf-8")
    assert evaluate(make_guard(), payload_text=None, body=body).allowed


# ---------------------------------------------------------------- fail closed


def test_a_guard_with_no_scanners_lets_nothing_out() -> None:
    assert evaluate(EgressGuard()).block_code == "scanner_error"


def raises(body: bytes, _meta: EgressMeta) -> Any:
    raise RuntimeError(body.decode("utf-8", "replace"))


def exits(_body: bytes, _meta: EgressMeta) -> Any:
    raise SystemExit(1)


MALFORMED: dict[str, Callable[[str], Any]] = {
    "none": lambda _sid: None,
    "number": lambda _sid: 7,
    "string": lambda _sid: "residual_secret",
    "bytes": lambda _sid: b"residual_secret",
    "not-a-hit": lambda _sid: [("residual_secret", 1)],
    "someone-elses-hit": lambda sid: [hit(sid + "_other")],
}
IDS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")


def scanners_with(faulty: Scripted) -> list[Scripted]:
    """Six scanners, as E12-02 registers, with ``faulty`` taking the place of its own id."""
    return [faulty if name == faulty.id else Scripted(name) for name in IDS]


@pytest.mark.parametrize("scanner_id", IDS)
@pytest.mark.parametrize("fault", [raises, exits], ids=["raises", "exits"])
def test_a_scanner_that_fails_blocks(scanner_id: str, fault: Any) -> None:
    decision = evaluate(make_guard(*scanners_with(Scripted(scanner_id, fault))))
    assert decision.block_code == "scanner_error"
    assert decision.ticket is None


@pytest.mark.parametrize("scanner_id", IDS)
@pytest.mark.parametrize("shape", sorted(MALFORMED))
def test_a_scanner_that_returns_malformed_hits_blocks(scanner_id: str, shape: str) -> None:
    faulty = Scripted(scanner_id, lambda _body, _meta: MALFORMED[shape](scanner_id))
    assert evaluate(make_guard(*scanners_with(faulty))).block_code == "scanner_error"


@pytest.fixture
def released() -> Iterator[threading.Event]:
    """An event that frees a hung scanner's thread when the test ends."""
    event = threading.Event()
    yield event
    event.set()


@pytest.mark.parametrize("scanner_id", IDS)
def test_a_scanner_that_times_out_blocks(scanner_id: str, released: threading.Event) -> None:
    hung = Scripted(scanner_id, lambda _body, _meta: released.wait(30) and ())
    decision = evaluate(make_guard(*scanners_with(hung)), settings=FAST)
    assert decision.block_code == "scanner_error"


def test_a_scanner_that_cannot_be_bound_blocks() -> None:
    class Unbindable(Scripted):
        def bind(self, vault: object, settings: Settings) -> None:
            raise RuntimeError("no vault")

    assert evaluate(make_guard(Unbindable())).block_code == "scanner_error"


def test_a_bound_scanner_receives_the_vault_and_the_settings() -> None:
    seen: list[object] = []

    class Bound(Scripted):
        def bind(self, vault: object, settings: Settings) -> None:
            seen.extend((vault, settings))

    class Vault:
        def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
            return iter(())

    vault = Vault()
    decision = make_guard(Bound()).evaluate(
        BODY, meta(), settings=SETTINGS, consent=None, vault=vault, payload_text=PAYLOAD
    )
    assert decision.allowed
    assert seen == [vault, SETTINGS]


def test_an_internal_failure_blocks() -> None:
    class Broken(ScannerRegistry):
        def __iter__(self) -> Iterator[LeakScanner]:
            raise RuntimeError("broken registry")

    registry = Broken([Scripted()])
    assert evaluate(EgressGuard(registry)).block_code == "scanner_error"


def test_a_request_that_cannot_be_audited_does_not_leave(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_args: object) -> None:
        raise RuntimeError("no log")

    monkeypatch.setattr(EgressGuard, "_audit", staticmethod(broken))
    decision = evaluate(make_guard())
    assert decision.block_code == "scanner_error"
    assert decision.ticket is None


def test_a_hit_names_the_decision_and_keeps_the_counts() -> None:
    decision = evaluate(make_guard(hitting("vault", "vault_identifier")))
    assert not decision.allowed
    assert decision.block_code == "vault_identifier"
    assert decision.hits == (hit("vault", "vault_identifier"),)


def test_the_most_serious_code_names_a_decision() -> None:
    scanners = [
        hitting("size", "size_budget"),
        hitting("pii", "residual_pii"),
        hitting("secret", "residual_secret"),
    ]
    decision = evaluate(make_guard(*scanners))
    assert decision.block_code == "residual_secret"
    assert len(decision.hits) == len(scanners)


def test_a_hit_outranks_a_scanner_that_failed_beside_it() -> None:
    decision = evaluate(make_guard(hitting("pii", "residual_pii"), Scripted("broken", raises)))
    assert decision.block_code == "residual_pii"


def scanner_for(index: int, outcome: str) -> Scripted:
    name = f"s{index}"
    actions: dict[str, Callable[[bytes, EgressMeta], Any]] = {
        "clean": lambda _body, _meta: (),
        "hit": lambda _body, _meta: [hit(name)],
        "raises": raises,
        "malformed": lambda _body, _meta: 7,
    }
    return Scripted(name, actions[outcome])


OUTCOMES = st.lists(
    st.sampled_from(["clean", "hit", "raises", "malformed"]), min_size=1, max_size=6
)


@given(st.binary(max_size=64), OUTCOMES)
def test_nothing_is_allowed_once_any_scanner_hit_or_failed(
    noise: bytes, outcomes: list[str]
) -> None:
    scanners = [scanner_for(index, outcome) for index, outcome in enumerate(outcomes)]
    decision = evaluate(make_guard(*scanners), body=BODY + noise)
    assert decision.allowed is all(outcome == "clean" for outcome in outcomes)
    assert (decision.ticket is not None) is decision.allowed


# ---------------------------------------------------------------- tickets


def test_a_ticket_is_bound_to_the_payload_the_provider_and_the_level() -> None:
    clock = Clock()
    ticket = ticket_of(make_guard(clock=clock), meta("hosted"))
    assert ticket.payload_hash == PAYLOAD_HASH
    assert ticket.provider == "hosted"
    assert ticket.level is PrivacyLevel.L3
    assert ticket.expires_at == clock.now + timedelta(seconds=60)


def redeem(guard: EgressGuard, ticket: EgressTicket, **changes: Any) -> None:
    fields: dict[str, Any] = {
        "payload_hash": ticket.payload_hash,
        "provider": ticket.provider,
        "level": ticket.level,
    }
    guard.redeem(ticket, **(fields | changes))


def test_a_ticket_redeems_once() -> None:
    guard = make_guard()
    ticket = ticket_of(guard)
    redeem(guard, ticket)
    with pytest.raises(EgressBlocked) as caught:
        redeem(guard, ticket)
    assert caught.value.block_code == "ticket_expired"


def test_a_ticket_expires_after_the_configured_time() -> None:
    clock = Clock()
    guard = make_guard(clock=clock)
    settings = configured(privacy={"egress": {"ticket_ttl_seconds": 5}})
    decision = evaluate(guard, settings=settings)
    assert decision.ticket is not None
    clock.advance(5)
    with pytest.raises(EgressBlocked) as caught:
        redeem(guard, decision.ticket)
    assert caught.value.block_code == "ticket_expired"


def test_a_ticket_is_good_until_it_expires() -> None:
    clock = Clock()
    guard = make_guard(clock=clock)
    ticket = ticket_of(guard)
    clock.advance(59)
    redeem(guard, ticket)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"payload_hash": "f" * 64}, "hash_mismatch"),
        ({"provider": "other"}, "provider_not_allowed"),
        ({"level": PrivacyLevel.L2}, "level_not_permitted"),
    ],
    ids=["payload", "provider", "level"],
)
def test_a_ticket_refuses_any_other_request_and_is_burnt(change: dict[str, Any], code: str) -> None:
    guard = make_guard()
    ticket = ticket_of(guard)
    with pytest.raises(EgressBlocked) as caught:
        redeem(guard, ticket, **change)
    assert caught.value.block_code == code
    with pytest.raises(EgressBlocked):
        redeem(guard, ticket)


def test_a_forged_ticket_is_refused() -> None:
    guard = make_guard()
    forged = a_ticket()
    with pytest.raises(EgressBlocked) as caught:
        redeem(guard, forged)
    assert caught.value.block_code == "ticket_expired"


def test_a_ticket_with_altered_fields_is_refused() -> None:
    guard = make_guard()
    ticket = ticket_of(guard)
    altered = ticket.model_copy(update={"payload_hash": "f" * 64})
    with pytest.raises(EgressBlocked) as caught:
        redeem(guard, altered)
    assert caught.value.block_code == "hash_mismatch"


def test_one_guard_does_not_honour_the_ticket_of_another() -> None:
    ticket = ticket_of(make_guard())
    with pytest.raises(EgressBlocked):
        redeem(make_guard(), ticket)


def test_every_ticket_has_its_own_tag() -> None:
    guard = make_guard()
    assert ticket_of(guard).tag != ticket_of(guard).tag


def test_the_live_registry_is_bounded() -> None:
    guard = make_guard()
    first = ticket_of(guard)
    for _ in range(guard_module._MAX_LIVE_TICKETS):
        ticket_of(guard)
    assert guard.live_tickets == guard_module._MAX_LIVE_TICKETS
    with pytest.raises(EgressBlocked):
        redeem(guard, first)


def test_expired_tickets_leave_the_registry() -> None:
    clock = Clock()
    guard = make_guard(clock=clock)
    ticket_of(guard)
    clock.advance(61)
    ticket_of(guard)
    assert guard.live_tickets == 1


def test_a_blocked_request_mints_nothing() -> None:
    guard = make_guard(hitting("secret"))
    evaluate(guard)
    assert guard.live_tickets == 0


def ticket_builders() -> list[str]:
    """Every module under ``src`` that calls ``EgressTicket`` or one of its constructors."""
    found: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            target = node.func.value if isinstance(node.func, ast.Attribute) else node.func
            if isinstance(target, ast.Name) and target.id == "EgressTicket":
                found.append(path.relative_to(SRC).as_posix())
    return found


def test_only_the_private_factory_builds_a_ticket() -> None:
    assert ticket_builders() == ["codekavach/privacy/egress/guard.py"]
    tree = ast.parse((EGRESS / "guard.py").read_text(encoding="utf-8"))
    (mint,) = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(call, ast.Call) and _callee(call) == "EgressTicket"
            for call in ast.walk(node)
        )
    ]
    assert mint.name == "_mint"


# ---------------------------------------------------------------- what reaches the outside


def test_the_audit_line_holds_ids_counts_codes_and_hash_prefixes() -> None:
    guard = make_guard(Scripted("clean"), hitting("vault", "vault_identifier"))
    with capture_logs() as lines:
        evaluate(guard)
    (line,) = [entry for entry in lines if entry["event"] == "egress_decision"]
    assert line == {
        "event": "egress_decision",
        "log_level": "info",
        "scanners": ["clean", "vault"],
        "hit_counts": {"vault": 1},
        "decision": "blocked",
        "block_code": "vault_identifier",
        "provider": "mock",
        "model": "m",
        "level": "L3",
        "payload_hash_prefix": PAYLOAD_HASH[:12],
        "body_hash_prefix": sha256_hex(BODY)[:12],
    }


def test_a_failed_scanner_is_logged_by_id_alone() -> None:
    with capture_logs() as lines:
        evaluate(make_guard(Scripted("broken", raises)))
    (line,) = [entry for entry in lines if entry["event"] == "egress_scanner_failed"]
    assert line == {
        "event": "egress_scanner_failed",
        "log_level": "warning",
        "scanner": "broken",
    }


@given(TOKENS)
def test_no_body_byte_reaches_a_message_a_log_line_or_a_rendering(token: str) -> None:
    body = BODY + token.encode("ascii")

    def quoting(_body: bytes, _meta: EgressMeta) -> Any:
        raise ValueError(f"found {token} in the request")

    guards = (make_guard(Scripted("broken", quoting)), make_guard(hitting("secret")))
    rendered: list[str] = []
    for guard in guards:
        with capture_logs() as lines:
            decision = evaluate(guard, body=body)
        assert decision.block_code is not None
        error = EgressBlocked(decision.block_code)
        rendered += [
            repr(lines),
            repr(decision),
            decision.model_dump_json(),
            str(error),
            repr(error),
        ]
    assert not [text for text in rendered if token in text]


def test_a_scanner_exception_is_not_printed_by_the_thread_hook(
    capfd: pytest.CaptureFixture[str],
) -> None:
    evaluate(make_guard(Scripted("broken", raises)))
    captured = capfd.readouterr()
    assert "fn_1" not in captured.out + captured.err


# ---------------------------------------------------------------- the registry


def test_the_registry_runs_scanners_in_id_order() -> None:
    registry = ScannerRegistry([Scripted("zulu"), Scripted("alpha")])
    assert registry.ids == ("alpha", "zulu")
    assert [scanner.id for scanner in registry] == ["alpha", "zulu"]
    assert len(registry) == 2


@pytest.mark.parametrize("scanner_id", ["", "Upper", "has space", "1digit", "a" * 49])
def test_a_scanner_id_is_validated(scanner_id: str) -> None:
    with pytest.raises(ValueError, match="scanner id"):
        ScannerRegistry([Scripted(scanner_id)])


def test_a_scanner_id_is_unique() -> None:
    with pytest.raises(ValueError, match="already registered"):
        ScannerRegistry([Scripted("same"), Scripted("same")])


def test_unregister_removes_a_scanner_and_tolerates_a_missing_one() -> None:
    registry = ScannerRegistry([Scripted("alpha")])
    registry.unregister("alpha")
    registry.unregister("alpha")
    assert len(registry) == 0
