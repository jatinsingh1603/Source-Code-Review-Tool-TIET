"""Invariant I6 at the egress guard: no original of four or more characters reaches the ledger.

The guard runs the six scanners of E12-02 over the final body. A body that holds an original in a
plain, JSON-escaped, case-changed or zero-width form is blocked, so it is never sent and never
stored as a sent payload; a clean body goes through and the ledger holds nothing from the vault.
"""

import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import TokenCounts
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.text import SanitisedText
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.guard import EgressGuard, ScannerRegistry
from codekavach.privacy.egress.ledger import EgressDraft, open_writer
from codekavach.privacy.egress.models import EgressDecision, EgressMeta
from codekavach.privacy.egress.scanners import (
    VaultOriginalScanner,
    register_default_scanners,
    release,
    warm,
)
from codekavach.privacy.slicing.metrics import ScanDisclosure
from tests.support.factories import FIXED_NOW, SCAN_ID
from tests.support.ledger_terms import assert_no_terms_in_ledger

pytestmark = pytest.mark.privacy

GRANTED = ConsentDecision(granted=True, source="flag")
SETTINGS = Settings.model_validate(
    {
        "llm": {
            "allow_remote": True,
            "providers": {
                "hosted": {
                    "kind": "openai-compatible",
                    "model": "m",
                    "base_url": "https://api.example.test/v1",
                }
            },
        },
        "privacy": {
            "domain_terms": ["Phoenix Ledger"],
            "egress": {"provider_host_allowlist": ["api.example.test"]},
        },
    }
)
ORIGINALS = ["calculate_festival_bonus", "AccountLedgerEntry", "merchant_payout_queue"]
CLEAN = "def fn_1(var_1, var_2):\n    return var_1 + cls_2(var_2)\n"


class Vault:
    def __init__(self, originals: list[str]) -> None:
        self.originals = originals

    def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
        yield from (item for item in self.originals if len(item) >= min_len)

    def original_count(self, min_len: int = 4) -> int:
        return len(list(self.iter_originals(min_len=min_len)))


def guard_and_vault(originals: list[str]) -> tuple[EgressGuard, Vault]:
    registry = register_default_scanners(ScannerRegistry(), ScanDisclosure(repo_lines=1000))
    vault = Vault(originals)
    warm(registry, vault, SETTINGS)
    return EgressGuard(registry), vault


def evaluate(
    guard: EgressGuard, vault: Vault, payload: str, body: bytes | None = None
) -> EgressDecision:
    request = EgressMeta(
        provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash=sha256_hex(payload)
    )
    return guard.evaluate(
        body or json.dumps({"system": "Review this.", "payload": payload}).encode("utf-8"),
        request,
        settings=SETTINGS,
        consent=GRANTED,
        vault=vault,
        payload_text=payload,
    )


def draft_of(payload: str, index: int) -> EgressDraft:
    return EgressDraft(
        timestamp=FIXED_NOW,
        scan_id=SCAN_ID,
        candidate_id=None,
        provider="hosted",
        model="m",
        task="triage",
        level=PrivacyLevel.L3,
        payload_hash=sha256_hex(payload),
        token_counts=TokenCounts(prompt=len(payload)),
        outcome=EgressOutcome.SENT,
    )


def test_a_clean_body_passes_all_six_scanners_and_the_ledger_holds_no_original(
    tmp_path: Path,
) -> None:
    guard, vault = guard_and_vault(ORIGINALS)
    decision = evaluate(guard, vault, CLEAN)
    assert decision.allowed, decision
    ledger = open_writer(tmp_path / "state", key_source="ephemeral")
    ledger.append(draft_of(CLEAN, 1), SanitisedText(CLEAN))
    assert_no_terms_in_ledger(ledger, [*ORIGINALS, "Phoenix Ledger"])
    release(guard.registry)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda text: text, id="plain"),
        pytest.param(lambda text: text.upper(), id="case_changed"),
        pytest.param(lambda text: text[:6] + "\u200b" + text[6:], id="zero_width"),
        pytest.param(lambda text: text.replace("a", "\u0430"), id="cyrillic_a"),
    ],
)
@pytest.mark.parametrize("original", ORIGINALS)
def test_a_body_with_an_original_is_blocked_with_vault_identifier(
    original: str, mutate: Callable[[str], str]
) -> None:
    guard, vault = guard_and_vault(ORIGINALS)
    payload = CLEAN + f"# see {mutate(original)}\n"
    decision = evaluate(guard, vault, payload)
    assert not decision.allowed
    assert decision.block_code == "vault_identifier"
    assert decision.ticket is None
    release(guard.registry)


def test_an_original_in_a_json_escape_is_blocked() -> None:
    guard, vault = guard_and_vault(ORIGINALS)
    body = json.dumps({"payload": CLEAN, "note": ORIGINALS[0]}).replace("calc", "\\u0063alc")
    decision = evaluate(guard, vault, CLEAN, body.encode("utf-8"))
    assert decision.block_code == "vault_identifier"
    release(guard.registry)


def test_a_domain_term_in_the_body_is_blocked_with_domain_term() -> None:
    guard, vault = guard_and_vault(ORIGINALS)
    decision = evaluate(guard, vault, CLEAN + "# Phoenix Ledger\n")
    assert decision.block_code == "domain_term"
    release(guard.registry)


def test_the_guard_decision_and_its_log_do_not_hold_the_original(
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard, vault = guard_and_vault(ORIGINALS)
    decision = evaluate(guard, vault, CLEAN + f"# {ORIGINALS[1]}\n")
    shown = (repr(decision) + decision.model_dump_json() + capsys.readouterr().out).casefold()
    assert all(original.casefold() not in shown for original in ORIGINALS)
    release(guard.registry)


def test_the_term_assertion_fails_without_printing_the_term(tmp_path: Path) -> None:
    ledger = open_writer(tmp_path / "state", key_source="ephemeral")
    leaky = CLEAN + f"# {ORIGINALS[0]}\n"
    ledger.append(draft_of(leaky, 1), SanitisedText(leaky))
    with pytest.raises(AssertionError) as caught:
        assert_no_terms_in_ledger(ledger, ORIGINALS)
    assert ORIGINALS[0] not in str(caught.value)
    assert_no_terms_in_ledger(ledger, ["abc"], min_len=4)  # shorter than the minimum: not checked


# --- the property -------------------------------------------------------------------------------

_LETTERS = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=4, max_size=14)
_ORIGINAL = _LETTERS.map(lambda tail: "zq" + tail + "_x")  # never a keyword, builtin or token
_FILLER = st.lists(st.sampled_from(["var_1", "fn_2", "return", "value", "(", ")", "="]), max_size=8)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    pool=st.lists(_ORIGINAL, min_size=1, max_size=8, unique=True),
    data=st.data(),
    filler=_FILLER,
)
def test_the_hits_are_exactly_the_embedded_originals(
    pool: list[str], data: st.DataObject, filler: list[str]
) -> None:
    embedded = data.draw(st.lists(st.sampled_from(pool), max_size=len(pool), unique=True))
    text = " ".join([*filler, *embedded])
    body = json.dumps({"payload": text}).encode("utf-8")
    request = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash="0" * 64)
    found = set()
    for original in pool:
        scanner = VaultOriginalScanner()
        scanner.bind(Vault([original]), SETTINGS)
        if scanner.scan(body, request):
            found.add(original)
    assert set(embedded) <= found  # nothing embedded is missed
    # Anything else found is a substring of something that is in the body.
    assert all(any(item in part for part in [*filler, *embedded]) for item in found - set(embedded))
    whole = VaultOriginalScanner()
    whole.bind(Vault(pool), SETTINGS)
    assert bool(whole.scan(body, request)) is bool(found)
