"""The six egress leak scanners (E12-02): one test group per block code, then the shared rules."""

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.config.merge import deep_merge
from codekavach.core.models import PrivacyLevel
from codekavach.privacy.egress.guard import LeakScanner, ScannerRegistry
from codekavach.privacy.egress.models import EgressMeta
from codekavach.privacy.egress.scanners import (
    SCANNER_IDS,
    AggregationScanner,
    BudgetScanner,
    DomainTermScanner,
    OriginalMatcher,
    ResidualPiiScanner,
    ResidualSecretScanner,
    VaultOriginalScanner,
    default_scanners,
    register_default_scanners,
    release,
    warm,
)
from codekavach.privacy.egress.textview import json_strings, normalise, view_of
from codekavach.privacy.slicing.metrics import ScanDisclosure
from tests.support.slicing import make_index
from tests.unit.privacy.slicing.test_metrics import make, seg

META = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash="0" * 64)
ORIGINAL = "calculate_festival_bonus"
OTHER = "AccountLedgerEntry"


class FakeVault:
    """The part of a vault a scanner may use: originals, and a count to detect change."""

    def __init__(self, originals: list[str]) -> None:
        self.originals = originals

    def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
        yield from (item for item in self.originals if len(item) >= min_len)

    def original_count(self, min_len: int = 4) -> int:
        return len(list(self.iter_originals(min_len=min_len)))


def settings(**privacy: Any) -> Settings:
    return Settings.model_validate(deep_merge({}, {"privacy": privacy}))


def body_of(text: str) -> bytes:
    return json.dumps({"payload": text}).encode("utf-8")


def bound(scanner: Any, vault: FakeVault | None = None, config: Settings | None = None) -> Any:
    scanner.bind(vault, config or settings())
    return scanner


def vault_scanner(*originals: str, config: Settings | None = None) -> VaultOriginalScanner:
    scanner = VaultOriginalScanner()
    scanner.bind(FakeVault(list(originals)), config or settings())
    return scanner


@pytest.fixture(autouse=True)
def _forget_body() -> Iterator[None]:
    yield
    release(ScannerRegistry())


# --- the text view -----------------------------------------------------------------------------


def test_normalise_folds_case_whitespace_zero_width_and_lookalikes() -> None:
    assert normalise("Fo\u200bo\u202e   BAR\n\tbaz") == "foo bar baz"
    assert normalise("\u0430ccount") == "account"  # Cyrillic a
    assert normalise("\uff46\uff55\uff4c\uff4c") == "full"  # full-width forms


def test_a_json_body_is_read_through_its_escapes() -> None:
    raw = '{"k\\u0065y": "va\\u006cue", "n": [1, "x"]}'
    assert json_strings(raw) == "key\nvalue\nn\nx"
    assert json_strings("not json {") is None


def test_the_view_of_a_body_is_decoded_once_per_body() -> None:
    body = body_of("abc")
    assert view_of(body) is view_of(body)
    assert view_of(body_of("abc")) is not view_of(body)


def test_an_invalid_utf8_body_is_decoded_with_replacement_and_still_scanned() -> None:
    scanner = vault_scanner(ORIGINAL)
    hits = scanner.scan(b"\xff\xfe " + ORIGINAL.encode(), META)
    assert [h.block_code for h in hits] == ["vault_identifier"]


# --- vault_identifier --------------------------------------------------------------------------

ESCAPED = json.dumps({"p": ORIGINAL}, ensure_ascii=True).encode().replace(b"calc", b"\\u0063alc")
FORMS = {
    "plain": body_of(f"x = {ORIGINAL}(1)"),
    "json_escaped": ESCAPED,
    "case_changed": body_of(f"x = {ORIGINAL.upper()}(1)"),
    "zero_width": body_of(f"x = {ORIGINAL[:5]}\u200b{ORIGINAL[5:]}(1)"),
    "bidi_mark": body_of(f"x = {ORIGINAL[:9]}\u202e{ORIGINAL[9:]}(1)"),
    "cyrillic_lookalike": body_of(f"x = {ORIGINAL.replace('a', chr(0x430))}(1)"),
    "inside_a_longer_word": body_of(f"x = pre_{ORIGINAL}_post(1)"),
    "inside_a_sentence": body_of(f"Please review the function {ORIGINAL} below."),
}


@pytest.mark.parametrize("form", sorted(FORMS))
def test_an_original_in_any_listed_form_is_found(form: str) -> None:
    hits = vault_scanner(ORIGINAL, OTHER).scan(FORMS[form], META)
    assert len(hits) == 1
    assert (hits[0].scanner_id, hits[0].block_code) == ("vault_original", "vault_identifier")
    assert hits[0].count == 1
    assert hits[0].first_offset >= 0


def test_a_clean_body_has_no_hit() -> None:
    assert vault_scanner(ORIGINAL, OTHER).scan(body_of("var_1 = fn_2(var_3)"), META) == ()


def test_count_and_first_offset_cover_every_occurrence() -> None:
    hits = vault_scanner(ORIGINAL).scan(body_of(f"{ORIGINAL} a {ORIGINAL} b {ORIGINAL}"), META)
    assert hits[0].count == 3
    assert hits[0].first_offset >= 0  # an offset into the view that matched, not the body


def test_originals_shorter_than_four_characters_are_not_checked() -> None:
    assert vault_scanner("abc", "id").scan(body_of("abc id abc"), META) == ()


def test_a_name_on_the_public_allowlist_is_not_an_original() -> None:
    scanner = vault_scanner("print", "isinstance", "append", ORIGINAL)
    assert scanner.scan(body_of("print(isinstance(x, list)); y.append(1)"), META) == ()
    assert len(scanner.scan(body_of(ORIGINAL), META)) == 1


def test_a_pseudonym_token_that_collides_with_an_original_is_not_checked() -> None:
    scanner = vault_scanner("var_12", "fn_3", "cls_4", "SECRET", "aws_access_key")
    assert scanner.scan(body_of("var_12 = fn_3(cls_4) <SECRET:aws_access_key:1>"), META) == ()


def test_exclusions_apply_only_to_the_exact_names() -> None:
    scanner = vault_scanner("printer_queue")  # contains the public word print
    assert len(scanner.scan(body_of("printer_queue.flush()"), META)) == 1


def test_the_automaton_is_rebuilt_when_the_vault_grows() -> None:
    vault = FakeVault([OTHER])
    scanner = VaultOriginalScanner()
    scanner.bind(vault, settings())
    assert scanner.scan(body_of(ORIGINAL), META) == ()
    vault.originals.append(ORIGINAL)  # a context round added a mapping
    scanner.bind(vault, settings())
    assert len(scanner.scan(body_of(ORIGINAL), META)) == 1


def test_warm_builds_before_the_first_request_and_release_drops_it() -> None:
    registry = register_default_scanners(ScannerRegistry(), ScanDisclosure(repo_lines=100))
    warm(registry, FakeVault([ORIGINAL]), settings())
    scanner = next(item for item in registry if isinstance(item, VaultOriginalScanner))
    assert len(scanner.scan(body_of(ORIGINAL), META)) == 1
    release(registry)
    with pytest.raises(RuntimeError, match="not been built"):
        scanner.scan(body_of(ORIGINAL), META)


def test_binding_without_a_vault_fails() -> None:
    with pytest.raises(RuntimeError, match="needs the vault"):
        VaultOriginalScanner().bind(None, settings())


def test_the_matcher_counts_word_patterns_by_run_and_phrases_by_text() -> None:
    matcher = OriginalMatcher(["festival", "festival bonus", "ab cd ef"])
    assert matcher.scan("a festival bonus and festivals, ab cd ef") == (4, 2)
    assert matcher.scan("nothing here") == (0, -1)
    assert len(matcher) == 3


# --- nothing prints, logs or raises the matched text -------------------------------------------


def test_no_scanner_output_log_or_representation_contains_the_matched_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = settings(domain_terms=["Phoenix Ledger"])
    registry = register_default_scanners(ScannerRegistry(), ScanDisclosure(repo_lines=100))
    caplog.set_level(logging.DEBUG)
    warm(registry, FakeVault([ORIGINAL]), config)
    dirty = body_of(f"{ORIGINAL} and Phoenix Ledger for jane.roe@corp-mail.in")
    shown: list[str] = []
    for scanner in registry:
        bound(scanner, FakeVault([ORIGINAL]), config)
        shown.append(repr(scanner))
        shown.extend(repr(hit) + hit.model_dump_json() for hit in scanner.scan(dirty, META))
    shown.append(caplog.text)
    joined = "\n".join(shown).casefold()
    for term in (ORIGINAL, "phoenix", "jane.roe", "corp-mail"):
        assert term.casefold() not in joined, "a matched term appeared in an output"


def test_a_scanner_that_fails_does_not_print_the_text_it_was_given() -> None:
    scanner = ResidualSecretScanner()
    with pytest.raises(RuntimeError) as caught:
        scanner.scan(body_of(ORIGINAL), META)
    assert ORIGINAL not in str(caught.value)


def test_scanners_are_marked_never_to_persist() -> None:
    for scanner in default_scanners(ScanDisclosure(repo_lines=1)):
        assert scanner.__ck_never_persist__ is True  # type: ignore[attr-defined]


def test_no_scanner_exposes_the_patterns_it_holds() -> None:
    scanner = vault_scanner(ORIGINAL)
    public = {name for name in dir(scanner) if not name.startswith("_")}
    assert public == {"bind", "id", "release", "scan", "warm"}
    assert not any(ORIGINAL in repr(value) for value in vars(scanner).values())
    assert "__dict__" in dir(scanner) and ORIGINAL not in repr(scanner)


# --- residual_secret and residual_pii ----------------------------------------------------------

AWS_EXAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"  # the vendor-documented example key


def test_a_residual_secret_is_found_in_a_plain_and_an_escaped_body() -> None:
    scanner = bound(ResidualSecretScanner())
    plain = scanner.scan(body_of(f'key = "{AWS_EXAMPLE}"'), META)
    assert [(h.scanner_id, h.block_code, h.count) for h in plain] == [
        ("residual_secret", "residual_secret", 1)
    ]
    escaped = json.dumps({"p": f'key = "{AWS_EXAMPLE}"'}).encode().replace(b"AKIA", b"\\u0041KIA")
    assert len(scanner.scan(escaped, META)) == 1


def test_a_placeholder_is_not_a_residual_secret() -> None:
    scanner = bound(ResidualSecretScanner())
    assert scanner.scan(body_of('key = "<SECRET:aws_access_key:1>"'), META) == ()


def test_a_residual_secret_is_not_reported_by_the_pii_scanner_and_the_reverse() -> None:
    secret = bound(ResidualSecretScanner())
    pii = bound(ResidualPiiScanner())
    assert pii.scan(body_of(f'key = "{AWS_EXAMPLE}"'), META) == ()
    mail = body_of("write to jane.roe@corp-mail.in")
    assert secret.scan(mail, META) == ()
    assert [h.block_code for h in pii.scan(mail, META)] == ["residual_pii"]


def test_a_card_number_with_a_valid_checksum_is_residual_pii() -> None:
    pii = bound(ResidualPiiScanner())
    assert len(pii.scan(body_of("card 4111 1111 1111 1111"), META)) == 1
    assert pii.scan(body_of("card 4111 1111 1111 1112"), META) == ()  # fails the checksum


def test_a_placeholder_is_not_residual_pii() -> None:
    pii = bound(ResidualPiiScanner())
    assert pii.scan(body_of("mail <PII:email:1>"), META) == ()


# --- domain_term -------------------------------------------------------------------------------


def test_a_domain_term_is_found_case_insensitively_across_whitespace_and_escapes() -> None:
    scanner = bound(DomainTermScanner(), config=settings(domain_terms=["Festival Bonus"]))
    for text in ("the Festival Bonus rule", "the FESTIVAL   bonus", "festival\nbonus"):
        hits = scanner.scan(body_of(text), META)
        assert [(h.block_code, h.count) for h in hits] == [("domain_term", 1)], text
    assert scanner.scan(body_of("the bonus festival rule"), META) == ()


def test_no_domain_terms_means_no_hit() -> None:
    assert bound(DomainTermScanner()).scan(body_of("anything at all"), META) == ()


def test_changing_the_term_list_rebuilds_the_detector() -> None:
    scanner = DomainTermScanner()
    scanner.bind(None, settings(domain_terms=["Phoenix Ledger"]))
    assert len(scanner.scan(body_of("phoenix ledger"), META)) == 1
    scanner.bind(None, settings(domain_terms=["Other Term"]))
    assert scanner.scan(body_of("phoenix ledger"), META) == ()


# --- size_budget and rate_budget ---------------------------------------------------------------


def test_a_body_over_the_size_limit_blocks_with_size_budget() -> None:
    config = settings(egress={"max_payload_bytes": 1024})
    scanner = bound(BudgetScanner(), config=config)
    assert scanner.scan(b"x" * 1024, META) == ()
    hits = scanner.scan(b"x" * 1025, META)
    assert [(h.block_code, h.first_offset) for h in hits] == [("size_budget", 1024)]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_the_token_bucket_blocks_the_request_after_the_limit_and_refills() -> None:
    clock = Clock()
    scanner = bound(BudgetScanner(clock), config=settings(egress={"rate_per_minute": 3}))
    results = [scanner.scan(b"{}", META) for _ in range(5)]
    assert [bool(r) for r in results] == [False, False, False, True, True]
    assert results[3][0].block_code == "rate_budget"
    clock.now += 20  # three per minute refills one token in twenty seconds
    assert scanner.scan(b"{}", META) == ()
    assert scanner.scan(b"{}", META) != ()


def test_each_provider_has_its_own_bucket() -> None:
    scanner = bound(BudgetScanner(Clock()), config=settings(egress={"rate_per_minute": 1}))
    other = META.model_copy(update={"provider": "second"})
    assert scanner.scan(b"{}", META) == ()
    assert scanner.scan(b"{}", other) == ()  # a different provider is not rate limited by the first
    assert scanner.scan(b"{}", META) != ()
    assert scanner.scan(b"{}", other) != ()


def test_the_size_and_rate_codes_can_come_together() -> None:
    config = settings(egress={"max_payload_bytes": 1024, "rate_per_minute": 1})
    scanner = bound(BudgetScanner(Clock()), config=config)
    scanner.scan(b"{}", META)
    codes = sorted(h.block_code for h in scanner.scan(b"x" * 2000, META))
    assert codes == ["rate_budget", "size_budget"]


# --- aggregation_budget ------------------------------------------------------------------------


REPO = make_index({"a.py": "x = 1\n" * 1000})


def record_of(pct: float) -> ScanDisclosure:
    """A scan record that has disclosed ``pct`` percent of a 1 000-line repository."""
    record = ScanDisclosure.for_index(REPO)
    if pct:
        record.record(make(seg("a.py", 1, round(pct * 10))), REPO)
    return record


@pytest.mark.parametrize(
    ("share", "ceiling", "blocked"),
    [(9.9, 10.0, False), (10.0, 10.0, False), (10.1, 10.0, True), (100.0, 100.0, False)],
)
def test_aggregation_blocks_only_above_the_ceiling(
    share: float, ceiling: float, blocked: bool
) -> None:
    scanner = bound(
        AggregationScanner(record_of(share)),
        config=settings(egress={"aggregation_budget_pct": ceiling}),
    )
    hits = scanner.scan(b"{}", META)
    assert bool(hits) is blocked
    if blocked:
        assert (hits[0].scanner_id, hits[0].block_code) == ("aggregation", "aggregation_budget")


def test_the_default_ceiling_never_blocks() -> None:
    assert bound(AggregationScanner(record_of(100.0))).scan(b"{}", META) == ()


def test_the_disclosure_can_be_chosen_per_provider() -> None:
    seen: list[str] = []

    def per(provider: str) -> ScanDisclosure:
        seen.append(provider)
        return record_of(50.0)

    scanner = bound(
        AggregationScanner(record_of(0), disclosure_for=per),
        config=settings(egress={"aggregation_budget_pct": 10.0}),
    )
    assert len(scanner.scan(b"{}", META)) == 1
    assert seen == ["hosted"]


def test_a_candidate_refused_by_the_exposure_account_is_blocked_whatever_the_share() -> None:
    """E26-01: the prepare stage's engagement or scan refusal reaches the guard and is ledgered."""
    refused = "cand_01ARYZ6S410000000000000001"
    scanner = bound(AggregationScanner(record_of(0), refused=[refused]))
    mine = META.model_copy(update={"candidate_id": refused})
    other = META.model_copy(update={"candidate_id": "cand_01ARYZ6S410000000000000002"})
    hits = scanner.scan(b"{}", mine)
    assert [(h.scanner_id, h.block_code) for h in hits] == [("aggregation", "aggregation_budget")]
    assert scanner.scan(b"{}", other) == ()
    assert scanner.scan(b"{}", META) == ()


def test_the_lifetime_budget_is_optional_and_bounded() -> None:
    assert settings().privacy.egress.lifetime_budget_pct is None
    assert settings(egress={"lifetime_budget_pct": 15.0}).privacy.egress.lifetime_budget_pct == 15
    for bad in (0.0, 100.5):
        with pytest.raises(ValueError, match="lifetime_budget_pct"):
            settings(egress={"lifetime_budget_pct": bad})


# --- registration and determinism --------------------------------------------------------------


def test_the_six_scanners_register_with_stable_ids() -> None:
    registry = register_default_scanners(ScannerRegistry(), ScanDisclosure(repo_lines=1))
    assert registry.ids == tuple(sorted(SCANNER_IDS))
    assert len(registry) == 6
    assert all(isinstance(scanner, LeakScanner) for scanner in registry)


def test_the_hits_do_not_depend_on_registration_order() -> None:
    config = settings(domain_terms=["Phoenix Ledger"])
    dirty = body_of(f"{ORIGINAL} Phoenix Ledger {AWS_EXAMPLE} jane.roe@corp-mail.in")

    def hits(order: slice) -> list[tuple[str, str, int, int]]:
        scanners = default_scanners(ScanDisclosure(repo_lines=1))[order]
        out: list[tuple[str, str, int, int]] = []
        for scanner in scanners:
            bound(scanner, FakeVault([ORIGINAL]), config)
            out.extend(
                (h.scanner_id, h.block_code, h.count, h.first_offset)
                for h in scanner.scan(dirty, META)
            )
        return sorted(out)

    forward = hits(slice(None))
    assert hits(slice(None, None, -1)) == forward
    assert {item[0] for item in forward} == {
        "domain_term",
        "residual_pii",
        "residual_secret",
        "vault_original",
    }
