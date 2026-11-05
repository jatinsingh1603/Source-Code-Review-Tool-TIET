"""The project's I5 test: the same scan salt and the same input give the same pseudonyms (E09-01).

Each test fails if the invariant is weakened: if a token came to depend on the order names were
asked for, on the process, or on anything but the salt and the set of names; if two names shared a
token; or if the salt reached a message, a log line or a ``repr``.
"""

import itertools
import json
import random
import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any, get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from structlog.testing import capture_logs

from codekavach.config import Settings
from codekavach.core.models.location import Location
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing.scopes import SymbolKind
from codekavach.parsing.symbols import Symbol
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise import generator as generator_module
from codekavach.privacy.pseudonymise.generator import (
    PSEUDONYM_SHAPE,
    SYMBOL_KINDS,
    PseudonymGenerator,
    PseudonymKind,
    SecurityRole,
)
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry

SALT_HEX = "5a" * 32  # pragma: allowlist secret
SALT = ScanSalt.from_hex(SALT_HEX)
OTHER_SALT = ScanSalt.from_hex("a5" * 32)  # pragma: allowlist secret
FN = PseudonymKind.FN
VAR = PseudonymKind.VAR
ORIGINAL = "accrue_premium_interest"
NAMES = [f"name_{index}" for index in range(50)]

salts = st.binary(min_size=32, max_size=32).map(ScanSalt)
names = st.text("abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20)
name_sets = st.sets(names, min_size=1, max_size=40)


def numbering(salt: ScanSalt, originals: list[str], kind: PseudonymKind = FN) -> dict[str, str]:
    """Each name's token from a generator prepared with the set, asked in the given order."""
    generator = PseudonymGenerator(salt)
    generator.prepare(kind, originals)
    return {original: generator.token(kind, original) for original in originals}


def index_of(token: str) -> int:
    return int(token.split("_")[1])


# ---------------------------------------------------------------- I5: determinism


@given(salts, name_sets)
def test_the_mapping_is_injective_and_deterministic(salt: ScanSalt, originals: set[str]) -> None:
    ordered = sorted(originals)
    first = numbering(salt, ordered)
    assert first == numbering(salt, ordered)
    assert len(set(first.values())) == len(ordered)


@given(salts, name_sets, st.randoms(use_true_random=False))
def test_a_token_does_not_depend_on_the_order_names_are_asked_for(
    salt: ScanSalt, originals: set[str], shuffler: random.Random
) -> None:
    ordered = sorted(originals)
    shuffled = list(ordered)
    shuffler.shuffle(shuffled)
    assert numbering(salt, ordered) == numbering(salt, shuffled)


def test_a_token_does_not_depend_on_how_many_names_came_before_it() -> None:
    universe = [ORIGINAL, *(f"other_{index}" for index in range(1_000))]
    after_one = PseudonymGenerator(SALT)
    after_one.prepare(FN, universe)
    after_one.token(FN, universe[1])
    after_a_thousand = PseudonymGenerator(SALT)
    after_a_thousand.prepare(FN, universe)
    for other in universe[1:]:
        after_a_thousand.token(FN, other)
    assert after_one.token(FN, ORIGINAL) == after_a_thousand.token(FN, ORIGINAL)


def test_a_slice_that_holds_one_name_gets_the_scan_wide_token() -> None:
    scan = PseudonymGenerator(SALT)
    scan.prepare(VAR, NAMES)
    expected = {name: scan.token(VAR, name) for name in NAMES}
    rerun = PseudonymGenerator(SALT)
    rerun.prepare(VAR, reversed(NAMES))
    assert rerun.token(VAR, NAMES[7]) == expected[NAMES[7]]


def test_a_token_is_stable_within_a_generator() -> None:
    generator = PseudonymGenerator(SALT)
    assert generator.token(FN, ORIGINAL) == generator.token(FN, ORIGINAL)


def test_preparing_more_names_leaves_earlier_tokens_alone() -> None:
    generator = PseudonymGenerator(SALT)
    generator.prepare(FN, NAMES[:10])
    before = {name: generator.token(FN, name) for name in NAMES[:10]}
    generator.prepare(FN, NAMES)
    assert {name: generator.token(FN, name) for name in NAMES[:10]} == before
    assert sorted(index_of(generator.token(FN, name)) for name in NAMES) == list(range(1, 51))


def test_a_name_nobody_prepared_is_numbered_after_the_prepared_ones() -> None:
    generator = PseudonymGenerator(SALT)
    generator.prepare(FN, NAMES)
    assert generator.token(FN, "late_arrival") == "fn_51"
    assert generator.token(FN, "late_arrival") == "fn_51"


def test_another_salt_gives_another_order() -> None:
    assert numbering(SALT, NAMES) != numbering(OTHER_SALT, NAMES)


def test_the_kinds_are_numbered_apart() -> None:
    generator = PseudonymGenerator(SALT)
    assert generator.token(FN, ORIGINAL) == "fn_1"
    assert generator.token(VAR, ORIGINAL) == "var_1"


def test_two_processes_with_one_salt_agree() -> None:
    program = (
        "import json, sys\n"
        "from codekavach.core.pipeline.salt import ScanSalt\n"
        "from codekavach.privacy.pseudonymise.generator import PseudonymGenerator\n"
        "names = json.loads(sys.argv[2])\n"
        "generator = PseudonymGenerator(ScanSalt.from_hex(sys.argv[1]))\n"
        "generator.prepare('fn', names)\n"
        "print(json.dumps({name: generator.token('fn', name) for name in names}))\n"
    )

    def run(ordered: list[str]) -> Any:
        completed = subprocess.run(
            [sys.executable, "-c", program, SALT_HEX, json.dumps(ordered)],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(completed.stdout)

    assert run(NAMES) == run(NAMES[::-1]) == numbering(SALT, NAMES)


def test_the_hash_input_is_the_documented_construction() -> None:
    """Pins ``HMAC-SHA256(salt, f"{kind}:{original}")``: the vectors below must not move."""
    assert numbering(SALT, ["alpha", "bravo", "charlie", "delta"]) == {
        "alpha": "fn_2",
        "bravo": "fn_4",
        "charlie": "fn_1",
        "delta": "fn_3",
    }


# ---------------------------------------------------------------- shape


def test_no_two_names_share_a_token_over_a_hundred_thousand_names() -> None:
    originals = [f"generated_name_{index}" for index in range(100_000)]
    generator = PseudonymGenerator(SALT)
    generator.prepare(VAR, originals)
    tokens = {generator.token(VAR, original) for original in originals}
    assert len(tokens) == len(originals)


@given(salts, name_sets)
def test_numbering_is_dense_per_kind(salt: ScanSalt, originals: set[str]) -> None:
    tokens = numbering(salt, sorted(originals)).values()
    assert sorted(index_of(token) for token in tokens) == list(range(1, len(originals) + 1))


@given(salts, st.sampled_from(PseudonymKind), names, st.sampled_from(SecurityRole))
def test_every_token_matches_the_published_shape(
    salt: ScanSalt, kind: PseudonymKind, original: str, role: SecurityRole
) -> None:
    generator = PseudonymGenerator(salt, role_hints=True)
    assert re.match(PSEUDONYM_SHAPE, generator.token(kind, original))
    assert re.match(PSEUDONYM_SHAPE, generator.token(kind, original, role))


def test_a_changed_token_format_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(generator_module, "_TOKEN", re.compile(r"^never$"))
    with pytest.raises(PseudonymError):
        PseudonymGenerator(SALT).token(FN, ORIGINAL)


def test_a_meaningful_token_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(generator_module, "_MEANINGFUL", frozenset({"fn_1"}))
    with pytest.raises(PseudonymError):
        PseudonymGenerator(SALT).token(FN, ORIGINAL)


def test_a_kind_outside_the_vocabulary_is_refused() -> None:
    with pytest.raises(ValueError, match="PseudonymKind"):
        PseudonymGenerator(SALT).token("password", ORIGINAL)


def test_the_kind_may_be_given_as_its_prefix() -> None:
    assert PseudonymGenerator(SALT).token("cls", ORIGINAL) == "cls_1"


def test_the_order_does_not_follow_the_alphabet() -> None:
    """Over many salts, the first name by HMAC is spread across the alphabet."""
    alphabet = [f"{letter}_name" for letter in "abcdefghijklmnopqrstuvwxyz"]
    first_positions = []
    for seed in range(400):
        salt = ScanSalt(seed.to_bytes(32, "big"))
        tokens = numbering(salt, alphabet)
        first_positions.append(next(i for i, n in enumerate(alphabet) if tokens[n] == "fn_1"))
    mean = sum(first_positions) / len(first_positions)
    assert 10.0 < mean < 15.0  # uniform over 0..25 has mean 12.5 and a standard error of 0.38
    assert len(set(first_positions)) == len(alphabet)


# ---------------------------------------------------------------- symbols


@pytest.mark.parametrize(
    ("kind", "prefix"),
    [
        ("function", "fn"),
        ("method", "fn"),
        ("class", "cls"),
        ("variable", "var"),
        ("parameter", "param"),
        ("field", "field"),
        ("module", "mod"),
        ("import", "mod"),
        ("constant", "const"),
    ],
)
def test_a_symbol_kind_maps_to_its_prefix(kind: SymbolKind, prefix: str) -> None:
    symbol = Symbol(
        name=ORIGINAL,
        kind=kind,
        scope_id=0,
        location=Location(path="app.py", start_line=1, end_line=1),
        is_definition=True,
    )
    assert PseudonymGenerator(SALT).token_for_symbol(symbol) == f"{prefix}_1"


def test_every_symbol_kind_has_a_pseudonym_kind() -> None:
    assert set(SYMBOL_KINDS) == set(get_args(SymbolKind))


# ---------------------------------------------------------------- per_request


def test_per_request_tokens_are_unlinkable_across_requests() -> None:
    scan = PseudonymGenerator(SALT)
    first = scan.for_request(b"request-1")
    second = scan.for_request(b"request-2")
    first.prepare(FN, NAMES)
    second.prepare(FN, NAMES)
    tokens = [(first.token(FN, name), second.token(FN, name)) for name in NAMES]
    assert any(left != right for left, right in tokens)


def test_per_request_tokens_are_consistent_within_a_request() -> None:
    request = PseudonymGenerator(SALT).for_request(b"request-1")
    assert request.token(FN, ORIGINAL) == request.token(FN, ORIGINAL)


def test_one_nonce_gives_one_numbering() -> None:
    def numbered(nonce: bytes) -> list[str]:
        request = PseudonymGenerator(SALT).for_request(nonce)
        request.prepare(FN, NAMES)
        return [request.token(FN, name) for name in NAMES]

    assert numbered(b"request-1") == numbered(b"request-1")


def test_a_request_starts_from_nothing_and_keeps_the_hint_setting() -> None:
    scan = PseudonymGenerator(SALT, role_hints=True)
    scan.prepare(FN, NAMES)
    request = scan.for_request(b"request-1")
    assert repr(request) == "PseudonymGenerator(0 names)"
    assert request.token(VAR, ORIGINAL, SecurityRole.CRED) == "var_1_cred"


# ---------------------------------------------------------------- role hints


def test_a_role_is_ignored_when_role_hints_are_off() -> None:
    assert PseudonymGenerator(SALT).token(VAR, ORIGINAL, SecurityRole.AUTHZ) == "var_1"


@pytest.mark.parametrize("role", list(SecurityRole))
def test_a_role_is_a_suffix_when_role_hints_are_on(role: SecurityRole) -> None:
    generator = PseudonymGenerator(SALT, role_hints=True)
    assert generator.token(VAR, ORIGINAL, role) == f"var_1_{role.value}"
    assert generator.token(VAR, ORIGINAL) == "var_1"


@pytest.mark.parametrize("hints", [True, False])
@pytest.mark.parametrize("role", ["authz", "premium", "id", 3])
def test_a_role_that_is_not_an_enum_member_is_refused(hints: bool, role: Any) -> None:
    with pytest.raises(TypeError, match="SecurityRole"):
        PseudonymGenerator(SALT, role_hints=hints).token(VAR, ORIGINAL, role)


# ---------------------------------------------------------------- settings


def test_the_pseudonym_settings_default_to_the_safe_values() -> None:
    pseudonym = Settings().privacy.pseudonym
    assert pseudonym.link_mode == "per_scan"
    assert pseudonym.role_hints is False


def test_the_link_mode_is_a_closed_choice() -> None:
    assert (
        Settings.model_validate(
            {"privacy": {"pseudonym": {"link_mode": "per_request"}}}
        ).privacy.pseudonym.link_mode
        == "per_request"
    )
    with pytest.raises(ValueError, match="link_mode"):
        Settings.model_validate({"privacy": {"pseudonym": {"link_mode": "per_file"}}})


# ---------------------------------------------------------------- what reaches the outside


def test_the_salt_appears_nowhere_over_a_large_run() -> None:
    fragments = [SALT_HEX, SALT.reveal().decode("latin-1"), repr(SALT.reveal())]
    rendered: list[str] = []
    with capture_logs() as lines:
        generator = PseudonymGenerator(SALT, role_hints=True)
        generator.prepare(FN, (f"name_{index}" for index in range(5_000)))
        for index, role in zip(range(5_000), itertools.cycle(SecurityRole), strict=False):
            rendered.append(generator.token(FN, f"name_{index}", role))
        rendered += [repr(generator), str(generator), repr(generator.for_request(b"n"))]
        bad_calls: list[Callable[[], object]] = [
            lambda: generator.token("nope", "x"),
            lambda: generator.token(FN, "x", "bad"),  # type: ignore[arg-type]
        ]
        for call in bad_calls:
            with pytest.raises((ValueError, TypeError)) as caught:
                call()
            rendered += [str(caught.value), repr(caught.value)]
    rendered.append(repr(lines))
    assert not [text for text in rendered for fragment in fragments if fragment in text]


def test_a_generator_shows_no_name_and_no_salt_in_its_repr() -> None:
    generator = PseudonymGenerator(SALT)
    generator.token(FN, ORIGINAL)
    assert repr(generator) == "PseudonymGenerator(1 names)"


def test_the_salt_is_read_once(monkeypatch: pytest.MonkeyPatch) -> None:
    reads: list[int] = []
    reveal = ScanSalt.reveal

    def counted(self: ScanSalt) -> bytes:
        reads.append(1)
        return reveal(self)

    monkeypatch.setattr(ScanSalt, "reveal", counted)
    generator = PseudonymGenerator(SALT)
    generator.prepare(FN, NAMES)
    generator.token(VAR, ORIGINAL)
    assert len(reads) == 1


ENTRY = MappingEntry("fn_1", ORIGINAL, FN, "module", None)


def test_a_mapping_repr_shows_counts_only() -> None:
    assert ORIGINAL not in repr(ENTRY)
    assert ORIGINAL not in str(ENTRY)
    assert repr(ENTRY) == "MappingEntry(1 mapping)"
    batch = MappingBatch("scan_01J9Z3K7Q2", (ENTRY, ENTRY))
    assert repr(batch) == "MappingBatch(2 mappings)"
    assert ORIGINAL not in str(batch)
    assert len(batch) == 2


def test_mappings_carry_the_never_persist_mark() -> None:
    assert ENTRY.__ck_never_persist__ is True
    assert MappingBatch("scan_01J9Z3K7Q2").__ck_never_persist__ is True


@settings(max_examples=25)
@given(salts, name_sets)
def test_a_repr_of_a_generator_holds_no_name(salt: ScanSalt, originals: set[str]) -> None:
    generator = PseudonymGenerator(salt)
    generator.prepare(FN, originals)
    assert repr(generator) == f"PseudonymGenerator({len(originals)} names)"
