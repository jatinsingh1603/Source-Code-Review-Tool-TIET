"""The pseudonymiser of E09-05: the whole path from a slice and a redaction to a payload.

Covers the levels, the fail-closed rule for every step, determinism (also across processes), the
survival self-check by fault injection, the provenance and golden payloads for two
KavachBank-shaped inputs.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import codekavach.privacy.pseudonymise.engine as engine_module
from codekavach.core.models import CodeSlice, Language, PrivacyLevel
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.engine import (
    PSEUDONYMISE_VERSION,
    Pseudonymiser,
    _check_survival,
)
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.renamers.registry import default_registry
from codekavach.privacy.redact.redactor import RedactionResult
from tests.support.factories import SCAN_ID
from tests.support.golden import assert_matches_golden
from tests.support.payload import SALT, segment, slice_of, stub, unredacted

PAYLOADS = Path(__file__).resolve().parents[3] / "fixtures" / "pseudonymise" / "payload"
L3 = PrivacyLevel.L3
ENGINE = Pseudonymiser()


def file_slice(name: str, language: Language):  # type: ignore[no-untyped-def]
    lines = (PAYLOADS / name).read_text(encoding="utf-8").splitlines()
    return slice_of(segment(name, 1, lines), language=language)


def run(slice_, *, level: PrivacyLevel = L3, salt: ScanSalt = SALT, redaction=None):  # type: ignore[no-untyped-def]
    return ENGINE.process(
        slice_,
        redaction if redaction is not None else unredacted(slice_, level),
        salt=salt,
        level=level,
        scan_id=SCAN_ID,
    )


PY = file_slice("handler.py", Language.PYTHON)
JS = file_slice("route.js", Language.JAVASCRIPT)
JAVA = file_slice("handler.java", Language.JAVA)
GO = file_slice("handler.go", Language.GO)


# --- golden payloads and the shape of the result --------------------------------------------


@pytest.mark.parametrize(
    ("slice_", "golden"),
    [
        (PY, "handler.py.golden.txt"),
        (JS, "route.js.golden.txt"),
        (JAVA, "handler.java.golden.txt"),
        (GO, "handler.go.golden.txt"),
    ],
    ids=["python", "javascript", "java", "go"],
)
def test_the_payload_matches_its_golden(slice_, golden: str) -> None:  # type: ignore[no-untyped-def]
    result = run(slice_)
    assert_matches_golden(result.payload.text.expose(), PAYLOADS / golden)


@pytest.mark.parametrize(
    ("slice_", "names"),
    [
        (JAVA, ("LoanDisbursement", "festivalBonus", "borrowerRef", "disburse", "limit_amount")),
        (GO, ("Disbursement", "FestivalBonus", "BorrowerRef", "festival_bonus", "limit_amount")),
    ],
    ids=["java", "go"],
)
def test_a_java_or_go_payload_validates_and_holds_none_of_the_clients_names(
    slice_: CodeSlice,
    names: tuple[str, ...],
) -> None:
    result = run(slice_)
    text = result.payload.text.expose()
    assert not [name for name in names if name in text]
    assert result.payload.pseudonym_count == len(result.batch) > 0
    assert run(slice_).payload.text.expose() == text


def test_a_python_payload_validates_and_inverts_its_line_map() -> None:
    result = run(PY)
    payload = result.payload
    assert payload.level is L3
    assert payload.slice_id == PY.id
    assert payload.pseudonym_count == len(result.batch) > 0
    covered = [n for n in range(1, payload.text.line_count + 1) if payload.map_line(n)]
    assert covered, "no payload line maps to a file line"
    for number in covered:
        index, file_line = payload.map_line(number)
        assert index == 0
        assert PY.segments[0].region.start_line <= file_line <= PY.segments[0].region.end_line
    # the first code line of the file is on the first covered payload line
    assert payload.map_line(covered[0]) == (0, 1)


def test_the_placeholders_of_the_redaction_are_declared_by_the_payload() -> None:
    declared = {ref.token for ref in run(PY).payload.placeholders}
    assert declared == {"<PII:email:1>"}


def test_no_original_name_of_the_client_is_in_the_payload() -> None:
    text = run(PY).payload.text.expose()
    for name in (
        "get_account_balance",
        "accrue_interest",
        "RATE_TABLE",
        "account_id",
        "customer",
        "kavachbank",
        "ledger.db",
        "festival_rates",
        "audit",
    ):
        assert name not in text, name
    assert "cursor =" not in text  # the variable; the sqlite3 method .cursor() is public
    for kept in ("sqlite3", "jsonify", "request", "execute", "fetchone", ".cursor("):
        assert kept in text, kept


def test_a_javascript_payload_keeps_the_shorthand_keys_only_beside_their_token() -> None:
    text = run(JS).payload.text.expose()
    assert "accountId: " in text
    assert text.count("accountId") == text.count("accountId: ")
    assert "customerTier" in text  # same rule: written as ``customerTier: var_N``
    assert "premium" not in text and "fraud" not in text


def test_the_payload_text_is_never_the_original_text() -> None:
    for slice_ in (PY, JS):
        original = "\n".join(s.text.expose() for s in slice_.segments)
        assert original not in run(slice_).payload.text.expose()


# --- levels ---------------------------------------------------------------------------------


def test_l1_replaces_values_only_and_renames_nothing() -> None:
    result = run(PY, level=PrivacyLevel.L1)
    text = result.payload.text.expose()
    assert "get_account_balance" in text
    assert text == unredacted(PY, PrivacyLevel.L1).text
    assert len(result.batch) == 0
    assert result.payload.pseudonym_count == 0
    assert result.provenance.allowlist_version is None
    assert next(n for n in range(1, 40) if result.payload.map_line(n)) == 3


def test_l2_takes_the_same_path_as_l3() -> None:
    l2 = run(PY, level=PrivacyLevel.L2).payload.text.expose()
    l3 = run(PY).payload.text.expose()
    assert l2.splitlines()[1:] == l3.splitlines()[1:]  # only the header names the level
    assert l2.splitlines()[0].endswith("L2")


def test_l4_is_a_visible_seam_that_names_its_epic() -> None:
    with pytest.raises(NotImplementedError, match="E27"):
        run(PY, level=PrivacyLevel.L4)


def test_l0_sends_nothing() -> None:
    with pytest.raises(PseudonymError, match="L0"):
        run(PY, level=PrivacyLevel.L0)


# --- determinism ----------------------------------------------------------------------------


def test_the_same_input_and_salt_give_the_same_hash_and_mappings() -> None:
    first, second = run(PY), run(PY)
    assert first.payload.payload_hash == second.payload.payload_hash
    assert first.payload.id != second.payload.id  # the id is new every time; the hash is not
    assert [(e.pseudonym, e.original) for e in first.batch.entries] == [
        (e.pseudonym, e.original) for e in second.batch.entries
    ]


def test_another_salt_gives_another_payload() -> None:
    other = ScanSalt(bytes(range(1, 33)))
    assert run(PY, salt=other).payload.payload_hash != run(PY).payload.payload_hash


def test_the_hash_is_the_same_in_another_process() -> None:
    script = (
        "from codekavach.core.models import Language, PrivacyLevel\n"
        "from tests.unit.privacy.pseudonymise.test_engine import PY, run\n"
        "print(run(PY).payload.payload_hash)\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONHASHSEED": "random"},
        cwd=str(Path(__file__).resolve().parents[4]),
        timeout=120,
    )
    assert done.stdout.strip() == run(PY).payload.payload_hash


# --- the mapping batch ----------------------------------------------------------------------


def test_the_batch_maps_every_pseudonym_back_to_its_original() -> None:
    batch = run(PY).batch
    pairs = {e.pseudonym: e.original for e in batch.entries}
    assert batch.scan_id == SCAN_ID
    assert pairs["fn_1"] in {"get_account_balance", "accrue_interest"} or "fn_1" not in pairs
    assert "get_account_balance" in pairs.values()
    assert any(e.kind is PseudonymKind.FILE for e in batch.entries)
    assert all(e.scope == "handler.py" for e in batch.entries)


# --- provenance -----------------------------------------------------------------------------


def test_the_provenance_records_versions_counts_and_public_names() -> None:
    provenance = run(PY).provenance
    assert provenance.pseudonymise_version == PSEUDONYMISE_VERSION
    assert provenance.allowlist_version
    assert provenance.grammar_version
    assert provenance.level is L3
    assert "jsonify" in provenance.kept_public_names
    assert provenance.report.identifiers_renamed > 0
    assert provenance.report.comments_blanked == 4  # header, label, a note and a docstring
    assert "get_account_balance" not in repr(provenance)


def test_the_extra_allowlist_names_are_part_of_the_allowlist_version() -> None:
    plain = run(PY).provenance.allowlist_version
    extra = Pseudonymiser(allowlist_extra=("accrue_interest",))
    result = extra.process(PY, unredacted(PY, L3, extra), salt=SALT, level=L3, scan_id=SCAN_ID)
    assert result.provenance.allowlist_version != plain
    assert "accrue_interest" in result.payload.text.expose()


# --- fixed lines ----------------------------------------------------------------------------


def test_the_header_labels_and_stub_summaries_survive_the_blanking_of_comments() -> None:
    slice_ = slice_of(
        segment("service.py", 5, ["def accrue(account):", "    return bonus(account)"]),
        stubs=[
            stub(
                "bonus",
                "def bonus(rate): ...\n"
                "# returns value; param_0 flows to return; derived: syntactic",
                path="bonus.py",
                line=1,
            )
        ],
    )
    text = run(slice_).payload.text.expose().splitlines()
    assert text[0] == "# codekavach payload L3"
    assert text[1].startswith("# file_")
    assert text[-1] == "# returns value; param_0 flows to return; derived: syntactic"
    assert "bonus" not in "\n".join(text) and "accrue" not in "\n".join(text)


def test_a_redaction_that_changed_a_fixed_line_is_refused() -> None:
    layout = ENGINE.layout(PY, L3)
    broken = layout.text.replace("# codekavach payload L3", "# something else", 1)
    with pytest.raises(PseudonymError, match="fixed line"):
        run(PY, redaction=RedactionResult(text=broken))


def test_a_redaction_with_another_number_of_lines_is_refused() -> None:
    layout = ENGINE.layout(PY, L3)
    with pytest.raises(PseudonymError, match="lines"):
        run(PY, redaction=RedactionResult(text=layout.text + "extra = 1\n"))


# --- failing closed -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["classify_all", "attach_imports", "build_symbol_table", "check_against", "map_layout"],
)
def test_a_failing_step_surfaces_as_a_pseudonym_error_without_text(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    def explode(*args: object, **kwargs: object) -> object:
        raise ValueError("AccountLedgerSecret appears in this message")

    monkeypatch.setattr(engine_module, target, explode)
    with pytest.raises(PseudonymError) as caught:
        run(PY)
    assert "AccountLedgerSecret" not in str(caught.value)
    assert "ValueError" in str(caught.value)
    assert caught.value.__cause__ is None


def test_a_failing_renamer_surfaces_as_a_pseudonym_error(monkeypatch: pytest.MonkeyPatch) -> None:
    renamer = default_registry().get(Language.PYTHON)

    def explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(type(renamer), "rename", explode)
    with pytest.raises(PseudonymError, match="RuntimeError"):
        run(PY)


def test_a_slice_that_does_not_parse_aborts_instead_of_falling_back_to_the_original() -> None:
    broken = slice_of(segment("a.py", 1, ["def f(:", "    pass"]))
    with pytest.raises(PseudonymError):
        run(broken)


# --- the survival self-check ----------------------------------------------------------------


def test_the_self_check_fires_when_an_original_name_is_planted() -> None:
    text = run(PY).payload.text.expose()
    assignments = ((PseudonymKind.FN, "accrue_interest", "fn_9"),)
    _check_survival(text, assignments, frozenset())  # not in the text: fine
    with pytest.raises(PseudonymError, match="survives"):
        _check_survival(text + "\naccrue_interest(row)\n", assignments, frozenset())


def test_the_self_check_allows_a_public_name_and_a_key_beside_its_own_token() -> None:
    assignments = ((PseudonymKind.VAR, "accountId", "var_2"),)
    _check_survival("f({ accountId: var_2 })", assignments, frozenset())
    with pytest.raises(PseudonymError):
        _check_survival("f({ accountId: var_3 })", assignments, frozenset())
    with pytest.raises(PseudonymError):
        _check_survival("f(accountId)", assignments, frozenset())
    _check_survival("f(accountId)", assignments, frozenset({"accountId"}))
    _check_survival("f(abc)", ((PseudonymKind.VAR, "abc", "var_1"),), frozenset())  # too short


def test_the_self_check_looks_for_a_whole_path_too() -> None:
    assignments = ((PseudonymKind.FILE, "billing/engine.py", "file_1"),)
    with pytest.raises(PseudonymError):
        _check_survival("x = 'billing/engine.py'", assignments, frozenset())


def test_a_renamer_that_leaves_a_name_makes_the_whole_apply_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renamer = default_registry().get(Language.PYTHON)
    real = type(renamer).rename

    def leaky(self: object, source: object, plan: object) -> str:
        return real(self, source, plan) + "\nleak = get_account_balance\n"  # type: ignore[arg-type]

    monkeypatch.setattr(type(renamer), "rename", leaky)
    with pytest.raises(PseudonymError):
        run(PY)
