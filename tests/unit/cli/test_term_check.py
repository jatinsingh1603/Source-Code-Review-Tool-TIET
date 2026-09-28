import hashlib
import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.cli.errors import UsageError
from codekavach.cli.term_check import Term, TermHit, load_terms, search_payloads
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.text import SanitisedText
from tests.support.cli import CliResult
from tests.support.factories import FIXED_NOW, SCAN_ID
from tests.support.fakes import fake_backend

Cli = Callable[..., CliResult]
TERM = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
DOMAIN = "kavachbank-premium"
SENT_TEXT = f'key = "{TERM}"\nrate = premium\n'
BLOCKED_TEXT = f"tier = '{DOMAIN}'\n"
CLEAN_TEXT = "def fn_1(param_2):\n    return param_2\n"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def chain_for(entries: list[tuple[str, EgressOutcome]]) -> list[EgressRecord]:
    chain: list[EgressRecord] = []
    for index, (text, outcome) in enumerate(entries):
        chain.append(
            EgressRecord.seal(
                prev=chain[-1] if chain else None,
                timestamp=FIXED_NOW + timedelta(seconds=index),
                scan_id=SCAN_ID,
                candidate_id=None,
                provider="mock",
                model="mock-1",
                task="triage",
                level=PrivacyLevel.L3,
                payload_hash=sha(text),
                token_counts=TokenCounts(prompt=10),
                outcome=outcome,
                block_code="secret_found" if outcome is EgressOutcome.BLOCKED else None,
            )
        )
    return chain


@dataclass
class Reader:
    chain: list[EgressRecord]
    texts: dict[str, str]

    def records(self, scan_id: str | None) -> Iterator[EgressRecord]:
        return iter(self.chain)

    def payload_text(self, payload_hash: str) -> SanitisedText | None:
        text = self.texts.get(payload_hash)
        return None if text is None else SanitisedText(text)


def install(monkeypatch: pytest.MonkeyPatch, texts: list[tuple[str, EgressOutcome]]) -> Reader:
    reader = Reader(chain_for(texts), {sha(text): text for text, _ in texts})
    fake_backend(monkeypatch, "codekavach.privacy.egress.ledger.open_reader", lambda layout: reader)
    return reader


SENT = EgressOutcome.SENT
BLOCKED = EgressOutcome.BLOCKED


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


@pytest.fixture
def terms_file(tmp_path: Path) -> Path:
    path = tmp_path / "terms.txt"
    path.write_text(f"# planted values\n\n{TERM}\nabc\n  id  \n\\#tag\n{DOMAIN}\n{TERM}\n")
    return path


def verify(cli: Cli, project: Path, *args: str) -> CliResult:
    return cli(["privacy", "ledger", "verify", str(project), *args])


def test_load_terms(terms_file: Path) -> None:
    loaded = load_terms(terms_file)
    assert [(term.line, term.text) for term in loaded.terms] == [
        (3, TERM), (6, "#tag"), (7, DOMAIN),
    ]  # fmt: skip
    assert loaded.short_lines == (4, 5)


def test_crlf_and_odd_separators(tmp_path: Path) -> None:
    path = tmp_path / "t.txt"
    path.write_bytes(b"first-term\r\nsec\x0cond-term\r\nthird-term\n")
    assert [term.line for term in load_terms(path).terms] == [1, 2, 3]


def test_unreadable_terms_file(tmp_path: Path) -> None:
    path = tmp_path / "latin1.txt"
    path.write_bytes(b"caf\xe9-term\n")
    with pytest.raises(UsageError) as error:
        load_terms(path)
    assert error.value.code == "terms_file_unreadable"
    assert "byte offset 3" in error.value.message
    assert "caf" not in error.value.message


def test_search_rules() -> None:
    terms = [Term("t", 1, TERM), Term("t", 2, "a.*b"), Term("t", 3, "Premium")]
    payloads = [("h1", f"prefix{TERM}suffix"), ("h2", "x = 'a.*b'"), ("h3", "aXXb premium")]
    hits = search_payloads(terms, payloads, ignore_case=False)
    assert [(hit.line, hit.payload_hash) for hit in hits] == [(1, "h1"), (2, "h2")]
    folded = search_payloads(terms, payloads, ignore_case=True)
    assert (3, "h3") in [(hit.line, hit.payload_hash) for hit in folded]


def test_reprs_hide_terms() -> None:
    assert TERM not in repr(Term("t", 3, TERM))
    assert repr(Term("t", 3, TERM)) == "Term(line=3)"
    assert TERM not in repr(TermHit("t", 3, "ab" * 32))


@given(
    prefix=st.text("abcdefgh \n", max_size=30),
    suffix=st.text("abcdefgh \n", max_size=30),
    term=st.text("XYZ0123456789", min_size=4, max_size=40),
)
def test_property_inserted_terms_are_found(prefix: str, suffix: str, term: str) -> None:
    payload = [("h", prefix + term + suffix)]
    assert search_payloads([Term("t", 1, term)], payload, ignore_case=False)
    assert not search_payloads([Term("t", 1, term)], [("h", prefix + suffix)], ignore_case=False)


def test_failing_run_never_prints_the_term(
    cli: Cli, project: Path, terms_file: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    install(monkeypatch, [(SENT_TEXT, SENT), (CLEAN_TEXT, SENT), (SENT_TEXT, SENT)])
    caplog.set_level(logging.DEBUG)
    for extra in ((), ("-vv",), ("--debug",)):
        result = verify(cli, project, "--check-terms", str(terms_file), *extra)
        assert result.exit_code == 3
        assert "error[ledger_term_found]" in result.stderr
        assert f"{terms_file}:3 found in seq 1, 3" in result.stdout
        assert "terms: 3 checked, 2 skipped (too short), 1 occurrence(s)" in result.stdout
        assert "warning[terms_too_short]" in result.stderr
        for text in (result.stdout, result.stderr, caplog.text):
            assert TERM not in text
            assert DOMAIN not in text


def test_passing_run(
    cli: Cli, project: Path, terms_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, [(CLEAN_TEXT, SENT)])
    result = verify(cli, project, "--check-terms", str(terms_file))
    assert result.exit_code == 0
    assert "verbatim check only; structural leakage is measured by" in result.stdout


def test_ignore_case(
    cli: Cli, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, [(f"x = '{TERM.lower()}'\n", SENT)])
    path = tmp_path / "t.txt"
    path.write_text(f"{TERM}\n")
    assert verify(cli, project, "--check-terms", str(path)).exit_code == 0
    assert verify(cli, project, "--check-terms", str(path), "--ignore-case").exit_code == 3


def test_blocked_hits(
    cli: Cli, project: Path, terms_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, [(BLOCKED_TEXT, BLOCKED)])
    result = verify(cli, project, "--check-terms", str(terms_file))
    assert result.exit_code == 0
    assert "(blocked, not sent)" in result.stdout
    strict = verify(cli, project, "--check-terms", str(terms_file), "--include-blocked")
    assert strict.exit_code == 3


def test_two_files_and_json(
    cli: Cli, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, [(SENT_TEXT, SENT), (BLOCKED_TEXT, SENT)])
    first, second = tmp_path / "a.txt", tmp_path / "b.txt"
    first.write_text(f"{TERM}\n")
    second.write_text(f"# domain\n{DOMAIN}\n")
    result = verify(cli, project, "--check-terms", str(first), "--check-terms", str(second),
                    "--json")  # fmt: skip
    assert result.exit_code == 3
    hits = result.json["data"]["terms"]["hits"]
    assert all(set(hit) == {"terms_file", "line", "seq", "payload_hash"} for hit in hits)
    assert {(Path(hit["terms_file"]).name, hit["line"], tuple(hit["seq"])) for hit in hits} == {
        ("a.txt", 1, (1,)), ("b.txt", 2, (2,)),
    }  # fmt: skip
    assert TERM not in result.stdout


def test_chain_failure_code_is_kept(
    cli: Cli, project: Path, terms_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = install(monkeypatch, [(SENT_TEXT, SENT), (CLEAN_TEXT, SENT)])
    reader.chain[1] = reader.chain[1].model_copy(update={"entry_hash": "d" * 64})
    result = verify(cli, project, "--check-terms", str(terms_file), "--json")
    assert result.exit_code == 3
    assert result.json["errors"][0]["code"] == "ledger_chain_broken"
    assert "terms" in result.json["data"]


def test_missing_terms_file(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, [(CLEAN_TEXT, SENT)])
    result = verify(cli, project, "--check-terms", str(project / "nope.txt"))
    assert result.exit_code == 2
    assert "error[terms_file_unreadable]" in result.stderr


@pytest.mark.slow
def test_benchmark() -> None:
    terms = [Term("t", index, f"term-{index:06d}-x") for index in range(10_000)]
    payloads = [(f"h{index}", "y" * 4096) for index in range(5_000)]
    started = time.perf_counter()
    assert search_payloads(terms, payloads, ignore_case=False) == []
    assert time.perf_counter() - started < 10


KAVACHBANK_TERMS = (
    Path(__file__).resolve().parents[3] / "fixtures/kavachbank/ground-truth/terms.txt"
)


@pytest.mark.skipif(not KAVACHBANK_TERMS.exists(), reason="needs E13 and the M1 privacy stages")
def test_demo_terms(cli: Cli) -> None:
    kavachbank = KAVACHBANK_TERMS.parents[1]
    assert cli(["scan", str(kavachbank), "--profile", "demo"]).exit_code == 0
    assert verify(cli, kavachbank, "--check-terms", str(KAVACHBANK_TERMS)).exit_code == 0
