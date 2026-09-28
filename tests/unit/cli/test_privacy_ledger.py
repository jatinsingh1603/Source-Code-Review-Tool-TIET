import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.cli.ledger import VerifyContext, chain_step
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.text import SanitisedText
from tests.support.cli import CliResult
from tests.support.factories import (
    FIXED_NOW,
    SCAN_ID,
    VECTOR_PAYLOAD_TEXT,
    make_egress_chain,
)
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden"
FIELDS = set(EgressRecord.model_fields)


@dataclass
class FakeReader:
    chain: list[EgressRecord]
    texts: dict[str, SanitisedText] = field(default_factory=dict)
    broken: set[str] = field(default_factory=set)

    def records(self, scan_id: str | None) -> Iterator[EgressRecord]:
        for record in self.chain:
            if scan_id is None or record.scan_id == scan_id:
                yield record

    def payload_text(self, payload_hash: str) -> SanitisedText | None:
        if payload_hash in self.broken:
            raise OSError("key unavailable")
        return self.texts.get(payload_hash)


def golden_reader(chain: list[EgressRecord] | None = None) -> FakeReader:
    records = chain if chain is not None else make_egress_chain(3)
    texts = {record.payload_hash: SanitisedText(VECTOR_PAYLOAD_TEXT) for record in records}
    return FakeReader(records, texts)


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    (project_dir / ".codekavach" / "scans" / SCAN_ID).mkdir(parents=True)
    return project_dir


@pytest.fixture
def reader(monkeypatch: pytest.MonkeyPatch) -> FakeReader:
    fake = golden_reader()
    fake_backend(monkeypatch, "codekavach.privacy.egress.ledger.open_reader", lambda layout: fake)
    return fake


def ledger(cli: Cli, project: Path, *args: str) -> CliResult:
    return cli(["privacy", "ledger", *args[:1], str(project), *args[1:]])


def test_verify_intact(cli: Cli, project: Path, reader: FakeReader) -> None:
    result = ledger(cli, project, "verify")
    assert result.exit_code == 0, result.stderr
    assert "chain intact: 3 records" in result.stdout
    assert "payloads: 1 checked, 0 mismatches" in result.stdout
    data = ledger(cli, project, "verify", "--json").json["data"]
    assert data["chain"] == {"ok": True, "first_bad_seq": None, "reason": None}
    assert (data["records"], data["payloads_checked"]) == (3, 1)


def test_show_json_fields(cli: Cli, project: Path, reader: FakeReader) -> None:
    data = ledger(cli, project, "show", "--json").json["data"]
    assert (data["total"], data["shown"]) == (3, 3)
    assert all(set(record) == FIELDS for record in data["records"])


def tampered(index: int, **update: Any) -> list[EgressRecord]:
    chain = make_egress_chain(3)
    chain[index] = chain[index].model_copy(update=update)
    return chain


@pytest.mark.parametrize(
    ("chain", "seq", "reason"),
    [
        (tampered(1, payload_hash="f" * 64), 2, "entry_hash_mismatch"),
        (tampered(1, prev_hash="e" * 64), 2, "prev_hash_mismatch"),
        (tampered(2, entry_hash="d" * 64), 3, "entry_hash_mismatch"),
        (tampered(0, prev_hash="1" * 64), 1, "genesis_mismatch"),
        ([make_egress_chain(3)[0], make_egress_chain(3)[2]], 2, "seq_gap"),
    ],
)
def test_chain_failures(  # noqa: PLR0917 - parametrised arguments
    cli: Cli,
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    chain: list[EgressRecord],
    seq: int,
    reason: str,
) -> None:
    fake = golden_reader(chain)
    fake_backend(monkeypatch, "codekavach.privacy.egress.ledger.open_reader", lambda layout: fake)
    result = ledger(cli, project, "verify", "--json")
    assert result.exit_code == 3
    assert result.json["data"]["chain"] == {"ok": False, "first_bad_seq": seq, "reason": reason}
    assert result.json["errors"][0]["code"] == "ledger_chain_broken"
    human = ledger(cli, project, "verify")
    assert f"ledger integrity check failed at seq {seq} ({reason})" in human.stderr


def test_ref_seq_invalid(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    chain = make_egress_chain(2)
    follow_up = EgressRecord.seal(
        prev=chain[-1],
        timestamp=FIXED_NOW + timedelta(seconds=5),
        scan_id=SCAN_ID,
        candidate_id=None,
        provider="mock",
        model="mock-1",
        task="triage",
        level=PrivacyLevel.L3,
        payload_hash="a" * 64,
        token_counts=TokenCounts(prompt=1),
        outcome=EgressOutcome.COMPLETED,
        ref_seq=1,
    )
    fake = golden_reader([*chain, follow_up])
    fake_backend(monkeypatch, "codekavach.privacy.egress.ledger.open_reader", lambda layout: fake)
    result = ledger(cli, project, "verify", "--json")
    assert result.json["data"]["chain"]["reason"] == "ref_seq_invalid"


def test_payload_mismatch(cli: Cli, project: Path, reader: FakeReader) -> None:
    for key in reader.texts:
        reader.texts[key] = SanitisedText("altered after recording\n")
    result = ledger(cli, project, "verify", "--json")
    assert result.exit_code == 3
    assert result.json["errors"][0]["code"] == "ledger_payload_mismatch"
    assert len(result.json["data"]["payloads"]["mismatched"]) == 1


def test_payload_missing_and_unreadable(cli: Cli, project: Path, reader: FakeReader) -> None:
    reader.texts.clear()
    warned = ledger(cli, project, "verify")
    assert warned.exit_code == 0
    assert "warning[payload_missing]" in warned.stderr
    strict = ledger(cli, project, "verify", "--require-payloads")
    assert strict.exit_code == 3
    reader.broken.add(reader.chain[0].payload_hash)
    assert "warning[payload_unreadable]" in ledger(cli, project, "verify").stderr


def test_empty_ledger(cli: Cli, project: Path, reader: FakeReader) -> None:
    reader.chain.clear()
    show = ledger(cli, project, "show")
    assert (show.exit_code, "ledger is empty" in show.stdout) == (0, True)
    verify = ledger(cli, project, "verify")
    assert (verify.exit_code, "0 records" in verify.stdout) == (0, True)


def test_no_backend(cli: Cli, project: Path) -> None:
    result = ledger(cli, project, "verify")
    assert result.exit_code == 2
    assert "error[backend_unavailable]" in result.stderr


def test_show_filters_and_footer(cli: Cli, project: Path, reader: FakeReader) -> None:
    human = ledger(cli, project, "show")
    assert "outcomes: sent 3" in human.stdout
    assert "providers: mock 3" in human.stdout
    assert "recorded but not transmitted (mock or replay provider)" in human.stdout
    assert "sent (no response recorded)" in human.stdout
    assert_matches_golden(human.stdout, GOLDEN / "ledger_show.txt")
    limited = ledger(cli, project, "show", "--limit", "1", "--json").json["data"]
    assert (limited["total"], limited["shown"]) == (3, 1)
    since = (FIXED_NOW + timedelta(seconds=1)).isoformat()
    later = ledger(cli, project, "show", "--since", since, "--json").json["data"]
    assert [record["seq"] for record in later["records"]] == [2, 3]
    blocked = ledger(cli, project, "show", "--outcome", "blocked", "--json").json["data"]
    assert blocked["records"] == []
    other_scan = ledger(cli, project, "show", "--scan", "scan_" + "1" * 26, "--json").json
    assert other_scan["data"]["records"] == []
    assert ledger(cli, project, "show", "--scan", "all", "--json").json["data"]["total"] == 3
    assert ledger(cli, project, "show", "--since", "yesterday").exit_code == 2


def test_no_payload_text_in_show(cli: Cli, project: Path, reader: FakeReader) -> None:
    for args in (("show",), ("show", "--json")):
        assert "fn_1" not in ledger(cli, project, *args).stdout


MUTABLE = ["payload_hash", "prev_hash", "entry_hash", "model", "provider", "timestamp", "seq"]


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=60, deadline=None)
@given(
    length=st.integers(1, 30),
    data=st.data(),
)
def test_property_single_mutation_is_detected(length: int, data: st.DataObject) -> None:
    chain = make_egress_chain(length)
    assert chain_step(VerifyContext(golden_reader(chain))).ok
    index = data.draw(st.integers(0, length - 1))
    name = data.draw(st.sampled_from(MUTABLE))
    original = chain[index]
    values = {
        "payload_hash": "f" * 64,
        "prev_hash": "e" * 64,
        "entry_hash": "d" * 64,
        "model": "other-model",
        "provider": "other",
        "timestamp": original.timestamp + timedelta(days=1),
        "seq": original.seq + 5,
    }
    chain[index] = original.model_copy(update={name: values[name]})
    result = chain_step(VerifyContext(golden_reader(chain)))
    assert not result.ok
    assert result.data["first_bad_seq"] <= original.seq


@pytest.mark.slow
def test_large_chain_is_fast() -> None:
    chain = make_egress_chain(100_000)
    started = time.perf_counter()
    assert chain_step(VerifyContext(golden_reader(chain))).ok
    assert time.perf_counter() - started < 30


def test_no_vault_or_restore_imports() -> None:
    code = (
        "import codekavach.cli.ledger, codekavach.cli.privacy, sys; "
        "bad = [m for m in sys.modules if m.startswith(('codekavach.privacy.vault', "
        "'codekavach.privacy.restore'))]; assert not bad, bad"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
