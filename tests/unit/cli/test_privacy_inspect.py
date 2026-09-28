import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from codekavach.cli.privacy import Entry, hash_matches, header, placeholder_counts
from codekavach.core.models import PrivacyLevel, Severity
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.ids import CandidateId
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.slice import CodeSlice
from codekavach.core.models.text import SanitisedText
from tests.support.cli import CliResult
from tests.support.factories import (
    CANDIDATE_ID,
    make_candidate,
    make_location,
    make_payload,
    make_slice,
)
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden"
SCAN_ID = "scan_01ARYZ6S410000000000000009"  # pragma: allowlist secret
SECOND = CandidateId("cand_01ARYZ6S410000000000000010")
ORIGINAL_MARKER = "find_by_owner"
SECRET_TEXT = 'key = "<SECRET:aws_access_key:1>"\nprint(var_1)\n'


@dataclass
class FakeSource:
    payload_list: list[SanitisedPayload]
    candidates: dict[str, Candidate]
    slices: dict[str, CodeSlice] = field(default_factory=dict)
    outcomes: dict[str, str] = field(default_factory=dict)
    never_send: list[str] = field(default_factory=list)

    def payloads(self, scan_id: str) -> Sequence[SanitisedPayload]:
        assert scan_id == SCAN_ID
        return self.payload_list

    def slice_for(self, candidate_id: str) -> CodeSlice | None:
        return self.slices.get(candidate_id)

    def candidate(self, candidate_id: str) -> Candidate | None:
        return self.candidates.get(candidate_id)

    def ledger_outcome(self, payload_hash: str) -> str | None:
        return self.outcomes.get(payload_hash)

    def never_send_candidates(self, scan_id: str) -> list[str]:
        return self.never_send


def second_pair() -> tuple[SanitisedPayload, Candidate]:
    payload = make_payload(candidate_id=SECOND, text=SanitisedText(SECRET_TEXT), line_map=())
    candidate = make_candidate(
        id=SECOND,
        engine_severity=Severity.MEDIUM,
        taint_path=None,
        locations=(make_location(path="src/bank/b.py", start_line=3, end_line=3),),
    )
    return payload, candidate


def default_source() -> FakeSource:
    first = make_payload()
    second, candidate = second_pair()
    return FakeSource(
        payload_list=[second, first],
        candidates={str(CANDIDATE_ID): make_candidate(), str(SECOND): candidate},
        slices={str(CANDIDATE_ID): make_slice()},
        outcomes={first.payload_hash: "recorded", second.payload_hash: "blocked:secret_found"},
    )


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    (project_dir / ".codekavach" / "scans" / SCAN_ID).mkdir(parents=True)
    return project_dir


@pytest.fixture
def source(monkeypatch: pytest.MonkeyPatch) -> FakeSource:
    fake = default_source()
    fake_backend(
        monkeypatch,
        "codekavach.privacy.inspect_source.open_payload_source",
        lambda layout, scan_id: fake,
    )
    return fake


def inspect(cli: Cli, project: Path, *args: str, **kwargs: object) -> CliResult:
    return cli(["privacy", "inspect", str(project), *args], **kwargs)


def test_header_and_placeholders() -> None:
    payload, candidate = second_pair()
    entry = Entry(payload, candidate, None, "blocked:secret_found", hash_ok=True)
    assert placeholder_counts(payload) == [
        {"kind": "SECRET", "subtype": "aws_access_key", "count": 1}
    ]
    first, second = header(entry, "mock")
    assert first.startswith(f"candidate {SECOND} rule python.sqli.string-concat CWE-89")
    assert "src/bank/b.py:3  level L3" in first
    assert f"payload {payload.payload_hash[:12]}" in second
    assert "placeholders SECRET:aws_access_key x1" in second
    assert second.endswith("ledger: blocked: secret_found")


def test_pairs_in_order_with_limit(cli: Cli, project: Path, source: FakeSource) -> None:
    result = inspect(cli, project)
    assert result.exit_code == 0, result.stderr
    first = result.stdout.index(f"candidate {CANDIDATE_ID}")
    second = result.stdout.index(f"candidate {SECOND}")
    assert first < second  # high severity before medium
    assert "Original (stays on this machine)" in result.stdout
    assert "recorded (mock provider: not transmitted)" in result.stdout
    limited = inspect(cli, project, "--limit", "1")
    assert f"candidate {SECOND}" not in limited.stdout
    assert "1 more payload(s); use --limit 0 to show all" in limited.stdout


def test_list_shows_no_code(cli: Cli, project: Path, source: FakeSource) -> None:
    result = inspect(cli, project, "--list")
    assert ORIGINAL_MARKER not in result.stdout
    assert "fn_2" not in result.stdout
    assert str(SECOND) in result.stdout


def test_layouts(cli: Cli, project: Path, source: FakeSource) -> None:
    wide = inspect(cli, project, "--candidate", str(CANDIDATE_ID), env={"COLUMNS": "160"})
    stacked = inspect(cli, project, "--candidate", str(CANDIDATE_ID))
    assert_matches_golden(wide.stdout, GOLDEN / "inspect_columns_160.txt")
    assert_matches_golden(stacked.stdout, GOLDEN / "inspect_stacked_100.txt")
    columns = inspect(cli, project, "--candidate", str(CANDIDATE_ID), "--layout", "columns",
                      env={"COLUMNS": "160"})  # fmt: skip
    assert columns.stdout == wide.stdout


def test_json_modes(cli: Cli, project: Path, source: FakeSource) -> None:
    plain = inspect(cli, project, "--json")
    assert ORIGINAL_MARKER not in plain.stdout
    payloads = plain.json["data"]["payloads"]
    assert all("payload_text" not in item for item in payloads)
    assert payloads[0]["segments"] == [
        {"path": "src/bank/accounts.py", "start_line": 86, "end_line": 89}
    ]
    full = inspect(cli, project, "--json", "--include-payload")
    assert ORIGINAL_MARKER not in full.stdout
    texts = {item["candidate_id"]: item["payload_text"] for item in full.json["data"]["payloads"]}
    assert texts[str(SECOND)] == SECRET_TEXT


def test_filters(cli: Cli, project: Path, source: FakeSource) -> None:
    by_candidate = inspect(cli, project, "--candidate", str(SECOND), "--json")
    assert [p["candidate_id"] for p in by_candidate.json["data"]["payloads"]] == [str(SECOND)]
    by_file = inspect(cli, project, "--file", "src/bank/acc*", "--json")
    assert [p["candidate_id"] for p in by_file.json["data"]["payloads"]] == [str(CANDIDATE_ID)]


def test_hash_mismatch(cli: Cli, project: Path, source: FakeSource) -> None:
    tampered = source.payload_list[1].model_copy(update={"text": SanitisedText("changed\n")})
    assert not hash_matches(tampered)
    source.payload_list[1] = tampered
    result = inspect(cli, project)
    assert result.exit_code == 3
    assert "error[payload_hash_mismatch]" in result.stderr
    assert "TAMPEREDTEXT" not in result.stdout


def test_missing_original_never_send_l4_l0(cli: Cli, project: Path, source: FakeSource) -> None:
    source.slices.clear()
    source.never_send.append("cand_01ARYZ6S410000000000000099")
    l4 = source.payload_list[0].model_copy(update={"level": PrivacyLevel.L4})
    l0 = source.payload_list[1].model_copy(update={"level": PrivacyLevel.L0})
    source.payload_list[:] = [l4, l0]
    result = inspect(cli, project)
    assert "original not available (file changed or removed since the scan)" in result.stdout
    assert "no payload: policy never-send" in result.stdout
    assert "L4: abstract facts, no code" in result.stdout
    assert "no payload: level L0" in result.stdout


def test_no_scan_and_no_backend(cli: Cli, project_dir: Path) -> None:
    (project_dir / ".git").mkdir()
    result = cli(["privacy", "inspect", str(project_dir)])
    assert result.exit_code == 2
    assert "error[scan_not_found]" in result.stderr
    (project_dir / ".codekavach" / "scans" / SCAN_ID).mkdir(parents=True)
    result = cli(["privacy", "inspect", str(project_dir)])
    assert result.exit_code == 2
    assert "error[backend_unavailable]" in result.stderr


def test_raw_code_is_exposed_only_by_privacy_inspect() -> None:
    cli_dir = Path(__file__).resolve().parents[3] / "src" / "codekavach" / "cli"
    users = {
        path.name
        for path in cli_dir.glob("*.py")
        if re.search(r"segment\.text\.expose\(|RawCode\(.*\)\.expose\(", path.read_text("utf-8"))
    }
    assert users == {"privacy.py"}


def test_json_is_valid(cli: Cli, project: Path, source: FakeSource) -> None:
    json.loads(inspect(cli, project, "--json").stdout)
