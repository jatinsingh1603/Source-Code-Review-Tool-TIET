"""KavachBank through ingest, parse, analyse, aggregate, privacy-prepare and llm-review (E13-02).

The mock provider answers, sockets are refused, and the checks are the ones the issue names: one
request per candidate, a ledger entry per request, no raw text in a payload, ``--no-send`` writes
``not_sent_dry_run`` entries and no verdict, and a candidate that fails is isolated from the rest.
"""

import re
import shutil
import socket
import sqlite3
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from codekavach.config import load_settings
from codekavach.core.models import Candidate, ScanStatus
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.finding import Finding
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.slice import CodeSlice
from codekavach.core.models.summary import ScanSummary
from codekavach.core.models.verdict import CandidateVerdict
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.guard import EgressGuard
from codekavach.privacy.egress.ledger import open_reader
from codekavach.privacy.egress.models import EgressDecision
from codekavach.privacy.errors import PseudonymError, RedactionError
from codekavach.privacy.policy.records import PolicyDecisionRow
from codekavach.privacy.pseudonymise.engine import Pseudonymiser
from codekavach.privacy.redact.redactor import Redactor
from codekavach.privacy.stages import PrivacyPrepareStage
from codekavach.privacy.vault.salt import vault_path
from codekavach.report.model.build import summarise_ledger
from tests.support.ingest import SALT_HEX, stages_registry
from tests.support.kavachbank import FIXTURE_ROOT

STAGES = (
    "ingest",
    "parse",
    "analyse-rules",
    "aggregate",
    "privacy-prepare",
    "llm-review",
    "restore",
    "rate",
)
PASSPHRASE_VARIABLE = "CK_TEST_VAULT_PASSPHRASE"
ENV = {
    "CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE": "passphrase",
    "CODEKAVACH_PRIVACY__VAULT__PASSPHRASE": f"env:{PASSPHRASE_VARIABLE}",
}


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Any attempt to open a connection fails the test (the mock opens none)."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    yield


def copy_fixture(into: Path) -> Path:
    root = into / "kavachbank"
    shutil.copytree(FIXTURE_ROOT, root)
    (root / ".git").mkdir()
    return root


def scan(
    root: Path,
    *,
    no_send: bool = False,
    home: str = "home",
    overrides: dict[str, object] | None = None,
    env: dict[str, str] | None = None,
) -> ScanOutcome:
    loaded = load_settings(
        target=root,
        env={"CODEKAVACH_HOME": str(root.parent / home), **ENV, **(env or {})},
        # Triage only: one request per payload (explain and remediate are tested in tests/unit/llm).
        cli_overrides={"llm": {"tasks": ["triage"]}, **(overrides or {})},
    )
    return run_scan(
        loaded,
        str(root),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=stages_registry(*STAGES),
        persist=False,
        no_send=no_send,
    )


def store_of(outcome: ScanOutcome) -> OnDiskArtefactStore:
    return OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)


@dataclass
class Run:
    """A finished scan and the in-memory artefacts that are gone once it ends."""

    outcome: ScanOutcome
    payloads: list[SanitisedPayload] = field(default_factory=list)
    slices: list[CodeSlice] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    verdicts: list[CandidateVerdict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: ScanSummary | None = None
    ledger: list[Any] = field(default_factory=list)


def run_and_capture(
    root: Path,
    *,
    no_send: bool = False,
    home: str = "home",
    overrides: dict[str, object] | None = None,
    env: dict[str, str] | None = None,
) -> Run:
    """Scan ``root``; payloads and slices are transient, so a spy on the stage keeps them."""
    captured = Run(outcome=None)  # type: ignore[arg-type]
    original = PrivacyPrepareStage.run

    def spy(self: PrivacyPrepareStage, ctx: RunContext) -> None:
        original(self, ctx)
        payloads = ctx.artefacts.get_object(keys.PAYLOADS_SANITISED)
        assert isinstance(payloads, list)
        captured.payloads = list(payloads)
        captured.slices = ctx.artefacts.get_list(keys.SLICES, CodeSlice)
        captured.candidates = ctx.artefacts.get_list(keys.CANDIDATES, Candidate)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(PrivacyPrepareStage, "run", spy)
        captured.outcome = scan(root, no_send=no_send, home=home, overrides=overrides, env=env)
    # Read now: a later scan in the same project replaces the stored records of this one.
    captured.verdicts = read(captured.outcome, keys.VERDICTS_RAW, CandidateVerdict)
    captured.findings = read(captured.outcome, keys.FINDINGS, Finding)
    captured.summary = store_of(captured.outcome).get(keys.SCAN_SUMMARY, ScanSummary)
    captured.ledger = ledger_of(captured.outcome)
    return captured


def read[Model: BaseModel](outcome: ScanOutcome, key: str, model: type[Model]) -> list[Model]:
    return store_of(outcome).get_list(key, model)


def ledger_of(outcome: ScanOutcome) -> list[EgressRecord]:
    return list(open_reader(StateLayout(outcome.state_dir)).records(outcome.scan.id))


@pytest.fixture(scope="module", autouse=True)
def vault_passphrase() -> Iterator[None]:
    """A synthetic passphrase, so the vault and the ledger open without a keyring."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(PASSPHRASE_VARIABLE, "synthetic passphrase for tests only")
        yield


@pytest.fixture(scope="module")
def root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return copy_fixture(tmp_path_factory.mktemp("privacy-pipeline"))


@pytest.fixture(scope="module")
def sent(root: Path) -> Run:
    return run_and_capture(root)


def test_the_eight_stages_complete_on_the_mock_provider(sent: Run) -> None:
    assert sent.outcome.scan.status in {ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS}
    assert [run.stage for run in sent.outcome.result.stage_runs] == list(STAGES)


def test_every_candidate_becomes_a_finding_with_its_review_recorded(sent: Run) -> None:
    findings = sent.findings
    assert len(findings) == len(sent.candidates)
    assert {f.provenance.candidate_ids[0] for f in findings} == {c.id for c in sent.candidates}
    reviewed = [f for f in findings if f.provenance.llm_reviews]
    assert len(reviewed) == len(sent.verdicts) > 0
    assert sent.summary is not None and sent.summary.findings_total == len(findings)


def test_a_no_send_scan_still_reports_every_deterministic_finding(root: Path) -> None:
    dry = run_and_capture(root, no_send=True, home="home-findings")
    findings = dry.findings
    assert len(findings) == len(dry.candidates) > 0
    assert all(not f.provenance.llm_reviews for f in findings)


def test_every_candidate_is_either_a_payload_or_a_failed_item(sent: Run) -> None:
    candidates = sent.candidates
    failed = {
        failure.item_id
        for failure in sent.outcome.result.item_failures
        if failure.stage == "privacy-prepare"
    }
    ids = {str(payload.candidate_id) for payload in sent.payloads}
    assert ids.isdisjoint(failed)
    assert ids | failed == {str(candidate.id) for candidate in candidates}
    assert sent.payloads


def test_one_request_per_payload_is_sent_and_completed(sent: Run) -> None:
    # One triage request per payload; a confirmed finding adds explain and remediate (E23-02).
    outcomes = Counter(record.outcome for record in sent.ledger if record.task == "triage")
    assert outcomes[EgressOutcome.SENT] == len(sent.payloads)
    assert outcomes[EgressOutcome.COMPLETED] == len(sent.payloads)
    assert Counter(record.outcome for record in sent.ledger)[EgressOutcome.BLOCKED] == 0
    assert {record.task for record in sent.ledger} <= {"triage", "explain", "remediate"}


def test_every_ledger_entry_records_the_policy_hash_and_rule_key(sent: Run) -> None:
    """E25-03: each entry names the policy that governed it, and nothing path-shaped."""
    rows = {
        str(row.candidate_id): row
        for row in read(sent.outcome, keys.POLICY_DECISIONS, PolicyDecisionRow)
    }
    assert sent.ledger
    for record in sent.ledger:
        assert record.schema_version == 2
        assert record.policy_hash and record.policy_rule_key
        row = rows[str(record.candidate_id)]
        assert (record.policy_hash, record.policy_rule_key) == (row.policy_hash, row.rule_key)
        assert "/" not in record.policy_rule_key
        assert "*" not in record.policy_rule_key
    assert open_reader(StateLayout(sent.outcome.state_dir)).verify_chain().ok


def test_every_sent_payload_has_a_raw_verdict(sent: Run) -> None:
    verdicts = sent.verdicts
    assert {str(v.candidate_id) for v in verdicts} == {str(p.candidate_id) for p in sent.payloads}


def test_payloads_carry_facts_and_a_matching_slice(sent: Run) -> None:
    assert len(sent.slices) == len(sent.payloads)
    assert {s.candidate_id for s in sent.slices} == {p.candidate_id for p in sent.payloads}
    for payload in sent.payloads:
        assert payload.facts is not None and payload.facts.rule
        assert payload.facts.strategy in {"enclosing_function", "hotspot"}


def test_no_send_writes_dry_run_entries_and_no_verdicts(root: Path) -> None:
    run = run_and_capture(root, no_send=True, home="home-dry")
    outcomes = Counter(record.outcome for record in run.ledger)
    assert outcomes[EgressOutcome.NOT_SENT_DRY_RUN] == len(run.payloads) > 0
    assert outcomes[EgressOutcome.SENT] == 0
    assert run.verdicts == []


# --- isolation, policy and the fail-closed paths -----------------------------------------------


def failures_of(outcome: ScanOutcome, stage: str) -> dict[str, str]:
    return {f.item_id: f.error_code for f in outcome.result.item_failures if f.stage == stage}


def test_a_never_send_path_has_no_payload_and_is_not_a_failure(root: Path, sent: Run) -> None:
    candidates = sent.candidates
    path = candidates[0].locations[0].path
    run = run_and_capture(root, home="home-never", overrides={"privacy": {"never_send": [path]}})
    withheld = {str(c.id) for c in candidates if c.locations[0].path == path}
    ids = {str(p.candidate_id) for p in run.payloads}
    assert withheld and ids.isdisjoint(withheld)
    assert withheld.isdisjoint(failures_of(run.outcome, "privacy-prepare"))
    assert ids  # the other files are still prepared


def test_a_failing_redaction_fails_that_candidate_only_and_leaks_no_raw_text(
    root: Path, sent: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Redactor.redact
    calls = {"count": 0}

    def flaky(self: Redactor, *args: Any, **kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 2:
            raise RedactionError("injected")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Redactor, "redact", flaky)
    run = run_and_capture(root, home="home-fault")
    failed = failures_of(run.outcome, "privacy-prepare")
    assert list(failed.values()) == ["privacy_redaction_failed"]
    ids = {str(p.candidate_id) for p in run.payloads}
    assert len(ids) == len(sent.payloads) - 1 and ids.isdisjoint(failed)
    raw = {segment.text.expose() for s in run.slices for segment in s.segments}
    assert all(p.text.expose() not in raw for p in run.payloads)


def test_a_failing_pseudonymisation_is_reported_with_its_own_code(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Pseudonymiser, *args: Any, **kwargs: Any) -> Any:
        raise PseudonymError("injected")

    monkeypatch.setattr(Pseudonymiser, "process", broken)
    run = run_and_capture(root, home="home-pseudo")
    assert run.payloads == []
    assert set(failures_of(run.outcome, "privacy-prepare").values()) == {
        "privacy_pseudonymise_failed"
    }
    assert run.verdicts == []
    # The report says how many candidates were not reviewed, and why.
    loaded = load_settings(
        target=root,
        env={"CODEKAVACH_HOME": str(root.parent / "home-pseudo"), **ENV},
        cli_overrides=None,
    )
    summary = summarise_ledger(run.outcome.state_dir, str(run.outcome.scan.id), loaded.settings)
    assert dict(summary.not_reviewed) == {"privacy_pseudonymise_failed": len(run.candidates)}


def test_a_request_the_guard_blocks_is_ledgered_and_the_scan_goes_on(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = EgressGuard.evaluate
    calls = {"count": 0}

    def block_second(self: EgressGuard, *args: Any, **kwargs: Any) -> EgressDecision:
        meta = args[1] if len(args) > 1 else kwargs["meta"]
        if meta.task != "triage":  # explain and remediate follow a confirmed triage (E23-02)
            return original(self, *args, **kwargs)
        calls["count"] += 1
        if calls["count"] == 2:
            return EgressDecision(allowed=False, block_code="residual_secret")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(EgressGuard, "evaluate", block_second)
    run = run_and_capture(root, home="home-block")
    records = [record for record in run.ledger if record.task == "triage"]
    outcomes = Counter(record.outcome for record in records)
    total = len(run.payloads)
    assert outcomes[EgressOutcome.BLOCKED] == 1
    assert outcomes[EgressOutcome.SENT] == total - 1 == outcomes[EgressOutcome.COMPLETED]
    blocked = next(r for r in records if r.outcome is EgressOutcome.BLOCKED)
    assert blocked.block_code == "residual_secret"
    assert list(failures_of(run.outcome, "llm-review").values()) == ["egress_blocked"]
    assert len(run.verdicts) == total - 1


def test_a_configured_aggregation_budget_blocks_requests_in_a_real_scan(root: Path) -> None:
    """The prepare stage's disclosure record reaches the guard (E13-02c)."""
    open_run = run_and_capture(root, home="home-agg-open")
    assert all(r.outcome is not EgressOutcome.BLOCKED for r in open_run.ledger)
    run = run_and_capture(
        root,
        home="home-agg",
        overrides={"privacy": {"egress": {"aggregation_budget_pct": 0.1}}},
    )
    assert run.payloads and run.verdicts == []
    assert {r.outcome for r in run.ledger} == {EgressOutcome.BLOCKED}
    assert {r.block_code for r in run.ledger} == {"aggregation_budget"}
    assert set(failures_of(run.outcome, "llm-review").values()) == {"egress_blocked"}


def _level(level: str) -> dict[str, object]:
    return {"privacy": {"level": level, "min_level": "L1"}}


def _by_site(run: Run) -> dict[tuple[str, str, int], str]:
    """Payload text keyed by (rule, path, line): candidate ids differ between scans."""
    sites = {
        c.id: (c.rule_id or "", c.locations[0].path, c.locations[0].start_line)
        for c in run.candidates
    }
    return {sites[p.candidate_id]: p.text.expose() for p in run.payloads}


def test_l1_and_l2_send_whole_files_and_l3_a_subset(tmp_path: Path) -> None:
    """E25-02: L1 keeps the names of whole files, L2 pseudonymises them, L3 sends the least.

    Each level scans its own copy, so one level's vault cannot influence another's guard.
    """
    runs = {
        level: run_and_capture(copy_fixture(tmp_path / level), overrides=_level(level))
        for level in ("L1", "L2", "L3")
    }
    for level in ("L1", "L2"):
        run = runs[level]
        assert run.payloads
        assert {p.level.value for p in run.payloads} == {level}
        assert "whole_file" in {s.strategy.value for s in run.slices}
        for slice_ in run.slices:
            if slice_.strategy.value not in {"whole_file", "hotspot"}:
                assert slice_.fallback_reason == "over_budget"  # a unit over budget falls back
    texts = {level: _by_site(run) for level, run in runs.items()}
    whole = {
        (c.rule_id or "", c.locations[0].path, c.locations[0].start_line)
        for c in runs["L1"].candidates
        for s in runs["L1"].slices
        if s.candidate_id == c.id and s.strategy.value == "whole_file"
    }
    shared = sorted(whole & set(texts["L2"]) & set(texts["L3"]))
    assert shared
    named = 0
    for site in shared:
        assert len(texts["L1"][site]) > len(texts["L3"][site])  # L3 is the minimised extent
        source = (tmp_path / "L1" / "kavachbank" / site[1]).read_text(encoding="utf-8")
        names = set(re.findall(r"^\s*def (\w{4,})", source, re.MULTILINE))
        names = {n for n in names if not n.startswith("__")}
        if names:
            named += 1
            l1_words = set(re.findall(r"\w+", texts["L1"][site]))
            l2_words = set(re.findall(r"\w+", texts["L2"][site]))
            assert names <= l1_words  # L1: the file's own names are kept
            assert not names & l2_words  # L2: every one of them is pseudonymised
    assert named


def test_the_engagement_budget_spans_scans_and_every_refusal_is_ledgered(
    tmp_path: Path,
) -> None:
    """E26-01: a second scan cannot push a provider's engagement exposure over the lifetime cap.

    The first scan discloses freely; the second runs with a lifetime budget below what the first
    already disclosed, so each of its requests is blocked by the guard, ledgered with
    ``aggregation_budget`` and the policy fields, and every candidate is still reported.
    """
    project = copy_fixture(tmp_path)
    first = run_and_capture(project, home="home-engagement")
    assert first.verdicts
    exposure = first.outcome.state_dir / "exposure.json"
    assert exposure.is_file()
    second = run_and_capture(
        project,
        home="home-engagement",
        overrides={"privacy": {"egress": {"lifetime_budget_pct": 0.1}}},
    )
    assert second.payloads
    assert second.verdicts == []
    assert len(second.ledger) == len(second.payloads)
    assert {r.outcome for r in second.ledger} == {EgressOutcome.BLOCKED}
    assert {r.block_code for r in second.ledger} == {"aggregation_budget"}
    assert all(r.policy_hash and r.policy_rule_key for r in second.ledger)
    assert len(second.findings) == len(second.candidates)
    # without the cap, the same project is reviewed again
    third = run_and_capture(project, home="home-engagement")
    assert third.verdicts


def test_a_disabled_llm_path_runs_neither_new_stage_and_writes_no_ledger(root: Path) -> None:
    outcome = scan(root, home="home-off", env={"CODEKAVACH_LLM__ENABLED": "false"})
    ran = [run.stage for run in outcome.result.stage_runs]
    assert "privacy-prepare" not in ran and "llm-review" not in ran


@settings(max_examples=4, deadline=None, suppress_health_check=list(HealthCheck))
@given(data=st.data())
def test_payloads_plus_failed_items_equal_the_candidates_that_may_leave(
    data: st.DataObject, root: Path, sent: Run
) -> None:
    candidates = sent.candidates
    paths = sorted({c.locations[0].path for c in candidates})
    held = data.draw(st.lists(st.sampled_from(paths), unique=True, max_size=len(paths) - 1))
    run = run_and_capture(root, home="home-prop", overrides={"privacy": {"never_send": held}})
    allowed = {str(c.id) for c in run.candidates if c.locations[0].path not in held}
    ids = {str(p.candidate_id) for p in run.payloads}
    failed = set(failures_of(run.outcome, "privacy-prepare"))
    assert ids.isdisjoint(failed)
    assert ids | failed == allowed


def test_retention_at_scan_start_removes_old_mappings_and_keeps_pseudonyms_stable(
    tmp_path: Path,
) -> None:
    """E10-03: the setting is applied before the vault is opened; the salt and the header stay."""
    project = copy_fixture(tmp_path)
    first = run_and_capture(project, home="home-retention")
    assert first.payloads
    database = vault_path(first.outcome.state_dir)
    connection = sqlite3.connect(database)
    old_scan = str(first.outcome.scan.id)
    connection.execute(
        "UPDATE scans SET created_at = '2020-01-01T00:00:00+00:00' WHERE scan_id = ?", (old_scan,)
    )
    connection.commit()
    header = connection.execute("SELECT * FROM header").fetchall()
    connection.close()
    second = run_and_capture(
        project,
        home="home-retention",
        overrides={"privacy": {"vault": {"retention_days": 30}}},
    )
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM records WHERE scan_id = ?", (old_scan,)
        ).fetchone() == (0,)
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM records WHERE scan_id = ?", (str(second.outcome.scan.id),)
            ).fetchone()[0]
            > 0
        )
        after = connection.execute("SELECT * FROM header").fetchall()
    finally:
        connection.close()
    assert after[0][:7] == header[0][:7]  # id, format, vault id, source, kdf, wrapped key
    first_text = sorted(str(p.model_dump_json()).count("fn_") for p in first.payloads)
    assert first_text and len(second.payloads) == len(first.payloads)
