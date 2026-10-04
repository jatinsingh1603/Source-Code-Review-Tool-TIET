"""The assembled pipeline, driven end to end with the fake default pipeline (E04-31).

Real entry-point discovery, plan building, concurrent execution, failure policy, caching,
manifest, checkpoint and persistence together. When a scan misbehaves, this suite tells whether
the pipeline or a stage is at fault. The scenarios are numbered as in the issue.
"""

import json
import os
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest

from codekavach.config import LoadedConfig, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import keys
from codekavach.core.pipeline import orchestrator as orchestrator_module
from codekavach.core.pipeline.events import NullEventBus
from codekavach.core.pipeline.manifest import ScanManifest
from codekavach.core.pipeline.plan import PlanError
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.resume import load_checkpoint
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import StageCategory, describe_stage
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.repositories import db_probe
from tests.support import fake_pipeline
from tests.support.fake_pipeline import (
    FAKE_REPO_FILES,
    FakeCandidate,
    fake_registry,
    fake_stages,
    install_fake_pipeline,
    snapshot_digests,
    write_fake_repo,
)
from tests.support.pipeline import CollectingBus

SALT_HEX = "6c" * 32  # pragma: allowlist secret
OTHER_SALT_HEX = "d4" * 32  # pragma: allowlist secret
ANALYSES = {"analyse-rules", "analyse-taint", "analyse-secrets"}
EGRESS_PATH = {"privacy-prepare", "llm-review", "restore"}
TIMED = {keys.SCAN_RECORD, keys.MANIFEST}
UPSTREAM_OF_PRIVACY = (
    keys.FILES,
    keys.LANGUAGES,
    keys.SYMBOLS,
    keys.CALL_GRAPH,
    keys.CANDIDATES_RAW,
    keys.CANDIDATES,
)
CANDIDATE_COUNT = len(ANALYSES) * len(FAKE_REPO_FILES)


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[Path]:
    fake_pipeline.reset_fake_pipeline()
    yield write_fake_repo(tmp_path / "repo")
    fake_pipeline.reset_fake_pipeline()


def loaded(repo: Path) -> LoadedConfig:
    return load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})


def scan(repo: Path, *, salt: str = SALT_HEX, **options: object) -> ScanOutcome:
    return run_scan(
        loaded(repo),
        str(repo),
        salt=ScanSalt.from_hex(salt),
        registry=fake_registry(),
        **options,  # type: ignore[arg-type]
    )


def store_of(outcome: ScanOutcome) -> OnDiskArtefactStore:
    return OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)


def digests(outcome: ScanOutcome) -> dict[str, str]:
    """Digests of every persisted key except the two that contain times."""
    found = snapshot_digests(store_of(outcome))
    return {key: digest for key, digest in found.items() if key not in TIMED}


def outcomes(outcome: ScanOutcome) -> dict[str, StageOutcome]:
    return {run.stage: run.outcome for run in outcome.result.stage_runs}


def manifest_of(outcome: ScanOutcome) -> ScanManifest:
    assert outcome.manifest_path is not None
    return ScanManifest.model_validate_json(outcome.manifest_path.read_text(encoding="utf-8"))


def configure(repo: Path, text: str) -> None:
    (repo / "codekavach.toml").write_text(text, encoding="utf-8")


# The contract of the fake stages.


def test_fake_stages_match_the_contract_table() -> None:
    """The ADR-0007 contract table, written with the constants of ``keys``."""
    k = keys
    none: set[str] = set()
    analyse = (StageCategory.ANALYSE, {k.FILES, k.SYMBOLS}, none, {k.CANDIDATES_RAW})
    table: dict[str, tuple[StageCategory, set[str], set[str], set[str]]] = {
        "ingest": (StageCategory.INGEST, {k.TARGET}, set(), {k.FILES, k.LANGUAGES}),
        "parse": (
            StageCategory.PARSE,
            {k.FILES, k.LANGUAGES},
            set(),
            {k.AST, k.SYMBOLS, k.CALL_GRAPH},
        ),
        "analyse-rules": analyse,
        "analyse-taint": analyse,
        "analyse-secrets": analyse,
        "aggregate": (StageCategory.AGGREGATE, {k.CANDIDATES_RAW}, set(), {k.CANDIDATES}),
        "privacy-prepare": (
            StageCategory.PRIVACY,
            {k.CANDIDATES, k.FILES},
            {k.AST, k.SYMBOLS, k.CALL_GRAPH},
            {k.PAYLOADS_SANITISED},
        ),
        "llm-review": (StageCategory.LLM, {k.PAYLOADS_SANITISED}, set(), {k.VERDICTS_RAW}),
        "restore": (StageCategory.RESTORE, {k.VERDICTS_RAW}, set(), {k.VERDICTS_RESTORED}),
        "rate": (
            StageCategory.RATE,
            {k.CANDIDATES},
            {k.VERDICTS_RESTORED},
            {k.FINDINGS, k.SCAN_SUMMARY},
        ),
        "report": (
            StageCategory.REPORT,
            {k.FINDINGS},
            {k.SCAN_SUMMARY, k.ITEM_FAILURES},
            {k.REPORT_OUTPUTS},
        ),
        "sync": (StageCategory.SYNC, {k.FINDINGS}, set(), {k.SYNC_RESULT}),
    }
    stages = fake_stages()
    assert set(stages) == set(table)
    for name, (category, requires, optional, provides) in table.items():
        info = describe_stage(stages[name]())
        assert info.name == name
        assert (info.category, set(info.requires)) == (category, requires), name
        assert (set(info.optional_requires), set(info.provides)) == (optional, provides), name
    assert describe_stage(stages["parse"]()).transient_provides == {k.AST}
    default_names = {"analyse" if name in ANALYSES else name for name in stages}
    assert default_names == set(k.DEFAULT_STAGE_ORDER)


# 1. Happy path.


def test_happy_path(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site)
    outcome = scan(repo)
    assert outcome.result.status is ScanStatus.COMPLETED
    assert outcomes(outcome) == dict.fromkeys(fake_stages(), StageOutcome.SUCCEEDED)
    assert any(set(wave) >= ANALYSES for wave in outcome.result.waves)
    store = store_of(outcome)
    assert store.has(keys.SCAN_RECORD)
    assert not store.has(keys.AST)  # transient
    assert len(store.get_parts(keys.CANDIDATES_RAW, FakeCandidate)) == len(ANALYSES)
    findings = store.get_json(keys.FINDINGS)
    assert isinstance(findings, list)
    assert len(findings) == CANDIDATE_COUNT
    assert store.get_json(keys.REPORT_OUTPUTS) == {"findings": CANDIDATE_COUNT, "item_failures": 0}
    assert fake_pipeline.SEEN_PAYLOADS == [CANDIDATE_COUNT]
    assert [manifest.status for manifest in fake_pipeline.PARTIAL_MANIFESTS] == ["running"]
    layout = StateLayout(outcome.state_dir)
    manifest = manifest_of(outcome)
    assert manifest.status == "completed"
    assert manifest.order == list(outcome.result.order)
    assert layout.snapshot_path(outcome.scan.id).is_file()
    checkpoint = load_checkpoint(layout, outcome.scan.id)
    assert checkpoint is not None
    assert checkpoint.status == "completed"
    assert db_probe(layout)["rows"] == {
        "projects": 1,
        "scans": 1,
        "stage_runs": len(fake_stages()),
        "findings": 0,  # the fake findings are JSON, not E02 models
    }


# 2. Determinism.


def test_concurrent_runs_are_deterministic(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site)
    configure(repo, "[scan]\njobs = 8\n")
    runs = []
    for index in range(10):
        # Make the analysis stages finish in a different order from run to run.
        fake_pipeline.DELAYS.clear()
        fake_pipeline.DELAYS[sorted(ANALYSES)[index % 3]] = 0.05
        runs.append(digests(scan(repo, use_cache=False, persist=False)))
    fake_pipeline.DELAYS.clear()
    assert all(run == runs[0] for run in runs)
    assert {keys.CANDIDATES, keys.PAYLOADS_SANITISED, keys.FINDINGS} <= set(runs[0])
    other = digests(scan(repo, salt=OTHER_SALT_HEX, use_cache=False, persist=False))
    assert other[keys.PAYLOADS_SANITISED] != runs[0][keys.PAYLOADS_SANITISED]
    for key in UPSTREAM_OF_PRIVACY:
        assert other[key] == runs[0][key], key


# 3. Events are advisory.


def test_events_are_advisory(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site)
    with_events = digests(scan(repo, use_cache=False, persist=False, bus=CollectingBus()))
    without = digests(scan(repo, use_cache=False, persist=False, bus=NullEventBus()))
    assert without == with_events


# 4. LLM disabled.


def test_llm_disabled_excludes_the_egress_path(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site)
    configure(repo, "[llm]\nenabled = false\n")
    outcome = scan(repo, persist=False)
    assert outcome.result.status is ScanStatus.COMPLETED
    assert {(item.name, item.reason_code) for item in outcome.result.excluded} == {
        (name, "llm_disabled") for name in EGRESS_PATH
    }
    assert not EGRESS_PATH & set(fake_pipeline.CALLS)
    store = store_of(outcome)
    assert not store.has(keys.PAYLOADS_SANITISED)
    findings = store.get_json(keys.FINDINGS)
    assert isinstance(findings, list)
    assert len(findings) == CANDIDATE_COUNT


# 5. Fail closed, stage level.


@pytest.mark.privacy
def test_failing_privacy_stage_locks_egress(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site, variant="privacy-raises")
    outcome = scan(repo, persist=False)
    assert outcome.result.status is ScanStatus.COMPLETED_WITH_ERRORS
    assert fake_pipeline.CALLS["privacy-prepare"] == 1
    assert fake_pipeline.CALLS["llm-review"] == 0
    assert fake_pipeline.SEEN_PAYLOADS == []
    store = store_of(outcome)
    assert not store.has(keys.PAYLOADS_SANITISED)
    assert not store.has(keys.VERDICTS_RAW)
    assert store.has(keys.FINDINGS)
    assert outcome.result.egress_locked
    assert manifest_of(outcome).counters.egress_locked
    skipped = outcome.result.run_of("llm-review")
    assert skipped is not None
    assert skipped.outcome is StageOutcome.SKIPPED


@pytest.mark.privacy
def test_failing_uncategorised_stage_locks_egress(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site, variant="uncategorised-stage-fails")
    outcome = scan(repo, persist=False)
    assert outcome.result.status is ScanStatus.COMPLETED_WITH_ERRORS
    assert outcome.result.failed_stages() == ("enrich",)
    assert outcome.result.egress_locked
    assert fake_pipeline.CALLS["privacy-prepare"] == 0
    assert fake_pipeline.CALLS["llm-review"] == 0
    store = store_of(outcome)
    assert not store.has(keys.PAYLOADS_SANITISED)
    assert store.has(keys.FINDINGS)


# 6. Fail closed, item level.


@pytest.mark.privacy
def test_failed_item_gets_no_payload(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site, variant="privacy-item-failures")
    outcome = scan(repo, persist=False)
    assert outcome.result.status is ScanStatus.COMPLETED
    failures = outcome.result.item_failures
    assert [(failure.stage, failure.error_code) for failure in failures] == [
        ("privacy-prepare", fake_pipeline.ITEM_ERROR_CODE)
    ]
    assert fake_pipeline.SEEN_PAYLOADS == [CANDIDATE_COUNT - 1]
    store = store_of(outcome)
    payloads = store.get_json(keys.PAYLOADS_SANITISED)
    assert isinstance(payloads, list)
    assert failures[0].item_id not in json.dumps(payloads)
    findings = store.get_json(keys.FINDINGS)
    assert isinstance(findings, list)
    assert len(findings) == CANDIDATE_COUNT  # still reported from deterministic evidence
    assert store.get_json(keys.REPORT_OUTPUTS) == {"findings": CANDIDATE_COUNT, "item_failures": 1}
    assert manifest_of(outcome).counters.item_failures == 1


# 7. Degrade.


def test_timed_out_engine_degrades(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_pipeline(fake_site, variant="engine-times-out")
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_timeout",
        lambda info, *_: 0.1 if info.name == "analyse-taint" else 30.0,
    )
    bus = CollectingBus()
    outcome = scan(repo, persist=False, bus=bus)
    assert outcome.result.status is ScanStatus.COMPLETED_WITH_ERRORS
    assert outcomes(outcome)["analyse-taint"] is StageOutcome.TIMED_OUT
    store = store_of(outcome)
    assert set(store.get_parts(keys.CANDIDATES_RAW, FakeCandidate)) == ANALYSES - {"analyse-taint"}
    warnings = [event.to_dict() for event in bus.of("warning")]
    assert {"aggregate"} == {
        str(warning["stage"]) for warning in warnings if warning["code"] == "partial_input"
    }
    findings = store.get_json(keys.FINDINGS)
    assert isinstance(findings, list)
    assert len(findings) == CANDIDATE_COUNT - len(FAKE_REPO_FILES)


# 8. Plan rejection.


@pytest.mark.privacy
def test_llm_stage_reading_raw_code_is_rejected(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site, variant="llm-reads-files")
    with pytest.raises(PlanError) as info:
        scan(repo)
    assert info.value.code == "llm_reads_unsanitised"
    assert fake_pipeline.CALLS == {}
    scans = repo / ".codekavach" / "scans"
    assert not scans.exists() or not any(scans.rglob("*"))


# 9. Incremental.


def test_incremental_rescan(fake_site: Path, repo: Path) -> None:
    install_fake_pipeline(fake_site)
    cacheable = ANALYSES | {"aggregate", "rate"}
    first = scan(repo, persist=False)
    second = scan(repo, persist=False)
    assert first.result.cache_hits == 0
    cached = {name for name, outcome in outcomes(second).items() if outcome is StageOutcome.CACHED}
    assert cached == cacheable
    assert outcomes(second)["ingest"] is StageOutcome.SUCCEEDED
    assert outcomes(second)["privacy-prepare"] is StageOutcome.SUCCEEDED
    assert digests(second) == digests(first)
    (repo / "app" / "db.py").write_text("def find_owner(owner):\n    return owner\n", "utf-8")
    third = scan(repo, persist=False)
    assert all(outcomes(third)[name] is StageOutcome.SUCCEEDED for name in cacheable)
    assert digests(third)[keys.FINDINGS] != digests(first)[keys.FINDINGS]


# 10. Offline.


def refuse(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("the pipeline must not start a process")


def test_scan_runs_offline(fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_pipeline(fake_site)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(os, "system", refuse)
    outcome = scan(repo)  # sockets are blocked for every test
    assert outcome.result.status is ScanStatus.COMPLETED
    assert outcomes(outcome) == dict.fromkeys(fake_stages(), StageOutcome.SUCCEEDED)


# 11. Hygiene.


@pytest.mark.privacy
def test_state_directory_hygiene(fake_site: Path, repo: Path, tmp_path: Path) -> None:
    install_fake_pipeline(fake_site)
    outcome = scan(repo)
    state = outcome.state_dir
    entries = list(state.rglob("*"))
    assert entries
    assert not [path.name for path in entries if path.name.endswith(".tmp")]
    if os.name != "nt":
        for path in [state, *entries]:
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == (0o700 if path.is_dir() else 0o600), path.relative_to(state)
    outside = {
        path.relative_to(repo).as_posix()
        for path in repo.rglob("*")
        if path.is_file() and not path.is_relative_to(state)
    }
    assert outside == set(FAKE_REPO_FILES)
    written = {
        path
        for path in tmp_path.rglob("*")
        if path.is_file() and not path.is_relative_to(repo) and not path.is_relative_to(fake_site)
    }
    assert written == set()
    layout = StateLayout(state)
    scan_id = outcome.scan.id
    target_forms = (str(repo), repo.as_posix(), json.dumps(str(repo))[1:-1])
    for record in (
        layout.manifest_path(scan_id),
        layout.snapshot_path(scan_id),
        layout.checkpoint_path(scan_id),
    ):
        text = record.read_text(encoding="utf-8")
        assert SALT_HEX not in text, record.name
        for form in target_forms:
            assert form not in text, record.name
