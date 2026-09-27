from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import (
    DataClassification,
    Language,
    ModelError,
    PrivacyLevel,
    ScanStatus,
    StageStatus,
)
from codekavach.core.models.ids import ProjectId, is_ulid, strip_prefix
from codekavach.core.models.scan import DEFAULT_STAGES, Project, Scan, StageResult
from codekavach.core.models.summary import EgressTotals, ScanSummary
from tests.support.golden import assert_matches_golden
from tests.support.synthetic import example_secret

GOLDEN = Path(__file__).parent / "golden" / "scan_v1.json"
T0 = datetime(2026, 10, 5, 4, 30, tzinfo=UTC)
PROJECT_ID = ProjectId("proj_01ARYZ6S410000000000000000")
CONFIG_HASH = "ab" * 32


def summary() -> ScanSummary:
    return ScanSummary.from_findings(
        [],
        files_scanned=12,
        lines_scanned=900,
        candidates_total=3,
        candidates_reviewed_by_llm=3,
        egress=EgressTotals.empty(),
        duration_seconds=4.0,
    )


def running(**optional: Any) -> Scan:
    return Scan.start(
        project_id=PROJECT_ID,
        codekavach_version="0.1.0",
        config_hash=CONFIG_HASH,
        privacy_level=PrivacyLevel.L3,
        at=T0,
        **optional,
    )


def test_example_lifecycle() -> None:
    scan = running()
    assert scan.status is ScanStatus.RUNNING
    assert is_ulid(strip_prefix(scan.id))
    scan = scan.with_stage(StageResult(name="ingest", status=StageStatus.RUNNING, started_at=T0))
    scan = scan.with_stage(
        StageResult(
            name="ingest",
            status=StageStatus.SUCCEEDED,
            started_at=T0,
            finished_at=T0 + timedelta(seconds=2),
            items_out=42,
        )
    )
    scan = scan.finish(ScanStatus.COMPLETED, summary(), at=T0 + timedelta(seconds=4))
    assert scan.status is ScanStatus.COMPLETED
    assert [(s.name, s.status) for s in scan.stages] == [("ingest", StageStatus.SUCCEEDED)]
    assert scan.duration_seconds == 4.0
    assert Scan.model_validate_json(scan.model_dump_json()) == scan


def test_pending_to_completed_with_errors() -> None:
    pending = Scan.model_validate({**running().model_dump(), "status": ScanStatus.PENDING})
    assert pending.duration_seconds is None
    scan = pending.evolve(status=ScanStatus.RUNNING).with_stage(
        StageResult(name="llm-review", status=StageStatus.FAILED, error_code="provider_timeout")
    )
    ended = scan.finish(ScanStatus.COMPLETED_WITH_ERRORS, summary(), at=T0 + timedelta(1))
    assert ended.status is ScanStatus.COMPLETED_WITH_ERRORS


@pytest.mark.parametrize("status", [ScanStatus.FAILED, ScanStatus.CANCELLED])
def test_failed_and_cancelled(status: ScanStatus) -> None:
    ended = running().finish(status, None, at=T0 + timedelta(seconds=1))
    assert ended.status is status
    assert ended.summary is None


def test_finish_rules() -> None:
    ended = running().finish(ScanStatus.FAILED, None, at=T0 + timedelta(seconds=1))
    with pytest.raises(ModelError, match="already finished"):
        ended.finish(ScanStatus.CANCELLED, None, at=T0 + timedelta(seconds=2))
    for status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        with pytest.raises(ModelError, match="end status"):
            running().finish(status, None, at=T0)
    with pytest.raises(ValidationError, match="summary"):
        running().finish(ScanStatus.COMPLETED, None, at=T0 + timedelta(seconds=1))


def test_with_stage_replaces_by_name_and_keeps_order() -> None:
    scan = running()
    for name in ("ingest", "parse", "analyse"):
        scan = scan.with_stage(StageResult(name=name, status=StageStatus.RUNNING))
    scan = scan.with_stage(StageResult(name="parse", status=StageStatus.SUCCEEDED))
    assert [s.name for s in scan.stages] == ["ingest", "parse", "analyse"]
    assert scan.stages[1].status is StageStatus.SUCCEEDED


def scan_fields(**overrides: Any) -> dict[str, Any]:
    data = running().model_dump()
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"status": ScanStatus.FAILED, "finished_at": T0 - timedelta(seconds=1)}, "before"),
        ({"status": ScanStatus.COMPLETED, "finished_at": T0}, "summary"),
        ({"summary": summary()}, "pending or running"),
        ({"finished_at": T0}, "pending or running"),
        ({"status": ScanStatus.CANCELLED}, "finished_at"),
        (
            {
                "stages": (
                    StageResult(name="ingest", status=StageStatus.RUNNING),
                    StageResult(name="ingest", status=StageStatus.SUCCEEDED),
                )
            },
            "unique",
        ),
        ({"git_commit": "abcdef1"[:6]}, "pattern"),
        ({"git_commit": "ABCDEF1"}, "pattern"),
        ({"git_commit": "a" * 65}, "pattern"),
        ({"config_hash": "xyz"}, "pattern"),
        ({"provider": "mo\x00ck"}, "control"),
    ],
)
def test_scan_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Scan.model_validate(scan_fields(**overrides))


def test_git_commit_accepts_sha1_and_sha256() -> None:
    assert Scan.model_validate(scan_fields(git_commit="a" * 7)).git_commit
    assert Scan.model_validate(scan_fields(git_commit="b" * 40)).git_commit
    assert Scan.model_validate(scan_fields(git_commit="c" * 64)).git_commit


def test_languages_sorted_and_deduplicated() -> None:
    scan = running(languages=(Language.PYTHON, Language.JAVASCRIPT, Language.PYTHON))
    assert scan.languages == (Language.JAVASCRIPT, Language.PYTHON)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"name": "Ingest", "status": StageStatus.RUNNING}, "pattern"),
        ({"name": "rate", "status": StageStatus.FAILED}, "error_code"),
        ({"name": "rate", "status": StageStatus.SUCCEEDED, "error_code": "boom"}, "error_code"),
        (
            {
                "name": "rate",
                "status": StageStatus.SUCCEEDED,
                "started_at": T0,
                "finished_at": T0 - timedelta(seconds=1),
            },
            "before",
        ),
        ({"name": "rate", "status": StageStatus.FAILED, "error_code": "Bad Code"}, "pattern"),
        (
            {
                "name": "rate",
                "status": StageStatus.FAILED,
                "error_code": "e1",
                "error_summary": "x" * 501,
            },
            "500",
        ),
    ],
)
def test_stage_result_rejected(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        StageResult.model_validate(fields)


def test_default_stage_names_are_valid() -> None:
    for name in DEFAULT_STAGES:
        StageResult(name=name, status=StageStatus.PENDING)


# project


def project(**overrides: Any) -> Project:
    fields: dict[str, Any] = {
        "id": PROJECT_ID,
        "name": "KavachBank",
        "root": "/home/demo/work/kavachbank",
        "created_at": T0,
    }
    fields.update(overrides)
    return Project.model_validate(fields)


# Credential-shaped values are assembled at runtime (tests/support/synthetic.py) so that no
# literal credential URL is committed.
BASIC_AUTH_URL = example_secret("basic_auth_url")
PASSWORD = BASIC_AUTH_URL.split(":")[2].split("@")[0]
TOKEN = "tok" + "envalue"


@pytest.mark.parametrize(
    "url",
    [
        BASIC_AUTH_URL,
        "https://" + TOKEN + "@example.test/x.git",
        "ssh://git:" + PASSWORD + "@example.test/x.git",
        "ftp://example.test/x.git",
        "not a url",
    ],
    ids=["https-password", "https-token", "ssh-password", "ftp", "garbage"],
)
def test_project_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValidationError) as info:
        project(repository_url=url)
    assert PASSWORD not in str(info.value)
    assert TOKEN not in str(info.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/org/x.git",
        "http://example.test/x.git",
        "ssh://git@example.test/x.git",
        "git@example.test:org/x.git",
    ],
)
def test_project_accepts_urls(url: str) -> None:
    assert project(repository_url=url).repository_url == url


def test_project_rules_and_round_trip() -> None:
    with pytest.raises(ValidationError):
        project(name="two\nlines")
    with pytest.raises(ValidationError):
        project(name="")
    value = project(repository_url="https://example.test/x.git")
    assert Project.model_validate_json(value.model_dump_json()) == value
    assert value.default_privacy_level is PrivacyLevel.L3
    for model in (Project, Scan, StageResult):
        assert model.DATA_CLASSIFICATION is DataClassification.RAW


def test_golden_file() -> None:
    scan = Scan.model_validate(
        {
            **running(git_commit="0123abc", git_branch="main", git_dirty=False).model_dump(),
            "id": "scan_01ARYZ6S410000000000000000",
        }
    )
    scan = scan.with_stage(
        StageResult(
            name="ingest",
            status=StageStatus.SUCCEEDED,
            started_at=T0,
            finished_at=T0 + timedelta(seconds=2),
            items_out=42,
        )
    ).finish(ScanStatus.COMPLETED, summary(), at=T0 + timedelta(seconds=4))
    assert_matches_golden(scan.model_dump_json(indent=2) + "\n", GOLDEN)


@given(
    st.lists(st.tuples(st.sampled_from(DEFAULT_STAGES), st.sampled_from(StageStatus)), max_size=30)
)
def test_with_stage_keeps_names_unique_and_first_order(
    steps: list[tuple[str, StageStatus]],
) -> None:
    scan = running()
    first_seen: list[str] = []
    for name, status in steps:
        code = "stage_failed" if status is StageStatus.FAILED else None
        scan = scan.with_stage(StageResult(name=name, status=status, error_code=code))
        if name not in first_seen:
            first_seen.append(name)
    assert [stage.name for stage in scan.stages] == first_seen
