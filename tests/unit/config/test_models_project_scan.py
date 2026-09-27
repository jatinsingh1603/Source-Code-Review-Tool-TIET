from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from codekavach.config.models.project import ProjectSettings
from codekavach.config.models.scan import DEFAULT_EXCLUDE, ScanSettings
from codekavach.core.models import Severity


def code_of(error: ValidationError) -> str:
    return str(error.errors()[0].get("ctx", {}).get("error", error.errors()[0]["msg"]))


def test_project_defaults() -> None:
    project = ProjectSettings()
    assert project.name is None
    assert project.client is None
    assert project.description is None
    assert project.state_dir == Path(".codekavach")
    assert project.languages == []


def test_scan_defaults() -> None:
    scan = ScanSettings()
    assert scan.include == ["**/*"]
    assert scan.exclude == DEFAULT_EXCLUDE
    assert scan.respect_gitignore is True
    assert scan.follow_symlinks is False
    assert scan.max_file_size_kb == 1024
    assert scan.max_files == 50_000
    assert scan.max_total_size_mb == 2048
    assert scan.jobs == 0
    assert scan.timeout_seconds == 3600
    assert scan.skip_stages == []
    assert scan.fail_on is Severity.HIGH
    assert scan.cache is True
    assert scan.stage_timeout_seconds == 1800
    assert scan.stage_timeouts == {}
    assert scan.cache_max_size_mb == 2048
    assert scan.cache_keep_scans == 5


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_file_size_kb": 0},
        {"jobs": -1},
        {"jobs": 257},
        {"include": []},
        {"include": ["x" * 257]},
        {"exclude": ["a\\b"]},
        {"stage_timeout_seconds": 9},
        {"stage_timeout_seconds": 86_401},
        {"stage_timeouts": {"parse": 5}},
        {"cache_max_size_mb": 63},
        {"cache_keep_scans": 0},
    ],
    ids=lambda o: next(iter(o)),
)
def test_scan_bounds(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as info:
        ScanSettings.model_validate(overrides)
    assert code_of(info.value).startswith("[CK-CFG-003]")


@pytest.mark.parametrize("value", ["critical", "high", "medium", "low", "info", "none"])
def test_fail_on_accepts(value: str) -> None:
    assert str(ScanSettings.model_validate({"fail_on": value}).fail_on) == value


@pytest.mark.parametrize("value", ["never", "HIGH"])
def test_fail_on_rejects(value: str) -> None:
    with pytest.raises(ValidationError):
        ScanSettings.model_validate({"fail_on": value})


def test_project_bounds() -> None:
    with pytest.raises(ValidationError):
        ProjectSettings.model_validate({"name": ""})
    with pytest.raises(ValidationError):
        ProjectSettings.model_validate({"name": "x" * 101})
    assert ProjectSettings.model_validate({"languages": ["python"]}).languages[0].value == "python"
