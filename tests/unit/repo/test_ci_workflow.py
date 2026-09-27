import re
from pathlib import Path

import pytest

from tests.support.workflows import assert_hardened, load_workflow

REPO_ROOT = Path(__file__).resolve().parents[3]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SHA = "0" * 40  # any 40-hex-digit value; a real commit SHA trips the secret scanner


def test_ci_is_hardened() -> None:
    assert_hardened(CI)


def test_every_action_has_a_version_comment() -> None:
    for line in CI.read_text(encoding="utf-8").splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line), line


def test_triggers() -> None:
    triggers = load_workflow(CI)["on"]
    assert triggers["push"] == {"branches": ["main"]}
    assert "pull_request" in triggers
    assert "workflow_dispatch" in triggers


def test_matrix() -> None:
    matrix = load_workflow(CI)["jobs"]["test"]["strategy"]["matrix"]
    assert sorted(matrix["os"]) == ["macos-latest", "ubuntu-latest"]
    assert sorted(matrix["python"]) == ["3.12", "3.13"]


def test_ci_ok_needs_every_other_job() -> None:
    jobs = load_workflow(CI)["jobs"]
    assert set(jobs["ci-ok"]["needs"]) == set(jobs) - {"ci-ok"}
    assert jobs["ci-ok"]["if"] == "always()"


def test_environment() -> None:
    workflow = load_workflow(CI)
    env = workflow["env"]
    assert env["HYPOTHESIS_PROFILE"] == "ci"
    assert "CODEKAVACH_PERF_FACTOR" in env
    assert "UV_FROZEN" not in CI.read_text(encoding="utf-8")
    assert workflow["jobs"]["test"]["env"]["UV_PYTHON"] == "${{ matrix.python }}"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "wf.yml"
    path.write_text(text, encoding="utf-8")
    return path


GOOD_STEP = f"      - uses: actions/checkout@{SHA} # v7.0.1\n"
HEADER = "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n"


def test_synthetic_good_workflow_passes(tmp_path: Path) -> None:
    assert_hardened(_write(tmp_path, HEADER + "    steps:\n" + GOOD_STEP))


@pytest.mark.parametrize(
    "text",
    [
        HEADER + "    steps:\n      - uses: actions/checkout@v7\n",
        HEADER + "    permissions:\n      contents: write\n    steps:\n" + GOOD_STEP,
        "on: pull_request_target\npermissions:\n  contents: read\njobs: {}\n",
        HEADER.replace("contents: read", "contents: write") + "    steps:\n" + GOOD_STEP,
    ],
    ids=["tag-instead-of-sha", "job-widens", "pull-request-target", "top-level-widens"],
)
def test_synthetic_bad_workflows_fail(tmp_path: Path, text: str) -> None:
    with pytest.raises(AssertionError):
        assert_hardened(_write(tmp_path, text))
