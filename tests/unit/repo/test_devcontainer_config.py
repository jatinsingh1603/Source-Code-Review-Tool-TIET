"""The devcontainer definition and its workflow (E01-29)."""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.support.workflows import assert_hardened, load_workflow

REPO_ROOT = Path(__file__).resolve().parents[3]
DEVCONTAINER = REPO_ROOT / ".devcontainer"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "devcontainer.yml"
FORBIDDEN_NAME_PARTS = ("KEY", "TOKEN", "SECRET")
_COMMENT = re.compile(r'^\s*//.*$|("(?:\\.|[^"\\])*")|\s//.*$', re.MULTILINE)


def strip_comments(text: str) -> str:
    """Remove ``//`` comments outside strings (devcontainer.json is JSON with comments)."""
    return _COMMENT.sub(lambda match: match.group(1) or "", text)


@pytest.fixture(scope="module")
def config() -> dict[str, Any]:
    text = (DEVCONTAINER / "devcontainer.json").read_text(encoding="utf-8")
    loaded = json.loads(strip_comments(text))
    assert isinstance(loaded, dict)
    return loaded


def test_strip_comments_keeps_urls_in_strings() -> None:
    assert json.loads(strip_comments('// c\n{"a": "http://x//y"} // tail\n')) == {
        "a": "http://x//y"
    }


def test_user_setup_and_environment(config: dict[str, Any]) -> None:
    assert config["remoteUser"] == "vscode"
    assert config["postCreateCommand"] == "make setup"
    env = config["containerEnv"]
    venv = env["UV_PROJECT_ENVIRONMENT"]
    assert venv.startswith("/")
    assert not venv.startswith("/workspaces")
    assert env["DO_NOT_TRACK"] == "1"
    assert env["UV_LINK_MODE"] == "copy"
    settings = config["customizations"]["vscode"]["settings"]
    assert settings["telemetry.telemetryLevel"] == "off"
    assert settings["python.defaultInterpreterPath"].startswith(venv)


def test_nothing_mounted_privileged_or_secret(config: dict[str, Any]) -> None:
    assert "mounts" not in config
    assert "workspaceMount" not in config
    run_args = " ".join(config.get("runArgs", []))
    assert "--privileged" not in run_args
    assert "--cap-add" not in run_args
    assert "privileged" not in config
    for section in ("containerEnv", "remoteEnv"):
        for name in config.get(section, {}):
            assert not any(part in name.upper() for part in FORBIDDEN_NAME_PARTS), name


def test_recommended_extensions_match() -> None:
    recommended = json.loads((REPO_ROOT / ".vscode" / "extensions.json").read_text("utf-8"))
    text = (DEVCONTAINER / "devcontainer.json").read_text(encoding="utf-8")
    container = json.loads(strip_comments(text))["customizations"]["vscode"]["extensions"]
    assert set(container) <= set(recommended["recommendations"])


def test_dockerfile_pins_and_installs() -> None:
    text = (DEVCONTAINER / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
    assert from_lines
    assert all("@sha256:" in line for line in from_lines)
    assert re.search(r"COPY --from=ghcr\.io/astral-sh/uv:\d+\.\d+\.\d+ /uv /uvx /bin/", text)
    assert not re.search(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh", text)
    assert "--no-install-recommends" in text
    assert "rm -rf /var/lib/apt/lists/*" in text
    for package in ("make", "git", "libpango-1.0-0", "libpangoft2-1.0-0"):
        assert package in text
    assert text.rstrip().splitlines()[-1] == "USER vscode"


def test_workflow_is_hardened_and_path_triggered() -> None:
    assert_hardened(WORKFLOW)
    workflow = load_workflow(WORKFLOW)
    triggers = workflow["on"]
    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    expected = [".devcontainer/**", ".github/workflows/devcontainer.yml"]
    assert triggers["push"]["paths"] == expected
    assert triggers["pull_request"]["paths"] == expected
    step = workflow["jobs"]["build-and-check"]["steps"][-1]
    assert step["uses"].startswith("devcontainers/ci@")
    assert step["with"]["push"] == "never"
    assert "make check" in step["with"]["runCmd"]
