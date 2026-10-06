"""The Dependabot configuration: ecosystems, schedule, commit prefix and labels (E01-28)."""

from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".github" / "dependabot.yml"

# Labels of the project that Dependabot may put on a pull request. A label that does not exist
# in the repository is a configuration error on GitHub's side, so the list is kept here.
ALLOWED_LABELS = frozenset({"type:infra", "area:packaging", "area:core", "area:hardening"})
FUTURE_ECOSYSTEMS = ("/ui", "/extensions/vscode", "/deploy")


@pytest.fixture(scope="module")
def config() -> dict[str, Any]:
    loaded = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_version_and_ecosystems(config: dict[str, Any]) -> None:
    assert config["version"] == 2
    ecosystems = [entry["package-ecosystem"] for entry in config["updates"]]
    assert ecosystems == ["uv", "github-actions", "devcontainers", "docker"]
    directories = [entry["directory"] for entry in config["updates"]]
    assert directories == ["/", "/", "/", "/.devcontainer"]


def test_every_entry_is_weekly_prefixed_limited_and_labelled(config: dict[str, Any]) -> None:
    for entry in config["updates"]:
        name = entry["package-ecosystem"]
        assert entry["commit-message"] == {"prefix": "infra"}, name
        assert entry["schedule"]["interval"] == "weekly", name
        assert entry["schedule"]["day"] == "monday", name
        assert entry["schedule"]["timezone"] == "Asia/Kolkata", name
        assert isinstance(entry["open-pull-requests-limit"], int), name
        assert entry["open-pull-requests-limit"] > 0, name
        assert entry["labels"], name
        assert set(entry["labels"]) <= ALLOWED_LABELS, name


def test_groups_leave_major_updates_ungrouped(config: dict[str, Any]) -> None:
    python, actions = config["updates"][:2]
    assert set(python["groups"]) == {"dev-tools", "runtime-minor-patch"}
    for group in python["groups"].values():
        assert group["update-types"] == ["minor", "patch"]
    assert python["groups"]["dev-tools"]["dependency-type"] == "development"
    assert python["groups"]["runtime-minor-patch"]["dependency-type"] == "production"
    assert actions["groups"] == {"actions": {"patterns": ["*"]}}


def test_prefix_gives_subjects_that_pass_the_commit_check() -> None:
    import importlib.util  # noqa: PLC0415
    import sys  # noqa: PLC0415

    script = REPO_ROOT / "tools" / "dev" / "check_commit_msg.py"
    spec = importlib.util.spec_from_file_location("check_commit_msg", script)
    assert spec is not None
    assert spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    sys.modules["check_commit_msg"] = checker
    spec.loader.exec_module(checker)
    assert checker.validate("infra: bump ruff from 0.16.0 to 0.16.1") == []
    assert checker.validate("infra: bump the dev-tools group with 3 updates") == []
    assert (
        checker.validate("infra: bump actions/checkout from 7.0.0 to 7.0.1 in the actions group")
        == []
    )


def test_comment_block_names_future_ecosystems_and_the_guide_documents_handling() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    header = text.split("version: 2", 1)[0]
    for directory in FUTURE_ECOSYSTEMS:
        assert directory in header, directory
    for epic in ("E33", "E35", "E39", "E01-29"):
        assert epic in header, epic
    guide = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    section = guide.split("## 9. Dependencies", 1)[1].split("\n## ", 1)[0]
    for phrase in ("Dependabot", "`infra:` prefix", "auto-merge", "upstream changelog"):
        assert phrase in section, phrase


def test_devcontainer_image_keeps_its_python_version(config: dict[str, Any]) -> None:
    docker = next(e for e in config["updates"] if e["package-ecosystem"] == "docker")
    (rule,) = docker["ignore"]
    assert rule["dependency-name"] == "mcr.microsoft.com/devcontainers/python"
    assert set(rule["update-types"]) == {
        "version-update:semver-major",
        "version-update:semver-minor",
    }
