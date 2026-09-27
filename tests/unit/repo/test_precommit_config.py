"""The pre-commit configuration pins hooks to tags and keeps the security hooks."""

import json
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
REQUIRED_HOOKS = {
    "detect-secrets",
    "forbid-runtime-artefacts",
    "mypy",
    "import-contracts",
    "ruff-check",
    "ruff-format",
}


def _config() -> dict[str, Any]:
    data = yaml.safe_load((REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_parses_and_has_repos() -> None:
    assert _config()["repos"]


def test_third_party_hooks_are_pinned_to_tags() -> None:
    for repo in _config()["repos"]:
        if repo["repo"] == "local":
            continue
        assert repo["rev"] not in {"main", "master", "HEAD"}, repo["repo"]
        assert any(char.isdigit() for char in repo["rev"]), repo["repo"]


def test_required_hooks_present() -> None:
    ids = {hook["id"] for repo in _config()["repos"] for hook in repo["hooks"]}
    assert ids >= REQUIRED_HOOKS


def test_secrets_baseline_is_committed_and_audited() -> None:
    baseline = json.loads((REPO_ROOT / ".secrets.baseline").read_text(encoding="utf-8"))
    for entries in baseline["results"].values():
        for entry in entries:
            assert entry.get("is_secret") is False, entry
