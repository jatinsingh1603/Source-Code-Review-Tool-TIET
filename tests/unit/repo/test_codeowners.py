"""CODEOWNERS and the pull request template (E01-27)."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CODEOWNERS = REPO_ROOT / ".github" / "CODEOWNERS"
TEMPLATE = REPO_ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
SENSITIVE = ("/src/codekavach/privacy/", "/src/codekavach/llm/", "/.importlinter", "/.github/")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def rules() -> list[list[str]]:
    lines = CODEOWNERS.read_text(encoding="utf-8").splitlines()
    return [line.split() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def test_first_rule_is_the_default() -> None:
    assert rules()[0][0] == "*"


def test_every_rule_has_handle_owners() -> None:
    for pattern, *owners in rules():
        assert owners, pattern
        assert all(owner.startswith("@") for owner in owners), pattern


def test_sensitive_paths_are_owned() -> None:
    patterns = {rule[0] for rule in rules()}
    for path in SENSITIVE:
        assert path in patterns, path


def test_no_email_addresses() -> None:
    assert not _EMAIL.search(CODEOWNERS.read_text(encoding="utf-8"))


def test_pull_request_template() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert len(text.splitlines()) <= 40
    for heading in ("## Summary", "## Linked issue", "## Checklist", "## Privacy impact"):
        assert heading in text, heading
    for item in ("acceptance criteria", "make check", "changelog.d/", "ADR"):
        assert item in text, item
    assert "Closes #" in text
