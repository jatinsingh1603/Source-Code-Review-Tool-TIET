"""The board configuration names the repository as it is (E42, issue 294).

``tools/project/board.json`` holds the coordinates of the project board for the tooling under
``tools/``. A wrong repository name keeps working only while GitHub redirects the old one, and
tooling that builds API requests or links from the value would then depend on the redirect.
"""

import json
import re
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BOARD = REPO / "tools" / "project" / "board.json"
OWNER = "jatinsingh1603"
REPOSITORY = "Source-Code-Review-Tool-TIET"
SLUG = f"{OWNER}/{REPOSITORY}"
URL = re.compile(rf"github\.com/{OWNER}/([A-Za-z0-9_.-]+)")
SCANNED = (
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "AGENTS.md",
    "docs/PLAN.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    "tools/project/README.md",
    "tools/project/board.json",
)


def board() -> dict[str, object]:
    loaded: dict[str, object] = json.loads(BOARD.read_text(encoding="utf-8"))
    return loaded


def test_the_board_names_the_repository() -> None:
    data = board()
    assert (data["owner"], data["repository"]) == (OWNER, REPOSITORY)


def test_it_agrees_with_the_project_urls_when_pyproject_has_them() -> None:
    urls = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    for value in urls.get("project", {}).get("urls", {}).values():
        match = URL.search(str(value))
        if match:
            assert match.group(1) == REPOSITORY, value


@pytest.mark.parametrize("name", SCANNED)
def test_no_file_links_to_the_old_repository_name(name: str) -> None:
    path = REPO / name
    if not path.exists():
        pytest.skip(f"{name} does not exist")
    names = {match.group(1) for match in URL.finditer(path.read_text(encoding="utf-8"))}
    assert names <= {REPOSITORY}, f"{name} names {sorted(names - {REPOSITORY})}"


def test_the_checks_are_live(tmp_path: Path) -> None:
    # A board file with the old name must not pass the comparison used above.
    old = {"owner": OWNER, "repository": "Source-Code-Review-Tool-TIT"}
    assert (old["owner"], old["repository"]) != (OWNER, REPOSITORY)
    assert URL.search("see https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIT/x")
    match = URL.search("https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIT/x")
    assert match is not None and match.group(1) != REPOSITORY
    assert SLUG == "jatinsingh1603/Source-Code-Review-Tool-TIET"
