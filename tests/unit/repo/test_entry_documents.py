"""The entry-point documents describe the tooling that exists (E01-34)."""

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RAW_COMMANDS = (
    "uv sync --all-extras",
    "uv run pre-commit install",
    "uv run pytest",
    "uv run codekavach --help",
)


def registered_profiles() -> list[str]:
    """The hypothesis profiles of ``tests/conftest.py``, read from its source."""
    match = re.search(r"^PROFILES = \((.*?)\)", read("tests/conftest.py"), re.MULTILINE)
    assert match is not None
    return re.findall(r'"(\w+)"', match.group(1))


def read(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8")


def section(text: str, heading: str, level: str = "##") -> str:
    """The body of ``heading`` up to the next heading of the same level."""
    match = re.search(rf"^{level} {re.escape(heading)}\n(.*?)(?=^{level} |\Z)", text, re.M | re.S)
    assert match is not None, heading
    return match.group(1)


def code_blocks(text: str) -> list[str]:
    return re.findall(r"```bash\n(.*?)```", text, re.S)


def makefile_targets() -> set[str]:
    return set(re.findall(r"^([a-zA-Z0-9_-]+):", read("Makefile"), re.MULTILINE))


# --- AGENTS.md -----------------------------------------------------------------------------------


def test_agents_setup_section_works_as_written_and_names_the_make_pair() -> None:
    text = section(read("AGENTS.md"), "8. Local setup")
    assert "will not work" not in text
    assert "E01" not in text
    block = code_blocks(text)[0]
    assert tuple(block.split("\n")[:4]) == RAW_COMMANDS
    for phrase in ("make setup", "make check", "make help"):
        assert f"`{phrase}`" in text


def test_agents_definition_of_done_names_the_real_commands() -> None:
    text = section(read("AGENTS.md"), "7. Definition of done")
    assert "`make check`" in text
    assert "`changelog.d/` fragment" in text


def test_agents_checklist_item_seven_names_prepush_and_the_rest_is_kept() -> None:
    text = section(read("AGENTS.md"), "9. Before every push")
    items = re.findall(r"^(\d+)\. \*\*(\w+)\.\*\*", text, re.MULTILINE)
    assert [name for _, name in items] == [
        "Relevance",
        "Claims",
        "Sources",
        "Secrets",
        "Architecture",
        "Licences",
        "Quality",
        "Size",
    ]
    quality = next(line for line in text.splitlines() if line.startswith("7. **Quality.**"))
    assert "`make prepush`" in quality
    assert "pytest" in quality  # the original sentence is still there


# --- README.md -----------------------------------------------------------------------------------


def test_readme_development_section_is_short_and_links_the_contributing_guide() -> None:
    text = section(read("README.md"), "Development")
    assert len(("## Development\n" + text).rstrip().splitlines()) <= 15
    assert "](CONTRIBUTING.md)" in text
    assert tuple(code_blocks(text)[0].split("\n")[:4]) == RAW_COMMANDS
    assert "make setup" in text and "make check" in text


def test_readme_and_agents_give_the_same_four_commands() -> None:
    readme = code_blocks(section(read("README.md"), "Development"))[0]
    agents = code_blocks(section(read("AGENTS.md"), "8. Local setup"))[0]
    assert readme == agents


def test_readme_status_badge_and_stale_wording() -> None:
    text = read("README.md")
    assert "actions/workflows/ci.yml/badge.svg" in text
    assert "foundations in place" in text.lower()
    assert "coming with milestone M0" not in text
    assert "later scaffolding issue" not in text
    assert "follows in E01-34" not in text


def test_readme_repository_map_has_a_row_for_every_tooling_directory() -> None:
    text = section(read("README.md"), "Repository map")
    for path in ("tests/", "tools/dev/", "docs/adr/", "changelog.d/", ".devcontainer/"):
        assert f"| `{path}` |" in text, path
        assert (REPO_ROOT / path).is_dir(), path


def test_contributing_setup_gives_the_make_pair() -> None:
    text = section(read("CONTRIBUTING.md"), "3. Set-up")
    assert "make setup\nmake check" in text


# --- tools/dev/README.md -------------------------------------------------------------------------


def test_every_dev_script_has_a_row_with_a_real_target() -> None:
    text = read("tools/dev/README.md")
    scripts = {path.name for path in (REPO_ROOT / "tools" / "dev").glob("*.py")}
    rows = re.findall(r"^\| `([\w.]+\.py)` \|", text, re.MULTILINE)
    assert set(rows) == scripts
    assert len(rows) == len(set(rows))
    targets = makefile_targets()
    for cell in re.findall(r"`make ([a-z-]+)", text):
        assert cell in targets, cell


# --- tests/README.md -----------------------------------------------------------------------------


def test_tests_readme_lists_every_marker_profile_and_tier_directory() -> None:
    text = read("tests/README.md")
    pyproject = tomllib.loads(read("pyproject.toml"))
    markers = [
        entry.split(":")[0].split("(")[0]
        for entry in pyproject["tool"]["pytest"]["ini_options"]["markers"]
    ]
    markers_table = section(text, "Markers")
    for marker in markers:
        assert f"`{marker}" in markers_table, marker
    profiles_table = section(text, "Property-based tests (hypothesis)")
    assert registered_profiles() == ["dev", "ci", "nightly"]
    for profile in registered_profiles():
        assert f"`{profile}`" in profiles_table, profile
    for tier in ("unit", "integration", "e2e", "privacy"):
        assert f"`tests/{tier}/`" in text
    for directory in ("perf", "process", "docs", "typing", "support"):
        assert f"`tests/{directory}/`" in text, directory
