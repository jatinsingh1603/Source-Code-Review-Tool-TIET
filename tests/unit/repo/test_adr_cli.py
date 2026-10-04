"""ADR-0008 (CLI conventions) and the command line contract of the architecture (E05-01)."""

import re
from pathlib import Path

from codekavach.cli.exit_codes import ExitCode

REPO = Path(__file__).resolve().parents[3]
ADR = REPO / "docs" / "adr" / "0008-cli-conventions.md"
ARCHITECTURE = REPO / "docs" / "ARCHITECTURE.md"
COMMANDS = (
    "scan", "report", "privacy", "providers", "vault", "config", "init", "doctor", "plugins",
    "sync", "eval", "demo", "completion",
)  # fmt: skip


def section(text: str, heading: str) -> str:
    """The text from ``heading`` to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(heading)
    following = re.search(rf"^#{{1,{level}}} ", text[start + len(heading) :], flags=re.MULTILINE)
    end = start + len(heading) + following.start() if following else len(text)
    return text[start:end]


def test_adr_has_the_required_parts() -> None:
    text = ADR.read_text(encoding="utf-8")
    assert "| Status | Proposed |" in text or "| Status | Accepted |" in text
    headings = [line for line in text.splitlines() if line.startswith("#")]
    for word in ("Context", "Decision", "Consequences", "Questions for acceptance"):
        assert any(word in heading for heading in headings), word
    for number in range(1, 10):
        assert f"**D{number} " in text, f"D{number}"
    questions = section(text, "## Questions for acceptance")
    assert len(re.findall(r"^\d+\. ", questions, flags=re.MULTILINE)) == 4


def test_adr_layout_names_modules_that_exist_under_their_names() -> None:
    text = ADR.read_text(encoding="utf-8")
    text = text[text.index("**D1 Layout.**") : text.index("**D2 ")]
    named = set(re.findall(r"`([a-z_]+\.py)`", text))
    existing = {path.name for path in (REPO / "src" / "codekavach" / "cli").glob("*.py")}
    assert existing - {"__init__.py"} <= named


def test_architecture_lists_every_command_and_points_to_the_adr() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    line = next(line for line in text.splitlines() if line.strip().startswith("cli/ "))
    listed = line.split("Typer app:")[1].split("(")[0]
    assert [name.strip() for name in listed.split(",")] == list(COMMANDS)
    assert "ADR-0008" in line


def test_architecture_exit_code_table_matches_the_enum() -> None:
    contract = section(ARCHITECTURE.read_text(encoding="utf-8"), "### 9.1 Command line contract")
    rows = re.findall(r"^\| (\d+) \| `([A-Z_]+)` \|", contract, flags=re.MULTILINE)
    assert {(int(code), name) for code, name in rows} == {
        (member.value, member.name) for member in ExitCode
    }
    assert {int(code) for code, _ in rows} == {0, 1, 2, 3, 4, 130}
    assert "adr/0008-cli-conventions.md" in contract
    assert "reference/exit-codes.md" in contract
    assert "--offline" in contract
    assert "--json" in contract
