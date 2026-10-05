"""The Demo 1 agenda covers the six exit criteria of the plan and stays within the demo's scope."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
AGENDA = REPO / "docs" / "status" / "demo-1-agenda.md"
GUIDE = REPO / "docs" / "process" / "sprint-cadence.md"
PLAN = REPO / "docs" / "PLAN.md"
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")

# One or more distinctive phrases per exit criterion of docs/PLAN.md section 5.
CRITERIA = {
    1: ("codekavach scan fixtures/kavachbank", "no paid API key"),
    2: ("planted vulnerabilities", "planted secrets", "interest and fee engine"),
    3: ("codekavach privacy inspect", "side by side", "typed placeholders"),
    4: ("no planted secret", "business-domain term", "verbatim", "egress ledger"),
    5: ("real files, lines and names",),
    6: ("An HTML and a PDF report", "executive summary", "risk matrix"),
}
OTHER_LANGUAGES = (
    "TypeScript", "Java", "Kotlin", "Go", "Golang", "Rust", "Ruby", "PHP", "Swift", "Scala", "C#",
    "C++", "Perl",
)  # fmt: skip


@pytest.fixture(scope="module")
def agenda() -> str:
    return AGENDA.read_text(encoding="utf-8")


def flat(text: str) -> str:
    return " ".join(text.split())


def section(text: str, heading: str) -> str:
    """The body of the H2 section ``heading``."""
    assert f"\n## {heading}\n" in text, heading
    return text.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0]


def test_criteria_phrases_come_from_the_plan() -> None:
    plan = flat(PLAN.read_text(encoding="utf-8").split("### Demo 1 exit criteria", 1)[1])
    for number, phrases in CRITERIA.items():
        for phrase in phrases:
            assert phrase in plan, (number, phrase)


@pytest.mark.parametrize("number", sorted(CRITERIA))
def test_agenda_covers_each_exit_criterion(agenda: str, number: int) -> None:
    text = flat(agenda)
    for phrase in CRITERIA[number]:
        assert phrase in text, phrase
    rows = [line for line in section(agenda, "Running order").splitlines() if line.startswith("|")]
    mapped = [row for row in rows if row.rstrip("| ").endswith(f"| {number}")]
    assert len(mapped) == 1, f"exit criterion {number} needs exactly one segment"
    assert re.search(rf"^{number}\. .+: segment \d\.$", agenda, flags=re.M)


def test_running_order_is_timed_and_has_an_objective(agenda: str) -> None:
    head = agenda.split("\n## ", 1)[0]
    assert "**Objective.**" in head
    rows = [line for line in section(agenda, "Running order").splitlines() if line.startswith("|")]
    spans = [re.search(r"\| (\d+) to (\d+) \|", row) for row in rows[2:]]
    assert all(spans)
    minutes = [(int(span.group(1)), int(span.group(2))) for span in spans if span]
    assert minutes[0][0] == 0
    assert all(start < end for start, end in minutes)
    assert [start for start, _ in minutes[1:]] == [end for _, end in minutes[:-1]]
    assert 20 <= minutes[-1][1] <= 30


def test_checklist_and_fallback_are_present(agenda: str) -> None:
    checklist = section(agenda, "Pre-demo checklist")
    assert checklist.count("- [ ]") >= 4
    for phrase in ("No paid key", "offline", "fixtures/kavachbank", "reports directory is clean"):
        assert phrase in flat(checklist), phrase
    fallback = flat(section(agenda, "Fallback plan"))
    for phrase in ("replay", "cassettes", "recorded artefacts", "HTML report"):
        assert phrase in fallback, phrase
    not_yet = section(agenda, "What we are not showing yet")
    assert len([line for line in not_yet.splitlines() if line.startswith("- ")]) == 2
    assert "M2 Detection engine" in not_yet
    assert "M5 Audit reporting" in not_yet


def test_demo_languages_are_python_and_javascript_only(agenda: str) -> None:
    assert "Python and JavaScript only" in agenda
    for language in OTHER_LANGUAGES:
        pattern = rf"(?<![A-Za-z]){re.escape(language)}(?![A-Za-z+#])"
        assert re.search(pattern, agenda) is None, language


def test_agenda_marks_the_commands_of_the_demo_slice(agenda: str) -> None:
    text = flat(agenda)
    assert "provided by the demo slice, epic E13" in text
    assert "reconcile them with the runbook `docs/demo/DEMO1.md`" in text
    assert "not on real client code" in text
    assert "what *would* have left" in text


def test_sprint_guide_links_to_the_agenda() -> None:
    targets = [
        target
        for target in LINK.findall(GUIDE.read_text(encoding="utf-8"))
        if "demo-1-agenda" in target
    ]
    assert targets
    for target in targets:
        assert (GUIDE.parent / target).resolve() == AGENDA.resolve()


def test_relative_links_of_the_agenda_resolve(agenda: str) -> None:
    for target in LINK.findall(agenda):
        if not target.startswith(("http://", "https://")):
            assert (AGENDA.parent / target).exists(), target
