"""The Definition of Ready is one tickable checklist that uses the repository's label names."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCUMENT = REPO / "docs" / "process" / "definition-of-ready.md"
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")
LABEL_GROUPS = {
    "Type": ("type:feature", "type:task", "type:test", "type:docs", "type:infra", "type:security"),
    "Priority": ("P0-critical", "P1-high", "P2-medium", "P3-low"),
    "Size": ("size:XS", "size:S", "size:M", "size:L", "size:XL"),
    "Area": ("area:",),
    "Readiness": ("agent-ready", "needs-human"),
}


@pytest.fixture(scope="module")
def document() -> str:
    return DOCUMENT.read_text(encoding="utf-8")


def checklist(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("- [ ] ")]


def test_it_is_one_checklist_of_a_readable_length(document: str) -> None:
    items = checklist(document)
    assert 10 <= len(items) <= 16
    assert document.count("\n## Checklist\n") == 1
    lines = document.splitlines()
    positions = [index for index, line in enumerate(lines) if line.startswith("- [ ] ")]
    assert positions == list(range(positions[0], positions[0] + len(items))), "one unbroken list"
    assert "- [x]" not in document.lower()


def test_each_label_group_is_named_with_the_exact_labels(document: str) -> None:
    items = checklist(document)
    for group, labels in LABEL_GROUPS.items():
        line = next((item for item in items if item.startswith(f"- [ ] {group}:")), None)
        assert line is not None, group
        for label in labels:
            assert f"`{label}" in line, label
        assert "exactly one" in line or "at least one" in line, group


def test_required_gates_are_present(document: str) -> None:
    text = " ".join(document.split())
    for phrase in (
        "The Goal states",
        "Acceptance criteria are present and each is verifiable",
        "Milestone is set",
        "Epic is set",
        '"Blocked by" exists and is resolvable',
        "For `needs-human`: the body states the exact question",
        "`privacy-critical` and names each affected invariant (I1 to I6)",
        "**How to use.**",
        "Definition of Done in `AGENTS.md` section 7",
    ):
        assert phrase in text, phrase


@pytest.mark.parametrize("page", ["AGENTS.md", "docs/process/sprint-cadence.md"])
def test_pages_link_to_the_checklist(page: str) -> None:
    source = REPO / page
    targets = [
        target
        for target in LINK.findall(source.read_text(encoding="utf-8"))
        if "definition-of-ready" in target
    ]
    assert targets, f"{page} has no link to the Definition of Ready"
    for target in targets:
        assert (source.parent / target).resolve() == DOCUMENT.resolve()


def test_relative_links_resolve(document: str) -> None:
    for target in LINK.findall(document):
        assert (DOCUMENT.parent / target).exists(), target
