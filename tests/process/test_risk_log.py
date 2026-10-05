"""The risk log has one seeded row per risk of the plan, and the ritual states how to rank them."""

import re
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOG = REPO / "docs" / "status" / "risk-log.md"
RITUAL = REPO / "docs" / "process" / "risk-review.md"
GUIDE = REPO / "docs" / "process" / "sprint-cadence.md"
TEMPLATE = REPO / "docs" / "status" / "TEMPLATE.md"
PLAN = REPO / "docs" / "PLAN.md"
COLUMNS = ["Id", "Risk", "Likelihood", "Impact", "Trend", "Owner", "Last reviewed", "Next action"]
SCALE = {"Low": 1, "Medium": 2, "High": 3}
TRENDS = {"up", "flat", "down", "closed"}
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")


def rows(text: str) -> list[list[str]]:
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in text.splitlines()
        if line.startswith("|")
    ]


def plan_risks() -> list[tuple[str, str, str]]:
    """``(risk, likelihood, impact)`` of ``docs/PLAN.md`` section 8, in order."""
    section = (
        PLAN.read_text(encoding="utf-8").split("## 8. Risk register", 1)[1].split("\n## ", 1)[0]
    )
    return [(row[0], row[1], row[2]) for row in rows(section)[2:]]


def log_rows() -> list[dict[str, str]]:
    table = rows(LOG.read_text(encoding="utf-8"))
    assert table[0] == COLUMNS
    return [dict(zip(COLUMNS, row, strict=True)) for row in table[2:]]


def top_three(entries: list[dict[str, str]]) -> list[str]:
    """The ranking rule of the ritual: score, then Id; last row per risk; closed ones left out."""
    current = {entry["Id"]: entry for entry in entries}
    open_risks = [entry for entry in current.values() if entry["Trend"] != "closed"]
    ranked = sorted(
        open_risks,
        key=lambda entry: (-SCALE[entry["Likelihood"]] * SCALE[entry["Impact"]], entry["Id"]),
    )
    return [entry["Id"] for entry in ranked[:3]]


def test_log_has_the_specified_columns_and_valid_values() -> None:
    entries = log_rows()
    assert len(entries) >= 8
    for entry in entries:
        assert re.fullmatch(r"R-\d{2}", entry["Id"]), entry
        assert entry["Likelihood"] in SCALE, entry
        assert entry["Impact"] in SCALE, entry
        assert entry["Trend"] in TRENDS, entry
        assert entry["Owner"], entry
        assert entry["Next action"], entry
        date.fromisoformat(entry["Last reviewed"])


def test_seeded_rows_match_the_risks_of_the_plan() -> None:
    planned = plan_risks()
    assert len(planned) == 8
    seeded = log_rows()[:8]
    assert [entry["Id"] for entry in seeded] == [f"R-{number:02d}" for number in range(1, 9)]
    for entry, (risk, likelihood, impact) in zip(seeded, planned, strict=True):
        assert (entry["Risk"], entry["Likelihood"], entry["Impact"]) == (risk, likelihood, impact)


def test_every_label_in_the_log_is_a_risk_of_the_plan_or_a_later_id() -> None:
    planned = {risk for risk, _, _ in plan_risks()}
    plan_text = PLAN.read_text(encoding="utf-8")
    for entry in log_rows():
        assert entry["Risk"] in planned or entry["Risk"] in plan_text, entry["Risk"]


def test_top_three_rule_is_stated_and_gives_the_documented_result() -> None:
    ritual = " ".join(RITUAL.read_text(encoding="utf-8").split())
    for phrase in (
        "Score = likelihood times impact, with Low = 1, Medium = 2, High = 3",
        "Order by score, highest first. Equal scores are ordered by Id, lowest first.",
        "Only the last row of each risk counts",
        "Trend `closed` are left out",
    ):
        assert phrase in ritual, phrase
    assert top_three(log_rows()[:8]) == ["R-01", "R-02", "R-03"]
    assert "the top three are R-01, R-02 and R-03" in ritual
    changed = [*log_rows()[:8], {**log_rows()[6], "Likelihood": "High", "Impact": "High"}]
    assert top_three(changed) == ["R-07", "R-01", "R-02"]
    closed = [*log_rows()[:8], {**log_rows()[0], "Trend": "closed"}]
    assert top_three(closed) == ["R-02", "R-03", "R-04"]


def test_ritual_covers_cadence_owner_fields_and_new_risks() -> None:
    ritual = " ".join(RITUAL.read_text(encoding="utf-8").split())
    for phrase in (
        "at the end of each sprint",
        "the status-note author runs it",
        "the first new one is R-09",
        "Trend `closed` and the closing date in Last reviewed",
        "**append** a new row",
        "`## Risks and blockers`",
    ):
        assert phrase in ritual, phrase
    for name in ("Likelihood", "Impact", "Trend", "Owner", "Next action"):
        assert f"| {name} |" in RITUAL.read_text(encoding="utf-8"), name


def test_links_between_guide_ritual_log_and_template() -> None:
    def targets(source: Path, needle: str) -> list[Path]:
        return [
            (source.parent / target).resolve()
            for target in LINK.findall(source.read_text(encoding="utf-8"))
            if needle in target
        ]

    assert RITUAL.resolve() in targets(GUIDE, "risk-review")
    assert LOG.resolve() in targets(RITUAL, "risk-log")
    assert RITUAL.resolve() in targets(LOG, "risk-review")
    assert (
        "risk-log.md" in TEMPLATE.read_text(encoding="utf-8").split("## Risks and blockers", 1)[1]
    )
