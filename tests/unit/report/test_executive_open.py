"""The executive summary says how many findings are still open, as the dashboard does."""

import codekavach.report.model.document  # noqa: F401 - loads the report model before the narrative
from codekavach.report.narrative import AggregatedFacts, executive_summary


def _overview(facts: AggregatedFacts) -> str:
    blocks = executive_summary(
        facts, (), (), client="Acme", project="KavachBank", period="in November",
        provider=None, model=None,
    )  # fmt: skip
    return " ".join(blocks[0].paragraphs)


def test_closed_findings_are_named_in_the_summary() -> None:
    facts = AggregatedFacts(total=66, by_severity=(("critical", 19), ("low", 7)), closed=2)
    text = _overview(facts)
    assert "The review identified 66 findings" in text
    assert "64 remain open; two were closed by the reviewers" in text


def test_no_closed_sentence_when_nothing_is_closed() -> None:
    text = _overview(AggregatedFacts(total=3, by_severity=(("high", 3),)))
    assert "remain open" not in text


def test_an_offline_run_says_no_model_reviewed_it() -> None:
    facts = AggregatedFacts(total=3, by_severity=(("high", 3),))
    blocks = executive_summary(
        facts, (), (), client="Acme", project="KavachBank", period="in November",
        provider=None, model="mock-1", offline="mock",
    )  # fmt: skip
    text = " ".join(blocks[0].paragraphs)
    assert "No language model reviewed the code" in text
    assert "model-assisted triage" not in text and "mock-1" not in text


def test_a_live_run_names_model_assisted_triage() -> None:
    facts = AggregatedFacts(total=3, by_severity=(("high", 3),))
    blocks = executive_summary(
        facts, (), (), client="Acme", project="KavachBank", period="in November",
        provider="agentrouter", model="gpt-5.6-sol",
    )  # fmt: skip
    assert "model-assisted triage" in " ".join(blocks[0].paragraphs)
