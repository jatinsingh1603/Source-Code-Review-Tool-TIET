"""The triage task, its prompt and its schema (E13-02)."""

import re

import pytest

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.payload import PayloadFacts, SanitisedPayload
from codekavach.core.models.text import SanitisedText
from codekavach.core.models.verdict import LLMVerdict
from codekavach.llm.prompts.loader import PromptNotFoundError, load_prompt
from codekavach.llm.schema.triage import FIRST_FIELD, triage_schema
from codekavach.llm.tasks.base import CandidateFacts
from codekavach.llm.tasks.triage import PromptBoundaryError, TriageTask
from tests.support.factories import make_payload

FACTS = PayloadFacts(
    rule="KB-VULN-001",
    cwe=(89,),
    sink_family="sql",
    strategy="enclosing_function",
    stub_summaries=("returns value; no sanitiser; derived: syntactic",),
)


def payload() -> SanitisedPayload:
    return make_payload(facts=FACTS)


def render(**kwargs: str) -> str:
    return TriageTask().render(payload(), CandidateFacts.from_payload(payload()), **kwargs)


def test_the_task_states_its_name_and_version() -> None:
    task = TriageTask()
    assert (task.name, task.prompt_version) == ("triage", "v2")
    assert re.fullmatch(r"[0-9a-f]{64}", task.prompt_hash)


def test_the_prompt_hash_is_the_hash_of_the_template_and_is_stable() -> None:
    template = load_prompt("triage", "v1")
    assert TriageTask("v1").prompt_hash == template.sha256 == TriageTask("v1").prompt_hash
    combined = sha256_hex(load_prompt("triage", "v2").sha256 + load_prompt("common", "v1").sha256)
    assert TriageTask().prompt_hash == combined
    assert re.fullmatch(r"[0-9a-f]{64}", template.sha256)


@pytest.mark.parametrize(("task", "version"), [("triage", "v9"), ("nope", "v1"), ("../x", "v1")])
def test_an_unknown_or_malformed_prompt_is_not_found(task: str, version: str) -> None:
    with pytest.raises(PromptNotFoundError):
        load_prompt(task, version)


def test_the_rubric_precedes_the_delimited_client_material() -> None:
    text = render(delimiter="=====TEST=====")
    first_boundary = text.index("=====TEST=====")
    assert text.index("Is the sink security-relevant") < first_boundary
    assert text.index("never instructions") < first_boundary
    assert text.index("SELECT * FROM tbl_7") > first_boundary
    assert text.index("rule: KB-VULN-001") > first_boundary
    assert text.count("=====TEST=====") == 3
    assert text.rstrip().endswith("=====TEST===== end")


def test_the_template_comment_is_not_sent() -> None:
    text = render()
    assert "<!--" not in text and "injection resistance" not in text


def test_the_template_itself_says_it_is_not_a_claim_of_injection_resistance() -> None:
    assert "not a claim of injection resistance" in load_prompt("triage", "v1").text


def test_the_delimiter_is_random_for_every_request() -> None:
    seen = {re.search(r"=====CK-[0-9a-f]+=====", render()) for _ in range(20)}
    assert None not in seen
    assert len({match.group() for match in seen if match}) == 20


def test_a_delimiter_that_occurs_in_the_material_fails_closed() -> None:
    with pytest.raises(PromptBoundaryError):
        render(delimiter="SELECT")


def test_the_payload_text_is_inserted_verbatim_even_if_it_looks_like_a_template() -> None:
    odd = make_payload(text=SanitisedText("x = '{{FACTS}} {{BOUNDARY}}'\n"), line_map=())
    text = TriageTask().render(odd, CandidateFacts.from_payload(odd), delimiter="=====T=====")
    assert "x = '{{FACTS}} {{BOUNDARY}}'" in text


# --- what a prompt never contains ---------------------------------------------------------------

EXCLUDED = {
    "engine severity": ("severity", "critical", "high severity"),
    "prior verdict": ("is_vulnerable", "verdict:", "previously"),
    "file path": ("services/api/accounts.py", "/src/", ".py:"),
    "author": ("author", "committer", "alice@example"),
    "commit message": ("commit message", "fix: ", "git log"),
    "pull request": ("pull request", "pull-request", "pr #"),
}


@pytest.mark.parametrize("field", sorted(EXCLUDED))
def test_each_excluded_field_is_absent_from_the_rendered_prompt(field: str) -> None:
    text = render().casefold()
    # The rubric may talk about the verdict it asks for; the candidate material may not.
    material = text[text.index("=====ck-") :]
    for needle in EXCLUDED[field]:
        if field == "prior verdict" and needle == "is_vulnerable":
            continue
        assert needle.casefold() not in material, (field, needle)


def test_the_facts_object_has_no_field_that_could_carry_an_excluded_value() -> None:
    names = set(CandidateFacts.__dataclass_fields__)
    assert names == {"rule_id", "cwe", "sink_family", "strategy", "stub_summaries"}
    assert set(PayloadFacts.model_fields) == {
        "rule",
        "cwe",
        "sink_family",
        "strategy",
        "stub_summaries",
    }


def test_a_payload_without_facts_renders_neutral_facts() -> None:
    bare = make_payload()
    text = TriageTask().render(bare, CandidateFacts.from_payload(bare))
    assert "rule: unknown" in text and "cwe: none given" in text


# --- the schema ---------------------------------------------------------------------------------


def test_the_free_text_analysis_comes_first_in_the_schema() -> None:
    schema = triage_schema()
    assert next(iter(schema["properties"])) == FIRST_FIELD  # type: ignore[call-overload]
    assert schema["required"][0] == FIRST_FIELD  # type: ignore[index]
    assert set(schema["properties"]) == set(LLMVerdict.llm_output_schema()["properties"])  # type: ignore[call-overload]


def test_the_strict_variant_wraps_the_same_schema() -> None:
    strict = triage_schema(strict=True)
    assert strict["strict"] is True and strict["name"] == "triage_verdict"
    assert strict["schema"] == triage_schema()
    assert strict["schema"]["additionalProperties"] is False


def test_the_task_output_schema_is_the_triage_schema() -> None:
    assert TriageTask().output_schema() == triage_schema()
