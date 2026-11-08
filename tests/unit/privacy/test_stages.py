"""The privacy-prepare and llm-review stage declarations and their helpers (E13-02)."""

import json

import pytest

from codekavach.analysis.aggregate.stage import AggregateStage
from codekavach.analysis.rules.stage import AnalyseRulesStage
from codekavach.config import Settings
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.stage import Stage, StageCategory, describe_stage
from codekavach.ingest.stage import IngestStage
from codekavach.llm.stages import LlmReviewStage
from codekavach.parsing.stage import ParseStage
from codekavach.privacy.egress.guard import MIN_STATIC_CHARS, mask_static
from codekavach.privacy.egress.scanners import OriginalMatcher
from codekavach.privacy.stages import PrivacyPrepareStage, _safe_rule, _summaries, facts_of
from tests.support.factories import make_candidate, make_slice
from tests.support.payload import segment, slice_of, stub

# --- declarations -----------------------------------------------------------------------------


def test_the_prepare_stage_declares_the_documented_keys_and_category() -> None:
    info = describe_stage(PrivacyPrepareStage())
    assert info.name == "privacy-prepare"
    assert {keys.CANDIDATES, keys.FILES, keys.SYMBOLS} <= set(info.requires)
    assert set(info.optional_requires) == {keys.CALL_GRAPH}
    assert set(info.provides) == {
        keys.PAYLOADS_SANITISED,
        keys.SLICES,
        keys.DISCLOSURE,
        keys.PAYLOAD_INDEX,
    }
    assert info.category is StageCategory.PRIVACY
    assert set(info.transient_provides) == {keys.PAYLOADS_SANITISED}


def test_the_review_stage_reads_sanitised_payloads_and_no_raw_code() -> None:
    info = describe_stage(LlmReviewStage())
    assert info.name == "llm-review"
    assert set(info.requires) == {keys.PAYLOADS_SANITISED}
    assert not (set(info.requires) | set(info.optional_requires)) & keys.RAW_CODE_KEYS
    assert set(info.provides) == {keys.VERDICTS_RAW}
    assert info.category is StageCategory.LLM


def test_the_real_stages_order_themselves_into_the_documented_pipeline() -> None:
    stages: list[Stage] = [
        LlmReviewStage(),
        PrivacyPrepareStage(),
        AggregateStage(),
        AnalyseRulesStage(),
        ParseStage(),
        IngestStage(),
    ]
    plan = plan_from_stages(stages)
    assert list(plan.order) == [
        "ingest",
        "parse",
        "analyse-rules",
        "aggregate",
        "privacy-prepare",
        "llm-review",
    ]


def test_disabling_the_llm_path_drops_the_privacy_and_review_stages() -> None:
    stages: list[Stage] = [IngestStage(), ParseStage(), AnalyseRulesStage(), AggregateStage()]
    stages += [PrivacyPrepareStage(), LlmReviewStage()]
    plan = plan_from_stages(stages, llm_enabled=False)
    assert list(plan.order) == ["ingest", "parse", "analyse-rules", "aggregate"]


# --- facts ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ("py.sql-injection", "py.sql-injection"),
        ("rules/py:xss", "rules/py:xss"),
        ("a b\tc", "a_b_c"),
        ("..hidden", "hidden"),
        ("", "unknown"),
        ("éé", "unknown"),
        ("x" * 300, "x" * 128),
    ],
)
def test_a_rule_identifier_is_reduced_to_the_fact_alphabet(rule: str, expected: str) -> None:
    assert _safe_rule(rule) == expected


def test_summaries_keep_only_lines_in_the_fixed_grammar() -> None:
    lines = [
        "# unresolved",
        "def fetch(*args): ...",
        "# returns value; no sanitiser; calls sink family: sql; derived: syntactic",
        "# call os.system(user_input) now",
        "# effects unknown; derived: syntactic",
        "# returns value; no sanitiser; calls sink family: sql; derived: syntactic",
    ]
    slice_ = slice_of(segment("a.py", 1, ["x = 1"]), stubs=[stub("fetch", "\n".join(lines))])
    assert _summaries(slice_) == (
        "returns value; no sanitiser; calls sink family: sql; derived: syntactic",
        "effects unknown; derived: syntactic",
    )


def test_the_facts_carry_rule_cwe_strategy_and_the_sink_family_of_the_summaries() -> None:
    summary = "# returns value; no sanitiser; calls sink family: sql; derived: syntactic"
    slice_ = slice_of(segment("a.py", 1, ["x = 1"]), stubs=[stub("q", f"def q(): ...\n{summary}")])
    facts = facts_of(make_candidate(), slice_)
    assert facts.rule == make_candidate().rule_id
    assert facts.cwe == (89,)
    assert facts.strategy == "enclosing_function"
    assert facts.sink_family == "sql"
    assert facts.stub_summaries == (summary[2:],)


def test_a_slice_without_stubs_has_no_summaries_and_no_sink_family() -> None:
    facts = facts_of(make_candidate(), make_slice())
    assert facts.stub_summaries == () and facts.sink_family is None


# --- the guard's trusted-text mask ------------------------------------------------------------

RUBRIC = "Decide whether the reported code is really vulnerable.\nStatic analysis proposes."


def body_with(prompt: str, schema: dict[str, object]) -> bytes:
    document = {"messages": [{"content": prompt}], "schema": schema}
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_the_mask_removes_a_rubric_and_a_schema_and_the_body_stays_json() -> None:
    schema: dict[str, object] = {
        "properties": {"config_value": {"type": "string"}},
        "type": "object",
    }
    schema_text = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    body = body_with(f"{RUBRIC}\nCODE: pickle.loads(param_1)", schema)
    masked = mask_static(body, (RUBRIC, schema_text))
    assert masked is not None
    assert b"config_value" not in masked and b"Static analysis" not in masked
    assert b"pickle.loads(param_1)" in masked
    json.loads(masked)


def test_the_mask_finds_a_rubric_with_non_ascii_text_in_both_escapings() -> None:
    rubric = "Prüfen Sie, ob der gemeldete Code wirklich verwundbar ist."
    for ensure_ascii in (True, False):
        body = json.dumps({"c": rubric + " CODE"}, ensure_ascii=ensure_ascii).encode()
        masked = mask_static(body, (rubric,))
        assert masked is not None and b"CODE" in masked and "Pr" not in masked.decode()[:6] + "x"
        json.loads(masked)


def test_a_short_fragment_cannot_be_used_to_hide_text() -> None:
    short = "x" * (MIN_STATIC_CHARS - 1)
    assert mask_static(b'{"a":"' + short.encode() + b'"}', (short,)) is None


def test_no_fragment_means_no_mask() -> None:
    assert mask_static(b"{}", ()) is None


# --- the vault matcher skips whole public names -----------------------------------------------


def test_an_original_inside_a_public_name_is_not_a_hit_but_inside_another_word_it_is() -> None:
    matcher = OriginalMatcher(["conn"], public_run=lambda run: run in {"connect", "jsonify"})
    assert matcher.scan("x = db.connect()")[0] == 0
    assert matcher.scan("my_conn = 1")[0] == 1
    assert matcher.scan("connection_pool")[0] == 1


def test_without_a_public_filter_the_matcher_is_unchanged() -> None:
    assert OriginalMatcher(["conn"]).scan("db.connect()")[0] == 1


# --- the provider a scan uses -----------------------------------------------------------------


def settings_with(**llm: object) -> Settings:
    return Settings.model_validate({"llm": llm})


def test_auto_selects_the_mock_when_nothing_else_is_configured() -> None:
    provider_id, provider = settings_with().llm.selected_provider()
    assert provider_id == "mock" and provider.kind.value == "mock"


def test_auto_skips_offline_disabled_and_forbidden_remote_providers() -> None:
    providers = {
        "off": {
            "kind": "ollama",
            "model": "m",
            "base_url": "http://127.0.0.1:11434",
            "enabled": False,
        },
        "local": {"kind": "ollama", "model": "llama3:8b", "base_url": "http://127.0.0.1:11434"},
    }
    chosen, _ = settings_with(providers=providers).llm.selected_provider()
    assert chosen == "local"


def test_a_named_default_provider_wins() -> None:
    chosen, _ = settings_with(default_provider="mock").llm.selected_provider()
    assert chosen == "mock"
