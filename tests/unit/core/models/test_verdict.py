import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import Confidence, DataClassification
from codekavach.core.models.enums import ContextKind
from codekavach.core.models.verdict import ContextRequest, LLMVerdict
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden" / "llm_verdict_output_schema.json"
RLO = chr(0x202E)
LRI = chr(0x2066)

EXAMPLE = {
    "is_vulnerable": True,
    "confidence": "high",
    "cwe": [89],
    "reasoning": (
        "param_2 flows from fn_1's request argument into cursor.execute through string "
        "concatenation without parameter binding."
    ),
    "impact": (
        "An attacker controlling param_2 can read or modify rows in the table queried by fn_3."
    ),
    "remediation": "Use a parameterised query: cursor.execute(const_4, (param_2,)).",
    "needs_context": [],
    "cited_lines": [2],
}


def verdict(**overrides: Any) -> LLMVerdict:
    return LLMVerdict.model_validate_json(json.dumps({**EXAMPLE, **overrides}))


def test_example_validates() -> None:
    parsed = verdict()
    assert parsed.is_vulnerable is True
    assert parsed.confidence is Confidence.HIGH
    assert parsed.cwe == (89,)
    assert verdict(cwe=["CWE-89"]).cwe == (89,)
    assert LLMVerdict.DATA_CLASSIFICATION is DataClassification.UNTRUSTED
    assert ContextRequest.DATA_CLASSIFICATION is DataClassification.UNTRUSTED


def test_cited_lines_sorted_and_deduplicated() -> None:
    assert verdict(cited_lines=[7, 2, 7]).cited_lines == (2, 7)


@pytest.mark.parametrize("lines", [[0], [-1], [100001], list(range(1, 22))])
def test_invalid_cited_lines(lines: list[int]) -> None:
    with pytest.raises(ValidationError):
        verdict(cited_lines=lines)


def _context(n: int) -> list[dict[str, str]]:
    return [{"kind": "callee_body", "symbol": f"fn_{i}", "reason": "need body"} for i in range(n)]


def test_null_decision_needs_context() -> None:
    with pytest.raises(ValidationError, match="needs_context"):
        verdict(is_vulnerable=None)
    undecided = verdict(is_vulnerable=None, needs_context=_context(1))
    assert undecided.needs_context[0].kind is ContextKind.CALLEE_BODY


@pytest.mark.parametrize(
    "overrides",
    [
        {"cwe": [1, 2, 3, 4, 5, 6]},
        {"needs_context": _context(4)},
        {"reasoning": "x" * 4001},
        {"impact": "x" * 2001},
        {"remediation": "x" * 4001},
        {"unknown": 1},
        {"confidence": "very high"},
        {"cwe": ["SQLi"]},
    ],
    ids=["cwes", "context", "reasoning", "impact", "remediation", "unknown", "confidence", "cwe"],
)
def test_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        verdict(**overrides)


def test_context_request_bounds() -> None:
    with pytest.raises(ValidationError):
        ContextRequest(kind=ContextKind.OTHER, symbol="", reason="r")
    with pytest.raises(ValidationError):
        ContextRequest(kind=ContextKind.OTHER, symbol="x" * 129, reason="r")
    with pytest.raises(ValidationError):
        ContextRequest(kind=ContextKind.OTHER, symbol="s", reason="x" * 301)


def test_control_and_bidi_characters_removed() -> None:
    dirty = f"  a\x00b{RLO}c{LRI}d\x1be\x7f\tf\ng  "
    parsed = verdict(reasoning=dirty, impact=dirty, remediation=dirty)
    for text in (parsed.reasoning, parsed.impact, parsed.remediation):
        assert text == "abcde\tf\ng"
    request = ContextRequest(kind=ContextKind.CALLER, symbol=f" fn{RLO}_1 ", reason="x\x00y")
    assert request.symbol == "fn_1"
    assert request.reason == "xy"


def test_over_long_text_is_rejected_not_truncated() -> None:
    with pytest.raises(ValidationError):
        verdict(reasoning="y" * 4001)


# output schema


def _walk(node: object) -> list[object]:
    nodes = [node]
    if isinstance(node, dict):
        for value in node.values():
            nodes.extend(_walk(value))
    elif isinstance(node, list):
        for value in node:
            nodes.extend(_walk(value))
    return nodes


def test_output_schema_shape() -> None:
    schema = LLMVerdict.llm_output_schema()
    text = json.dumps(schema)
    assert "$ref" not in text
    assert "$defs" not in text
    assert "schema_version" not in text
    assert "x-schema-version" not in schema
    for node in _walk(schema):
        if isinstance(node, dict) and "properties" in node:
            assert node["additionalProperties"] is False
            assert node["required"] == list(node["properties"])
    assert schema["properties"]["cwe"]["items"]["type"] == "integer"  # type: ignore[index]


def test_output_schema_keeps_refs_when_asked() -> None:
    assert "$defs" in LLMVerdict.llm_output_schema(inline_refs=False)


def test_output_schema_golden() -> None:
    schema = LLMVerdict.llm_output_schema()
    assert_matches_golden(json.dumps(schema, indent=2, sort_keys=True) + "\n", GOLDEN)


def test_example_fits_output_schema() -> None:
    schema: dict[str, Any] = LLMVerdict.llm_output_schema()
    properties = schema["properties"]
    assert set(EXAMPLE) == set(properties)
    assert set(schema["required"]) == set(EXAMPLE)
    type_names = {bool: "boolean", str: "string", list: "array", int: "integer"}
    for key, value in EXAMPLE.items():
        spec = properties[key]
        allowed = {option["type"] for option in spec.get("anyOf", [spec])}
        assert type_names[type(value)] in allowed, key
        if "enum" in spec:
            assert value in spec["enum"]
        if "maxLength" in spec:
            assert len(value) <= spec["maxLength"]  # type: ignore[arg-type]


def test_every_field_has_a_description() -> None:
    for model in (LLMVerdict, ContextRequest):
        properties = model.model_json_schema()["properties"]
        for name, spec in properties.items():
            if name == "schema_version":
                continue
            assert spec.get("description"), f"{model.__name__}.{name} has no description"


# properties

_FORBIDDEN = {chr(c) for c in [*range(0x09), *range(0x0B, 0x20), 0x7F]} | {
    chr(c) for c in [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]
}
_text = st.text(max_size=60)


@st.composite
def verdicts(draw: st.DrawFn) -> dict[str, Any]:
    requests = draw(
        st.lists(
            st.fixed_dictionaries(
                {
                    "kind": st.sampled_from([k.value for k in ContextKind]),
                    "symbol": st.from_regex(r"[a-z]{1,8}_[0-9]{1,3}", fullmatch=True),
                    "reason": _text,
                }
            ),
            max_size=3,
        )
    )
    decided = draw(st.booleans()) or not requests
    return {
        "is_vulnerable": draw(st.booleans()) if decided else None,
        "confidence": draw(st.sampled_from(["low", "medium", "high"])),
        "cwe": draw(st.lists(st.integers(1, 99999), max_size=5)),
        "reasoning": draw(_text),
        "impact": draw(_text),
        "remediation": draw(_text),
        "needs_context": requests,
        "cited_lines": draw(st.lists(st.integers(1, 100_000), max_size=20)),
    }


@given(verdicts())
def test_round_trip_and_clean_text(data: dict[str, Any]) -> None:
    parsed = LLMVerdict.model_validate(data)
    assert LLMVerdict.model_validate_json(parsed.model_dump_json()) == parsed
    texts = [parsed.reasoning, parsed.impact, parsed.remediation]
    texts += [r.reason for r in parsed.needs_context] + [r.symbol for r in parsed.needs_context]
    for text in texts:
        assert not (set(text) & _FORBIDDEN)
