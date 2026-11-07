"""The triage output schema, built on ``LLMVerdict.llm_output_schema()``.

Owning epic: E13. MVP; extended by E23, which adds the schemas of the other tasks.

**The free-text analysis comes first.** The model is asked for ``reasoning`` before the verdict
fields, because an answer that commits to ``is_vulnerable`` first and explains afterwards tends to
rationalise it (``docs/research/INSIGHTS.md`` section 1.4). Providers that honour property order in
structured output therefore generate the analysis first; for the others the order is still the
order the prompt asks for.

``triage_schema(strict=True)`` is the variant for providers with a strict structured-output mode:
the same schema wrapped in the envelope those modes expect (a name and ``strict: true``), with
every property required and no additional properties, which ``llm_output_schema`` already
guarantees.
"""

from typing import Any, Final

from codekavach.core.models.verdict import LLMVerdict

SCHEMA_NAME: Final = "triage_verdict"
FIRST_FIELD: Final = "reasoning"


def _reordered(schema: dict[str, object]) -> dict[str, object]:
    properties: dict[str, Any] = dict(schema["properties"])  # type: ignore[call-overload]
    ordered = {FIRST_FIELD: properties[FIRST_FIELD]}
    ordered.update({name: value for name, value in properties.items() if name != FIRST_FIELD})
    required: list[str] = list(schema.get("required", []))  # type: ignore[call-overload]
    schema_out = dict(schema)
    schema_out["properties"] = ordered
    schema_out["required"] = [FIRST_FIELD, *(name for name in required if name != FIRST_FIELD)]
    return schema_out


def triage_schema(*, strict: bool = False) -> dict[str, object]:
    """The JSON Schema of a triage answer; with ``strict`` the strict-mode envelope around it."""
    schema = _reordered(LLMVerdict.llm_output_schema())
    if strict:
        return {"name": SCHEMA_NAME, "strict": True, "schema": schema}
    return schema
