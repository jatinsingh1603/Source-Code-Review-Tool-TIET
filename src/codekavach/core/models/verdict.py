"""LLMVerdict: the structured model answer, in pseudonym space.

Owning epic: E02.

The content comes from an untrusted source: the reviewed code may have prompt-injected the
model. The type therefore bounds what can come back: lengths are limited (over-long text is
rejected, never truncated), control and bidirectional characters are removed, unknown keys are
rejected and confidence is a three-value enum. The verdict must never be evaluated, executed or
used to select file paths. Its text may contain Markdown or HTML written by the model; renderers
and the GitHub sync (E31, E34) must escape it.

Deterministic findings are never discarded because a model disagrees (ARCHITECTURE section 7):
a verdict adjusts confidence and ordering and is shown to the auditor; nothing here is
permission to drop a candidate.
"""

import copy
import re
from typing import Annotated, Any, ClassVar, Self

from pydantic import BeforeValidator, Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.enums import Confidence, ContextKind
from codekavach.core.models.taxonomy import CweId

MAX_CWES = 5
MAX_CONTEXT_REQUESTS = 3
MAX_CITED_LINES = 20
MAX_LINE = 100_000

_FORBIDDEN_CHARACTERS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]"  # keeps \t (x09) and \n (x0a)
)


def clean_untrusted_text(value: Any) -> Any:
    """Strip surrounding whitespace and remove control and bidirectional characters."""
    if isinstance(value, str):
        return _FORBIDDEN_CHARACTERS.sub("", value).strip()
    return value


UntrustedText = Annotated[str, BeforeValidator(clean_untrusted_text)]
_PLACEHOLDER_NOTE = "Names in the code are placeholders; repeat them exactly as written."


class ContextRequest(KavachModel):
    """A request for more code before the model can decide."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.UNTRUSTED

    kind: ContextKind = Field(description="State which kind of additional code you need.")
    symbol: UntrustedText = Field(
        min_length=1,
        max_length=128,
        description=f"Give the name you need more code for. {_PLACEHOLDER_NOTE}",
    )
    reason: UntrustedText = Field(
        max_length=300,
        description=f"Explain in one sentence why you need it. {_PLACEHOLDER_NOTE}",
    )


class LLMVerdict(VersionedModel):
    """The model's structured answer for one candidate, in pseudonym space."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.UNTRUSTED
    SCHEMA_VERSION: ClassVar[int] = 1

    is_vulnerable: bool | None = Field(
        description=(
            "Answer true if the code is vulnerable, false if not; use null only together with "
            "needs_context."
        )
    )
    confidence: Confidence = Field(description="Rate your confidence as low, medium or high.")
    cwe: tuple[CweId, ...] = Field(
        default=(),
        max_length=MAX_CWES,
        description="List the CWE numbers that apply, most specific first, at most five.",
    )
    reasoning: UntrustedText = Field(
        max_length=4000,
        description=(
            f"Explain the data flow and why it is or is not exploitable. {_PLACEHOLDER_NOTE}"
        ),
    )
    impact: UntrustedText = Field(
        default="",
        max_length=2000,
        description=(
            f"Describe what an attacker could achieve; leave empty if none. {_PLACEHOLDER_NOTE}"
        ),
    )
    remediation: UntrustedText = Field(
        default="",
        max_length=4000,
        description=f"Describe how to fix the code; leave empty if none. {_PLACEHOLDER_NOTE}",
    )
    needs_context: tuple[ContextRequest, ...] = Field(
        default=(),
        max_length=MAX_CONTEXT_REQUESTS,
        description="Request up to three pieces of additional code if you cannot decide.",
    )
    cited_lines: tuple[Annotated[int, Field(ge=1, le=MAX_LINE)], ...] = Field(
        default=(),
        max_length=MAX_CITED_LINES,
        description="List the line numbers of the given code that your answer relies on.",
    )

    @field_validator("cited_lines", mode="before")
    @classmethod
    def _sort_lines(cls, value: Any) -> Any:
        if isinstance(value, list | tuple) and all(
            isinstance(item, int) and not isinstance(item, bool) for item in value
        ):
            return tuple(sorted(set(value)))
        return value

    @model_validator(mode="after")
    def _check_decision(self) -> Self:
        if self.is_vulnerable is None and not self.needs_context:
            raise ValueError("is_vulnerable may be null only when needs_context is not empty")
        return self

    @classmethod
    def llm_output_schema(cls, *, inline_refs: bool = True) -> dict[str, object]:
        """Return a provider-friendly JSON Schema for structured output.

        No ``schema_version``, every object closed with ``additionalProperties: false`` and every
        property required; with ``inline_refs`` all ``$ref`` are replaced by their definitions.
        """
        schema: dict[str, Any] = copy.deepcopy(cls.model_json_schema(mode="validation"))
        schema.pop("x-schema-version", None)
        schema["properties"].pop("schema_version", None)
        definitions: dict[str, Any] = schema.get("$defs", {})
        if inline_refs:
            schema = _inline(schema, definitions)
            schema.pop("$defs", None)
        schema["properties"]["cwe"]["items"] = {"type": "integer", "minimum": 1, "maximum": 99999}
        _close_objects(schema)
        return schema


def _inline(node: Any, definitions: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[-1]
            merged = {key: value for key, value in node.items() if key != "$ref"}
            return _inline({**copy.deepcopy(definitions[name]), **merged}, definitions)
        return {key: _inline(value, definitions) for key, value in node.items() if key != "$defs"}
    if isinstance(node, list):
        return [_inline(item, definitions) for item in node]
    return node


def _close_objects(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" or "properties" in node:
            node["additionalProperties"] = False
            node["required"] = list(node.get("properties", {}))
        for value in node.values():
            _close_objects(value)
    elif isinstance(node, list):
        for item in node:
            _close_objects(item)
