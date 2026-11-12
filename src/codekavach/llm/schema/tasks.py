"""Answer models and strict JSON Schemas of the review tasks other than triage (E23-02).

Owning epic: E23. Every answer is untrusted: text fields go through ``clean_untrusted_text``,
lengths are capped (over-long text is rejected, never truncated), unknown keys are rejected, and
the free-text ``analysis`` field comes first so that a provider that honours property order
generates the reasoning before the conclusions (``docs/research/INSIGHTS.md`` section 1.4).

``schema_for(model)`` returns a provider-ready schema: every object closed with
``additionalProperties: false`` and every property required, which is what strict structured
output modes (OpenAI Responses ``json_schema`` with ``strict: true``) demand.
"""

import copy
import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from codekavach.core.models.enums import Confidence
from codekavach.core.models.verdict import MAX_LINE, ContextRequest, UntrustedText

Severity = Literal["critical", "high", "medium", "low", "info"]
Cwe = Annotated[int, Field(ge=0, le=99999)]
Short = Annotated[UntrustedText, Field(max_length=300)]
Medium = Annotated[UntrustedText, Field(max_length=1500)]


class _Answer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis: Annotated[UntrustedText, Field(max_length=3000)] = Field(
        description="Think step by step here first; refer to stand-in names exactly."
    )


class ExplainAnswer(_Answer):
    """The impact explanation of one confirmed finding."""

    impact: Medium = Field(description="What an attacker can achieve, concretely.")
    attack_scenario: Medium = Field(description="One realistic attack sequence.")
    affected_assets: Annotated[tuple[Short, ...], Field(max_length=6)] = Field(
        description="What is exposed or affected."
    )
    severity: Severity = Field(description="Severity judged on the code shown.")
    exploit_preconditions: Medium = Field(description="What must hold for the attack to work.")


class RemediateAnswer(_Answer):
    """Fix guidance and a secure code example, in pseudonym space."""

    guidance: Annotated[UntrustedText, Field(max_length=2000)] = Field(
        description="The fix in plain ordered steps."
    )
    secure_example: Annotated[UntrustedText, Field(max_length=2500)] = Field(
        description="Corrected version of the vulnerable lines, using the same stand-in names."
    )
    secure_example_language: Annotated[UntrustedText, Field(max_length=32)] = Field(
        description="Name of the programming language of the example."
    )
    defence_in_depth: Annotated[tuple[Short, ...], Field(max_length=3)] = Field(
        description="Additional hardening measures."
    )


class ClassifyAnswer(_Answer):
    """The CWE classification of one weakness."""

    primary_cwe: Cwe = Field(description="Most specific CWE number; 0 if the code is not weak.")
    related_cwes: Annotated[tuple[Cwe, ...], Field(max_length=3)] = Field(
        description="Up to three related CWE numbers."
    )
    weakness_class: Annotated[UntrustedText, Field(max_length=80)] = Field(
        description="Short class name, for example injection."
    )
    confidence: Confidence = Field(description="low, medium or high.")


class Hotspot(BaseModel):
    """One suspected security hotspot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    line: Annotated[int, Field(ge=1, le=100_000)] = Field(description="Line number in the code.")
    cwe: Cwe = Field(description="CWE number that applies.")
    title: Annotated[UntrustedText, Field(max_length=120)] = Field(description="Short title.")
    reason: Short = Field(description="One concrete sentence.")


class DiscoverAnswer(_Answer):
    """Hotspots found in a slice no rule flagged."""

    hotspots: Annotated[tuple[Hotspot, ...], Field(max_length=5)] = Field(
        description="At most five hotspots; empty when nothing stands out."
    )


class SummariseAnswer(_Answer):
    """The executive summary of a review, written from non-code facts."""

    headline: Short = Field(description="One sentence headline.")
    summary: Annotated[UntrustedText, Field(max_length=1200)] = Field(
        description="At most 120 words for a non-technical reader."
    )
    top_risks: Annotated[tuple[Short, ...], Field(max_length=5)] = Field(
        description="Up to five short risk statements."
    )
    next_steps: Annotated[tuple[Short, ...], Field(max_length=5)] = Field(
        description="Up to five ordered, actionable next steps."
    )
    overall_risk: Literal["critical", "high", "medium", "low"] = Field(
        description="Overall risk posture."
    )


# The combined review (``review`` task): triage, impact and remediation of one candidate in one
# answer, for providers that serve one request at a time. The request still carries exactly one
# payload. The triage fields mirror ``LLMVerdict`` and come first, ``reasoning`` before everything
# else; the enrichment fields are empty strings when the code is not vulnerable. The review flow
# folds the answer into an ``LLMVerdict`` in pseudonym space (``llm.review.verdict_of``), which
# the output defence, consensus and the restore stage then treat like a triage verdict. The
# docstring is the schema description the provider sees, so it stays one line.
class ReviewAnswer(BaseModel):
    """Triage verdict, impact and remediation of one finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reasoning: Annotated[UntrustedText, Field(max_length=4000)] = Field(
        description="Think step by step here first; refer to stand-in names exactly."
    )
    is_vulnerable: bool | None = Field(
        description="true if vulnerable, false if not; null only together with needs_context."
    )
    confidence: Confidence = Field(description="low, medium or high.")
    cwe: Annotated[tuple[Cwe, ...], Field(max_length=5)] = Field(
        description="Applicable CWE numbers, most specific first, at most five."
    )
    cited_lines: Annotated[
        tuple[Annotated[int, Field(ge=1, le=MAX_LINE)], ...], Field(max_length=20)
    ] = Field(description="Line numbers of the given code the answer relies on.")
    needs_context: Annotated[tuple[ContextRequest, ...], Field(max_length=3)] = Field(
        description="Up to three pieces of additional code, only if you cannot decide."
    )
    severity: Severity = Field(description="Severity judged on the code shown.")
    impact: Medium = Field(description="What an attacker can achieve; empty if not vulnerable.")
    exploit_scenario: Medium = Field(
        description="One realistic attack sequence; empty if not vulnerable."
    )
    remediation: Annotated[UntrustedText, Field(max_length=2000)] = Field(
        description="The fix in plain ordered steps; empty if not vulnerable."
    )
    secure_example: Annotated[UntrustedText, Field(max_length=2500)] = Field(
        description="Corrected vulnerable lines with the same stand-in names; empty if none."
    )
    secure_example_language: Annotated[UntrustedText, Field(max_length=32)] = Field(
        description="Programming language of the example; empty if none."
    )


def _inline(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[-1]
            extra = {k: v for k, v in node.items() if k != "$ref"}
            return _inline({**copy.deepcopy(defs[name]), **extra}, defs)
        return {k: _inline(v, defs) for k, v in node.items() if k not in ("$defs", "title")}
    if isinstance(node, list):
        return [_inline(item, defs) for item in node]
    return node


def _close(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" or "properties" in node:
            node["additionalProperties"] = False
            node["required"] = list(node.get("properties", {}))
        for value in node.values():
            _close(value)
    elif isinstance(node, list):
        for item in node:
            _close(item)


def schema_for(model: type[BaseModel]) -> dict[str, object]:
    """The strict-mode JSON Schema of ``model`` (a fresh copy on every call)."""
    raw = model.model_json_schema(mode="validation")
    schema: dict[str, Any] = _inline(raw, raw.get("$defs", {}))
    _close(schema)
    # JSON Schema keywords that strict modes reject: the length bounds stay in the prose.
    _strip_unsupported(schema)
    return schema


_UNSUPPORTED = frozenset({"maxLength", "minLength", "maxItems", "minItems", "minimum", "maximum"})


def _strip_unsupported(node: Any) -> None:
    if isinstance(node, dict):
        for key in _UNSUPPORTED & node.keys():
            del node[key]
        for value in node.values():
            _strip_unsupported(value)
    elif isinstance(node, list):
        for item in node:
            _strip_unsupported(item)


def parse_answer[A: BaseModel](model: type[A], text: str) -> A:
    """Validate ``text`` (a JSON object) as ``model``.

    Raises:
        ValueError: not JSON, or it breaks the model. The message never repeats the text.
    """
    try:
        return model.model_validate(json.loads(text))
    except json.JSONDecodeError:
        raise ValueError("answer_not_json") from None
    except ValueError:
        raise ValueError("answer_violates_schema") from None
