"""Severity and confidence normalisation for SARIF results (E14-02).

Owning epic: E14. Severity starts from the SARIF ``level`` (through ``Severity.from_sarif_level``),
is replaced by ``security-severity`` (a 0 to 10 number, GitHub's convention) when the result or rule
carries one, and then the per-engine table has the last word: a rule row wins, and a
``default_level_map`` replaces the generic level mapping for that engine. The outcome is only ever
``Candidate.engine_severity``, an opinion; the verdict is decided elsewhere (E29).

Confidence comes from engine-specific properties named in the table, or from the ``precision`` and
``confidence`` properties, and is otherwise ``None``.
"""

from typing import Any, Final

from codekavach.analysis.engines.sarif.model import ReportingDescriptor, Result
from codekavach.analysis.engines.sarif.tables import (
    SeverityTable,
    default_severity_table,
    longest_prefix,
)
from codekavach.core.models.enums import Confidence, Severity

SECURITY_SEVERITY: Final = "security-severity"
GENERIC_CONFIDENCE_KEYS: Final = ("precision", "confidence")
_GENERIC_WORDS: Final = {
    "very-high": Confidence.HIGH,
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
    "very-low": Confidence.LOW,
}


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def normalise_severity(
    result: Result,
    rule: ReportingDescriptor | None,
    engine_id: str,
    *,
    table: SeverityTable | None = None,
    rule_id: str | None = None,
) -> Severity:
    """The engine's severity for ``result`` as a ``Severity``."""
    rows = (table if table is not None else default_severity_table()).engines.get(engine_id)
    identifier = rule_id or result.rule_id or (rule.id if rule else None)
    if rows is not None and identifier:
        override = longest_prefix(rows.rules, identifier)
        if override is not None:
            return override
    score = _number(result.properties.get(SECURITY_SEVERITY))
    if score is None and rule is not None:
        score = _number(rule.properties.get(SECURITY_SEVERITY))
    if score is not None:
        try:
            return Severity.from_cvss_score(score)
        except ValueError:
            pass
    default = rule.default_configuration.level if rule and rule.default_configuration else None
    level = result.level or default or "warning"
    if rows is not None and level in rows.level_map:
        return rows.level_map[level]
    try:
        return Severity.from_sarif_level(level)
    except ValueError:
        return Severity.MEDIUM


def normalise_confidence(
    result: Result,
    rule: ReportingDescriptor | None,
    engine_id: str,
    *,
    table: SeverityTable | None = None,
) -> Confidence | None:
    """The engine's own confidence, or ``None`` when it states none."""
    rows = (table if table is not None else default_severity_table()).engines.get(engine_id)
    keys = (*(rows.confidence_keys if rows else ()), *GENERIC_CONFIDENCE_KEYS)
    sources = (result.properties, rule.properties if rule else {})
    for key in keys:
        for properties in sources:
            value = properties.get(key)
            if value is None or isinstance(value, bool):
                continue
            word = str(value).strip().lower()
            if rows is not None and word in rows.confidence_map:
                return rows.confidence_map[word]
            if word in _GENERIC_WORDS:
                return _GENERIC_WORDS[word]
            number = _number(value)
            if number is not None and 0.0 <= number <= 1.0:
                return Confidence.from_score(number)
    return None
