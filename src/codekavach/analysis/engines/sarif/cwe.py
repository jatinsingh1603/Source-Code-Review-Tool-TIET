"""CWE extraction from a SARIF result and its rule (E14-02).

Owning epic: E14. Engines record a CWE in at least four places, so they are tried in order and the
first usable hit wins:

1. ``cwe`` in the rule or result properties (a number, ``"CWE-89"``, ``"cwe-089"`` or a list);
2. ``tags`` entries such as ``CWE-89``, ``external/cwe/cwe-089`` or ``cwe:89``;
3. taxonomy references: ``rule.relationships[].target`` and ``result.taxa[]`` that point into a
   taxonomy named ``CWE``;
4. the fallback table, by exact rule id and then by the longest rule-id prefix.

Values go through ``parse_cwe``, are de-duplicated in first-seen order and must lie between 1 and
1425. A Pillar-level weakness is not a mapping (MITRE's guidance): a rule that yields only Pillars
gets an empty result and ``unmapped`` set, never a default such as CWE-20.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from codekavach.analysis.engines.sarif.model import (
    ReportingDescriptor,
    ReportingDescriptorReference,
    Result,
    Run,
)
from codekavach.analysis.engines.sarif.tables import CweFallback, default_cwe_fallback
from codekavach.core.models.taxonomy import parse_cwe

MAX_CWE: Final = 1425
PILLARS: Final = frozenset({284, 435, 664, 682, 691, 693, 697, 703, 707, 710})
SOURCES: Final = ("properties", "tags", "taxonomy", "fallback")
_NUMBER = re.compile(r"^\s*(?:cwe[-_ :/]*)?0*(\d{1,5})(?!\d)", re.IGNORECASE)
_TAG = re.compile(
    r"^(?:external/)?cwe(?:[-/:]|/cwe-)0*(\d{1,5})(?!\d)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CweExtraction:
    """The weaknesses found, the strategy that found them and whether only a Pillar was named."""

    cwe: tuple[int, ...] = ()
    source: str | None = None
    unmapped: bool = False


def _numbers(values: Iterable[int | None]) -> tuple[list[int], bool]:
    """Valid, de-duplicated numbers in order, and whether a Pillar was dropped."""
    found: dict[int, None] = {}
    pillar = False
    for value in values:
        if value is None:
            continue
        try:
            number = parse_cwe(value)
        except ValueError:
            continue
        if not 1 <= number <= MAX_CWE:
            continue
        if number in PILLARS:
            pillar = True
            continue
        found.setdefault(number, None)
    return list(found), pillar


def _from_value(value: object) -> list[int | None]:
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, str):
        match = _NUMBER.match(value)
        return [int(match.group(1))] if match else []
    if isinstance(value, list | tuple):
        return [n for item in value for n in _from_value(item)]
    return []


def _from_tags(value: object) -> list[int | None]:
    if not isinstance(value, list | tuple):
        return []
    out: list[int | None] = []
    for tag in value:
        match = _TAG.match(tag.strip()) if isinstance(tag, str) else None
        if match:
            out.append(int(match.group(1)))
    return out


def _is_cwe_taxonomy(reference: ReportingDescriptorReference, run: Run) -> bool:
    component = reference.tool_component
    if component is None:
        return False
    if component.name is not None:
        return component.name.upper() == "CWE"
    if component.index is not None and 0 <= component.index < len(run.taxonomies):
        name = run.taxonomies[component.index].name
        return name is not None and name.upper() == "CWE"
    return False


def _from_taxonomy(rule: ReportingDescriptor | None, result: Result, run: Run) -> list[int | None]:
    references = [r.target for r in rule.relationships if r.target] if rule else []
    references.extend(result.taxa)
    out: list[int | None] = []
    for reference in references:
        if reference.id is not None and _is_cwe_taxonomy(reference, run):
            out.extend(_from_value(reference.id))
    return out


def extract_cwe_details(
    rule: ReportingDescriptor | None,
    result: Result,
    engine_id: str,
    *,
    run: Run | None = None,
    rule_id: str | None = None,
    fallback: CweFallback | None = None,
) -> CweExtraction:
    """Find the weaknesses of ``result`` with the four strategies, in order."""
    run = run or Run()
    rule_props: Mapping[str, Any] = rule.properties if rule else {}
    strategies: list[tuple[str, list[int | None]]] = [
        (
            "properties",
            _from_value(result.properties.get("cwe")) + _from_value(rule_props.get("cwe")),
        ),
        (
            "tags",
            _from_tags(result.properties.get("tags")) + _from_tags(rule_props.get("tags")),
        ),
        ("taxonomy", _from_taxonomy(rule, result, run)),
    ]
    identifier = rule_id or result.rule_id or (rule.id if rule else None)
    if identifier:
        table = fallback if fallback is not None else default_cwe_fallback()
        strategies.append(("fallback", list(table.lookup(engine_id, identifier))))
    pillar_seen = False
    for source, raw in strategies:
        numbers, pillar = _numbers(raw)
        pillar_seen = pillar_seen or pillar
        if numbers:
            return CweExtraction(tuple(numbers), source)
    return CweExtraction(unmapped=pillar_seen)


def extract_cwe(
    rule: ReportingDescriptor | None,
    result: Result,
    engine_id: str,
    *,
    run: Run | None = None,
    fallback: CweFallback | None = None,
) -> tuple[int, ...]:
    """The weaknesses of ``result``; see ``extract_cwe_details`` for the strategy that fired."""
    return extract_cwe_details(rule, result, engine_id, run=run, fallback=fallback).cwe
