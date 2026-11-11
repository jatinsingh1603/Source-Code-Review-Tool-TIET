"""Rule lookup for one SARIF run (E14-02).

Owning epic: E14. ``RuleIndex`` is built once per run and resolves a result's rule by
``result.rule`` (id, index, tool component), ``result.ruleIndex`` and ``result.ruleId`` against the
driver's rules and the extensions' rules, in that order.
"""

from codekavach.analysis.engines.sarif.model import (
    ReportingDescriptor,
    ReportingDescriptorReference,
    Result,
    Run,
    ToolComponent,
)


class RuleIndex:
    """The rules of one run, indexed by position and by id."""

    def __init__(self, run: Run) -> None:
        tool = run.tool
        driver = tool.driver if tool and tool.driver else ToolComponent()
        self._components: list[ToolComponent] = [driver, *(tool.extensions if tool else ())]
        self._by_id: list[dict[str, ReportingDescriptor]] = []
        for component in self._components:
            ids: dict[str, ReportingDescriptor] = {}
            for rule in component.rules:
                if rule.id is not None:
                    ids.setdefault(rule.id, rule)
            self._by_id.append(ids)

    def _component_of(self, reference: ReportingDescriptorReference | None) -> int:
        component = reference.tool_component if reference else None
        if component is None:
            return 0
        extensions = len(self._components) - 1
        if component.index is not None and 0 <= component.index < extensions:
            return component.index + 1
        if component.name is not None:
            for position, candidate in enumerate(self._components):
                if candidate.name == component.name:
                    return position
        return 0

    def lookup(self, result: Result) -> ReportingDescriptor | None:
        """The rule descriptor for ``result``, or ``None`` when the log does not describe it."""
        reference = result.rule
        position = self._component_of(reference)
        rules = self._components[position].rules
        index = reference.index if reference and reference.index is not None else result.rule_index
        if index is not None and 0 <= index < len(rules):
            return rules[index]
        rule_id = result.rule_id or (reference.id if reference else None)
        if rule_id is None:
            return None
        found = self._by_id[position].get(rule_id)
        if found is not None:
            return found
        for ids in self._by_id:
            if rule_id in ids:
                return ids[rule_id]
        return None

    def rule_id_of(self, result: Result, rule: ReportingDescriptor | None) -> str | None:
        """The id of the rule: the result's own, else the descriptor's."""
        if result.rule_id:
            return result.rule_id
        if result.rule and result.rule.id:
            return result.rule.id
        return rule.id if rule is not None else None
