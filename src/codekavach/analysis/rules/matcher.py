"""The structural matcher: rules over tree-sitter trees (E16-02).

Owning epic: E16. ``Matcher.match_file(parsed, rules)`` finds the nodes where a rule's match block
holds and returns one ``RuleMatch`` per node.

**Clause semantics at one anchor node.** A rule matches at node N when

* some ``any`` clause matches at N (when there is any ``any`` clause),
* every ``all`` clause holds at N, and
* no ``none`` clause holds at N.

``none`` is evaluated at the same anchor, never over the whole file, so a nearby unrelated match
cannot hide a real finding. A ``pattern`` clause matches when its compiled pattern matches with N
as its root; ``pattern_inside`` when some ancestor of N (or N) matches it; ``pattern_not_inside``
when none does; ``pattern_regex`` when the expression is found in N's text; ``ref`` when the named
rule matches at N. Candidate anchors are the nodes of the kinds the positive ``pattern`` clauses
start with, found in one pass over the tree for all rules. A rule whose only positive clauses are
regular expressions matches text spans instead and ignores ``all`` and ``none``.

**Metavariables.** ``$X`` binds one subtree, ``$...X`` a run of siblings. A name used twice must
bind identical text (whitespace collapsed). ``_`` matches one node and ``...`` any run of
siblings, including statements, with the comma beside it in an argument list.

**Taint rules.** A rule with a ``TaintSpec`` is handed to the ``TaintEngine`` when one is
configured. Without one, the rule falls back to its patterns (or, when it has none, to the patterns
of its sink entries) and every match carries ``rule.taint = unavailable``.

**Budget.** Each rule gets a wall-clock budget; a rule that exceeds it, or raises, is reported as a
failure and the other rules still run.
"""

import re
import time
from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol

from tree_sitter import Node

from codekavach.analysis.rules.compile import (
    ANY_STRING,
    ITEM_NODE,
    ITEM_VAR,
    LEAF,
    METAVAR,
    STRING_KINDS,
    WILDCARD_NODE,
    CompiledPattern,
    PatternSyntaxError,
    PItem,
    PNode,
    compile_pattern,
    grammar_version,
    significant,
    unwrap,
)
from codekavach.analysis.rules.constraints import holds, normalised
from codekavach.analysis.rules.dsl import PatternClause, RuleDef
from codekavach.analysis.rules.pack import CatalogueEntry, CatalogueKind, RulePack
from codekavach.analysis.rules.resolve import chain, import_aliases, symbol_match
from codekavach.analysis.rules.syntax import FUNCTION_TYPES, enclosing_function
from codekavach.core.log import get_logger
from codekavach.core.models import Language
from codekavach.core.models.taint import TaintPath
from codekavach.parsing.models import ParsedFile

MATCHER_VERSION: Final = "2"
CALL_NODES: Final = frozenset({"call", "call_expression"})
DEFAULT_RULE_SECONDS: Final = 2.0
MAX_STEPS_PER_CLOCK_CHECK: Final = 512
_TRIVIA: Final = frozenset({"comment"})
_WRAPPERS: Final = frozenset({"expression_statement"})
_EMPTY_STRING: Final = re.compile(rb"[A-Za-z]{0,2}(\"\"\"|'''|\"|'|`)\.\.\.\1")
_log = get_logger("codekavach.analysis.rules.matcher")


class RuleTimeoutError(Exception):
    """A rule used up its wall-clock budget."""


@dataclass(frozen=True, slots=True)
class Binding:
    """What a metavariable matched."""

    nodes: tuple[Node, ...]
    text: str


Env = dict[str, Binding]


@dataclass(frozen=True, slots=True)
class TaintHit:
    """A sink reached by tainted data, as reported by the taint engine."""

    start_byte: int
    end_byte: int
    path: TaintPath | None = None


class TaintEngine(Protocol):
    """What the matcher needs from the taint engine of E17."""

    def find_paths(
        self,
        parsed: ParsedFile,
        sources: Sequence[CatalogueEntry],
        sinks: Sequence[CatalogueEntry],
        sanitisers: Sequence[CatalogueEntry],
    ) -> Sequence[TaintHit]:
        """Sinks that tainted data from a source reaches without passing a sanitiser."""
        ...


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """One place a rule matched. Client data: it holds the matched code through ``bindings``."""

    rule: RuleDef
    start_byte: int
    end_byte: int
    node_type: str
    bindings: Mapping[str, str] = field(default_factory=dict)
    taint_path: TaintPath | None = None
    taint_unavailable: bool = False
    properties: tuple[tuple[str, str], ...] = ()
    partial: bool = False


@dataclass(frozen=True, slots=True)
class RuleFailure:
    """A rule that raised or ran out of time; ``code`` is the item failure code."""

    rule_id: str
    code: str


@dataclass(frozen=True, slots=True)
class FileResult:
    """The matches and the failures of one file."""

    matches: list[RuleMatch]
    failures: list[RuleFailure]


def _norm(nodes: Sequence[Node]) -> str:
    return " ".join(" ".join(normalised(node) for node in nodes).split())


def _scope_of(node: Node) -> Node:
    """The function ``node`` is or sits in (with its decorators), else the root of its tree."""
    found = node if node.type in FUNCTION_TYPES else enclosing_function(node)
    if found is not None:
        parent = found.parent
        return parent if parent is not None and parent.type == "decorated_definition" else found
    while node.parent is not None:
        node = node.parent
    return node


class Matcher:
    """Matches rules against parsed files; holds the catalogues and the optional taint engine."""

    def __init__(
        self,
        *,
        catalogues: Mapping[str, tuple[Language, CatalogueEntry]] | None = None,
        provenance: Mapping[str, tuple[str, str]] | None = None,
        taint_engine: TaintEngine | None = None,
        rule_seconds: float = DEFAULT_RULE_SECONDS,
    ) -> None:
        self.catalogues = dict(catalogues or {})
        self.provenance = dict(provenance or {})
        self.taint_engine = taint_engine
        self.rule_seconds = rule_seconds
        self._deadline = 0.0
        self._steps = 0
        self._rules: dict[str, RuleDef] = {}
        self._language = Language.PYTHON
        self._stack: list[str] = []
        self._patterns: dict[tuple[str, Language], CompiledPattern] = {}
        self._aliases: dict[str, str] = {}
        self._prefixes: dict[
            tuple[str, Language], tuple[dict[str, list[CatalogueEntry]], list[str]]
        ] = {}
        self._partial = False
        self._props: dict[str, str] = {}
        self._cl_partial = False
        self._cl_props: dict[str, str] = {}

    @classmethod
    def for_packs(
        cls,
        packs: Sequence[RulePack],
        *,
        taint_engine: TaintEngine | None = None,
        rule_seconds: float = DEFAULT_RULE_SECONDS,
    ) -> "tuple[Matcher, list[RuleDef]]":
        """A matcher with the catalogues and provenance of ``packs``, and all their rules."""
        catalogues: dict[str, tuple[Language, CatalogueEntry]] = {}
        provenance: dict[str, tuple[str, str]] = {}
        rules: list[RuleDef] = []
        for pack in packs:
            for catalogue in pack.catalogues:
                language = _language(catalogue.language)
                for entry in catalogue.items():
                    if language is not None:
                        catalogues[entry.id] = (language, entry)
            for rule in pack.rules:
                provenance[rule.id] = (pack.id, pack.version)
                rules.append(rule)
        matcher = cls(
            catalogues=catalogues,
            provenance=provenance,
            taint_engine=taint_engine,
            rule_seconds=rule_seconds,
        )
        return matcher, rules

    def cache_key(self, rules: Sequence[RuleDef], language: Language, checksums: str) -> str:
        """What a cached result of this matcher over a file depends on besides the file."""
        return f"{MATCHER_VERSION}:{grammar_version(language)}:{checksums}:{len(rules)}"

    # --- budget ---------------------------------------------------------------------------

    def _tick(self) -> None:
        self._steps += 1
        if self._steps % MAX_STEPS_PER_CLOCK_CHECK == 0 and time.monotonic() > self._deadline:
            raise RuleTimeoutError

    def _pattern(self, text: str) -> CompiledPattern:
        key = (text, self._language)
        found = self._patterns.get(key)
        if found is None:
            found = self._patterns[key] = compile_pattern(text, self._language)
        return found

    # --- structural matching --------------------------------------------------------------

    def _bind(self, env: Env, name: str, nodes: tuple[Node, ...]) -> Env | None:
        text = _norm(nodes)
        current = env.get(name)
        if current is not None:
            return env if current.text == text else None
        return {**env, name: Binding(nodes, text)}

    def match_node(self, pattern: PNode, target: Node, env: Env) -> Env | None:
        """Match one pattern node against one target node, extending ``env`` or failing."""
        kind = pattern.kind
        if kind == METAVAR:
            return self._bind(env, pattern.name, (target,)) if target.is_named else None
        if kind == WILDCARD_NODE:
            return env if target.is_named else None
        if kind == ANY_STRING:
            return env if target.type in STRING_KINDS else None
        if pattern.type != target.type:
            return None
        if kind == LEAF:
            return env if target.text == pattern.text else None
        return self._match_sequence(pattern.items, 0, significant(target.children), 0, env, True)

    def _match_sequence(  # noqa: PLR0917 - the recursion state is all positional
        self,
        items: tuple[PItem, ...],
        i: int,
        targets: Sequence[Node],
        j: int,
        env: Env,
        exact: bool,
    ) -> Env | None:
        self._steps += 1
        if self._steps % MAX_STEPS_PER_CLOCK_CHECK == 0 and time.monotonic() > self._deadline:
            raise RuleTimeoutError
        if i == len(items):
            return env if (not exact or j == len(targets)) else None
        item = items[i]
        if item.kind == ITEM_NODE:
            if j >= len(targets) or item.node is None:
                return None
            matched = self.match_node(item.node, targets[j], env)
            if matched is None:
                return None
            return self._match_sequence(items, i + 1, targets, j + 1, matched, exact)
        for taken in range(len(targets) - j + 1):
            if taken > 0 and item.lead_comma and targets[j].type != ",":
                break
            if taken > 0 and item.trail_comma and targets[j + taken - 1].type != ",":
                continue
            bound: Env | None = env
            if item.kind == ITEM_VAR:
                named = tuple(n for n in targets[j : j + taken] if n.type != ",")
                bound = self._bind(env, item.name, named)
            if bound is None:
                continue
            found = self._match_sequence(items, i + 1, targets, j + taken, bound, exact)
            if found is not None:
                return found
        return None

    def match_at(self, pattern: CompiledPattern, node: Node, env: Env | None = None) -> Env | None:
        """Match ``pattern`` with ``node`` as its root (or, for a sequence, its first statement)."""
        if node.type != pattern.anchor_kind:
            return None
        if not pattern.is_sequence:
            if pattern.required:
                text = node.text or b""
                if any(word not in text for word in pattern.required):
                    return None
            return self.match_node(pattern.root, node, env or {})
        unit = node.parent if node.parent is not None and node.parent.type in _WRAPPERS else node
        parent = unit.parent
        if parent is None:
            return None
        siblings = significant(parent.named_children)
        position = next((n for n, item in enumerate(siblings) if item.id == unit.id), None)
        if position is None:
            return None
        siblings = [unwrap(item) for item in siblings]
        return self._match_sequence(pattern.items, 0, siblings, position, env or {}, False)

    # --- clauses and rules ----------------------------------------------------------------

    def _symbol_hit(self, entry: CatalogueEntry, node: Node, language: Language) -> bool:
        """Whether ``node`` is the code ``entry.symbol`` names; a partial match is recorded."""
        assert entry.symbol is not None  # noqa: S101 - checked by the caller
        target: Node | None = node
        if node.type in CALL_NODES:
            target = node.child_by_field_name("function")
        while target is not None:
            hit = symbol_match(entry.symbol, target, self._aliases, language)
            if hit is not None:
                self._cl_partial = self._cl_partial or hit == "partial"
                return True
            if entry.kind is not CatalogueKind.SOURCE:
                return False
            # A source is read through its members: request.args.get(...) reads request.args.
            target = target.child_by_field_name("object")
        return False

    def _catalogue_test(self, language: Language) -> Callable[[str, Node], bool]:
        def test(entry_id: str, node: Node) -> bool:
            if entry_id.endswith(".*"):
                return self._wildcard_hit(entry_id[:-1], node, language)
            return self._catalogue_entry(entry_id, node, language)

        return test

    def _wildcard_entries(
        self, prefix: str, language: Language
    ) -> tuple[dict[str, list[CatalogueEntry]], list[str]]:
        """Entries under ``prefix``: symbol sinks keyed by last segment, and the other ids."""
        cached = self._prefixes.get((prefix, language))
        if cached is None:
            by_last: dict[str, list[CatalogueEntry]] = {}
            others: list[str] = []
            for key, (entry_language, entry) in self.catalogues.items():
                if entry_language is not language or not key.startswith(prefix):
                    continue
                if entry.symbol is not None and entry.kind is not CatalogueKind.SOURCE:
                    by_last.setdefault(entry.symbol.rsplit(".", 1)[-1], []).append(entry)
                else:
                    others.append(key)
            cached = self._prefixes[(prefix, language)] = (by_last, others)
        return cached

    def _wildcard_hit(self, prefix: str, node: Node, language: Language) -> bool:
        by_last, others = self._wildcard_entries(prefix, language)
        target = node.child_by_field_name("function") if node.type in CALL_NODES else node
        parts = chain(target) if target is not None else None
        if parts and any(
            self._symbol_hit(entry, node, language) for entry in by_last.get(parts[-1], ())
        ):
            return True
        return any(self._catalogue_entry(key, node, language) for key in others)

    def _catalogue_entry(self, entry_id: str, node: Node, language: Language) -> bool:
        found = self.catalogues.get(entry_id)
        if found is None or found[0] is not language:
            return False
        entry = found[1]
        if entry.symbol is not None:
            return self._symbol_hit(entry, node, language)
        if entry.pattern is None:
            return False
        try:
            pattern = self._pattern(entry.pattern)
        except PatternSyntaxError:
            return False
        return self.match_at(pattern, node) is not None

    def _inadequate_test(self, language: Language) -> Callable[[str, Node], bool]:
        """A call to a catalogued sanitiser that does not cover ``context`` (E16-03)."""

        def test(context: str, node: Node) -> bool:
            if node.type not in CALL_NODES:
                return False
            inadequate: str | None = None
            for found_language, entry in self.catalogues.values():
                if found_language is not language or entry.kind is not CatalogueKind.SANITISER:
                    continue
                if entry.symbol is None or not self._symbol_hit(entry, node, language):
                    continue
                if context in entry.covers:
                    return False
                inadequate = entry.symbol
            if inadequate is None:
                return False
            self._cl_props["sanitiser.inadequate"] = inadequate
            self._cl_props["sanitiser.required_context"] = context
            return True

        return test

    def _constraints_hold(
        self, rule: RuleDef, clause: PatternClause, env: Env, shared: Env
    ) -> bool:
        scope = {**shared, **env}
        for constraint in clause.where:
            binding = scope.get(constraint.metavariable)
            if binding is None:
                binding = scope.get(constraint.metavariable.replace("...", ""))
            if binding is None:
                return False
            ok = holds(
                constraint,
                binding.nodes,
                rule.compiled_regexes,
                self._catalogue_test(self._language),
                self._inadequate_test(self._language),
            )
            if not ok:
                return False
        return True

    def _clause(self, rule: RuleDef, clause: PatternClause, node: Node, shared: Env) -> Env | None:
        env = self._clause_core(rule, clause, node, shared)
        if env is not None and clause.function_regex is not None:
            scope = _scope_of(node)
            text = (scope.text or b"").decode("utf-8", errors="replace")
            if rule.compiled_regexes[clause.function_regex].search(text) is None:
                return None
        return env

    def _clause_core(
        self, rule: RuleDef, clause: PatternClause, node: Node, shared: Env
    ) -> Env | None:
        if clause.pattern is not None:
            pattern = self._pattern(clause.pattern)
            self._cl_partial, self._cl_props = False, {}
            env = self.match_at(pattern, node, shared)
            if env is None or not self._constraints_hold(rule, clause, env, shared):
                return None
            self._partial = self._partial or self._cl_partial
            self._props.update(self._cl_props)
            return env
        if clause.pattern_inside is not None or clause.pattern_not_inside is not None:
            return self._inside(rule, clause, node, shared)
        if clause.pattern_regex is not None:
            text = (node.text or b"").decode("utf-8", errors="replace")
            return {} if rule.compiled_regexes[clause.pattern_regex].search(text) else None
        if clause.ref is not None:
            return self._ref(clause.ref, node)
        return None

    def _inside(self, rule: RuleDef, clause: PatternClause, node: Node, shared: Env) -> Env | None:
        negated = clause.pattern_not_inside is not None
        text = clause.pattern_not_inside if negated else clause.pattern_inside
        assert text is not None  # noqa: S101 - narrowed by the caller
        pattern = self._pattern(text)
        found: Env | None = None
        ancestor: Node | None = node
        while ancestor is not None and found is None:
            env = self.match_at(pattern, ancestor, shared)
            if env is not None and self._constraints_hold(rule, clause, env, shared):
                found = env
            ancestor = ancestor.parent
        if negated:
            return {} if found is None else None
        return found

    def _ref(self, rule_id: str, node: Node) -> Env | None:
        target = self._rules.get(rule_id)
        if target is None or rule_id in self._stack:
            return None  # a cycle is a load error (CK-RULE-015); never loop here
        self._stack.append(rule_id)
        try:
            return self._at(target, node)
        finally:
            self._stack.pop()

    def _at(self, rule: RuleDef, node: Node) -> Env | None:
        block = rule.match
        shared: Env = {}
        if block.any:
            for clause in block.any:
                env = self._clause(rule, clause, node, shared)
                if env is not None:
                    shared = {**shared, **env}
                    break
            else:
                return None
        for clause in block.all:
            env = self._clause(rule, clause, node, shared)
            if env is None:
                return None
            shared = {**shared, **env}
        for clause in block.none:
            if self._clause(rule, clause, node, shared) is not None:
                return None
        return shared

    def anchor_kinds(self, rule: RuleDef, seen: frozenset[str] = frozenset()) -> set[str]:
        """Node types the rule can match at, from its positive pattern clauses."""
        clauses = (
            rule.match.any
            or tuple(c for c in rule.match.all if c.pattern is not None or c.ref is not None)[:1]
        )
        kinds: set[str] = set()
        for clause in clauses:
            if clause.pattern is not None:
                kinds.add(self._pattern(clause.pattern).anchor_kind)
            elif clause.ref is not None and clause.ref not in seen and clause.ref in self._rules:
                kinds |= self.anchor_kinds(self._rules[clause.ref], seen | {clause.ref})
        return kinds

    # --- files ----------------------------------------------------------------------------

    def match_file(self, parsed: ParsedFile, rules: Sequence[RuleDef]) -> list[RuleMatch]:
        """The matches of ``rules`` in ``parsed`` (``match_detailed`` also reports failures)."""
        return self.match_detailed(parsed, rules).matches

    def match_detailed(self, parsed: ParsedFile, rules: Sequence[RuleDef]) -> FileResult:
        """Like ``match_file`` and also the rules that raised or timed out."""
        matches: list[RuleMatch] = []
        failures: list[RuleFailure] = []
        if parsed.tree is None:
            return FileResult(matches, failures)
        self._language = parsed.language
        self._aliases = import_aliases(parsed.tree.root_node, parsed.language)
        self._rules = {rule.id: rule for rule in rules}
        applicable = [rule for rule in rules if parsed.language.value in rule.languages]
        index: dict[str, list[Node]] | None = None
        for rule in applicable:
            self._steps = 0
            self._stack = []
            self._deadline = time.monotonic() + self.rule_seconds
            try:
                if index is None:
                    index = _index(parsed.tree.root_node)
                matches.extend(self._rule_matches(rule, parsed, index))
            except RuleTimeoutError:
                failures.append(RuleFailure(rule.id, "rule_timeout"))
            except Exception:  # noqa: BLE001 - one bad rule must not lose the others
                _log.warning("rule_failed", rule=rule.id)
                failures.append(RuleFailure(rule.id, "rule_error"))
        matches.sort(key=lambda m: (m.start_byte, m.end_byte, m.rule.id))
        return FileResult(matches, failures)

    def _rule_matches(
        self, rule: RuleDef, parsed: ParsedFile, index: Mapping[str, list[Node]]
    ) -> Iterator[RuleMatch]:
        unavailable = False
        if rule.taint is not None:
            hits = self._taint(rule, parsed)
            if hits is not None:
                for hit in hits:
                    yield RuleMatch(
                        rule, hit.start_byte, hit.end_byte, "taint", taint_path=hit.path
                    )
                return
            unavailable = True
            rule = self._pattern_only(rule)
        seen: set[tuple[int, int]] = set()
        for kind in sorted(self.anchor_kinds(rule)):
            for node in index.get(kind, ()):
                span = (node.start_byte, node.end_byte)
                if span in seen:
                    continue
                self._partial, self._props = False, {}
                env = self._at(rule, node)
                if env is not None:
                    seen.add(span)
                    bindings = {name: value.text for name, value in env.items()}
                    yield RuleMatch(
                        rule,
                        node.start_byte,
                        node.end_byte,
                        node.type,
                        bindings,
                        None,
                        unavailable,
                        tuple(sorted(self._props.items())),
                        self._partial,
                    )
        if (
            rule.match.any
            and not rule.match.all
            and all(c.pattern_regex is not None for c in rule.match.any)
        ):
            for clause in rule.match.any:
                yield from self._regex_spans(rule, clause, parsed, seen, unavailable)

    def _regex_spans(
        self,
        rule: RuleDef,
        clause: PatternClause,
        parsed: ParsedFile,
        seen: set[tuple[int, int]],
        unavailable: bool,
    ) -> Iterator[RuleMatch]:
        assert clause.pattern_regex is not None  # noqa: S101 - checked by the caller
        compiled = rule.compiled_regexes[clause.pattern_regex]
        decoded = parsed.source.expose()
        for found in compiled.finditer(decoded):
            start = len(decoded[: found.start()].encode("utf-8"))
            end = start + len(found.group(0).encode("utf-8"))
            if (start, end) not in seen and end > start:
                seen.add((start, end))
                yield RuleMatch(rule, start, end, "text", {}, None, unavailable)

    def _taint(self, rule: RuleDef, parsed: ParsedFile) -> Sequence[TaintHit] | None:
        spec = rule.taint
        if self.taint_engine is None or spec is None:
            return None

        def entries(ids: Sequence[str]) -> list[CatalogueEntry]:
            return [self.catalogues[i][1] for i in ids if i in self.catalogues]

        try:
            return self.taint_engine.find_paths(
                parsed, entries(spec.sources), entries(spec.sinks), entries(spec.sanitisers)
            )
        except NotImplementedError:
            return None

    def _pattern_only(self, rule: RuleDef) -> RuleDef:
        """The rule without its taint spec; a taint-only rule falls back to its sink patterns."""
        if rule.match.clauses or rule.taint is None:
            return rule
        clauses = []
        for entry_id in rule.taint.sinks:
            found = self.catalogues.get(entry_id)
            if found is not None and found[0].value in rule.languages:
                clauses.append({"pattern": found[1].pattern})
        return rule.model_copy(update={"match": type(rule.match).model_validate({"any": clauses})})


def _language(name: str) -> Language | None:
    try:
        return Language(name)
    except ValueError:
        return None


def _index(root: Node) -> dict[str, list[Node]]:
    """Every named node of the tree by type, in source order, from one traversal."""
    found: dict[str, list[Node]] = defaultdict(list)
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_named:
            found[node.type].append(node)
        stack.extend(reversed(node.children))
    return found
