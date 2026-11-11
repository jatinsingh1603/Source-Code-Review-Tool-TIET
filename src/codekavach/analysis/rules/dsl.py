"""The native rule DSL: the models a rule file is read into (E16-01).

Owning epic: E16. A rule file is YAML data and nothing in it is executed. The models check the
*shape* of a file (field names, types, patterns of identifiers, length caps). Meaning is checked
by ``codekavach.analysis.rules.validate``, which reports a stable ``CK-RULE-nnn`` code per
problem, so an author sees every problem in a file instead of the first one. That is why, for
example, a clause with two pattern kinds or a match block with no clause still *loads*.

Metavariables: ``$NAME`` binds one node, ``$...NAME`` binds a sequence, ``_`` is one anonymous
node and ``...`` matches any sequence of siblings. Matching is E16-02.
"""

import re
from functools import cached_property
from typing import ClassVar, Final, Literal

from pydantic import Field, field_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import Confidence, Severity
from codekavach.core.models.taxonomy import CweId

RULE_ID_PATTERN: Final = r"^[a-z0-9]+(\.[a-z0-9-]+)+$"
METAVARIABLE_PATTERN: Final = r"^\$\.?\.?\.?[A-Z][A-Z0-9_]*$"
OWASP_PATTERN: Final = r"^A(0[1-9]|10):20[12][0-9]$"
SEMVER_PATTERN: Final = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$"
MAX_REGEX_LENGTH: Final = 512
MAX_REMEDIATION: Final = 2000
MAX_MESSAGE: Final = 500
MAX_CLAUSES: Final = 64
RULE_ID: Final = re.compile(RULE_ID_PATTERN)
METAVARIABLE: Final = re.compile(METAVARIABLE_PATTERN)
PATTERN_KINDS: Final = ("pattern", "pattern_inside", "pattern_not_inside", "pattern_regex", "ref")
CONSTRAINT_KINDS: Final = (
    "regex",
    "not_regex",
    "kind",
    "is_constant",
    "min_length",
    "equals",
    "one_of",
    "catalogue",
    "inadequate_for",
)
NODE_KINDS: Final = frozenset(
    {
        "concatenation",
        "call",
        "literal",
        "identifier",
        "attribute",
        "interpolation",
        "argument",
        "parameter",
        "request_derived",
        "dynamic_string",
        "constant_binding",
    }
)


class _RuleModel(KavachModel):
    """Rule files hold no client data; they are metadata under the data classification."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA


class Constraint(_RuleModel):
    """A condition on one metavariable: exactly one of the condition keys is expected."""

    metavariable: str = Field(pattern=METAVARIABLE_PATTERN, max_length=64)
    regex: str | None = Field(default=None, max_length=MAX_REGEX_LENGTH)
    not_regex: str | None = Field(default=None, max_length=MAX_REGEX_LENGTH)
    kind: str | None = Field(default=None, max_length=32)
    is_constant: bool | None = None
    min_length: int | None = Field(default=None, ge=0, le=100_000)
    equals: str | None = Field(default=None, max_length=1000)
    one_of: tuple[str, ...] | None = Field(default=None, max_length=256)
    catalogue: str | None = Field(default=None, max_length=128)
    inadequate_for: str | None = Field(default=None, max_length=32)

    @property
    def conditions(self) -> tuple[str, ...]:
        """The condition keys that are set."""
        return tuple(key for key in CONSTRAINT_KINDS if getattr(self, key) is not None)


class PatternClause(_RuleModel):
    """One clause of a match block: a pattern of one kind, with optional constraints."""

    pattern: str | None = Field(default=None, max_length=4000)
    pattern_inside: str | None = Field(default=None, max_length=4000)
    pattern_not_inside: str | None = Field(default=None, max_length=4000)
    pattern_regex: str | None = Field(default=None, max_length=MAX_REGEX_LENGTH)
    ref: str | None = Field(default=None, pattern=RULE_ID_PATTERN, max_length=128)
    function_regex: str | None = Field(default=None, max_length=MAX_REGEX_LENGTH)
    where: tuple[Constraint, ...] = Field(default=(), max_length=MAX_CLAUSES)

    @property
    def kinds(self) -> tuple[str, ...]:
        """The pattern keys that are set (exactly one in a valid rule)."""
        return tuple(key for key in PATTERN_KINDS if getattr(self, key) is not None)


class MatchBlock(_RuleModel):
    """``any`` clauses are alternatives, ``all`` must all hold and ``none`` must not hold."""

    any: tuple[PatternClause, ...] = Field(default=(), max_length=MAX_CLAUSES)
    all: tuple[PatternClause, ...] = Field(default=(), max_length=MAX_CLAUSES)
    none: tuple[PatternClause, ...] = Field(default=(), max_length=MAX_CLAUSES)

    @property
    def clauses(self) -> tuple[PatternClause, ...]:
        """Every clause of the block."""
        return (*self.any, *self.all, *self.none)


class TaintSpec(_RuleModel):
    """Catalogue entry ids for a taint rule; stored here, handed to the taint engine by E16-02."""

    sources: tuple[str, ...] = Field(default=(), max_length=256)
    sinks: tuple[str, ...] = Field(default=(), max_length=256)
    sanitisers: tuple[str, ...] = Field(default=(), max_length=256)
    require_path: bool = False


class RuleMeta(_RuleModel):
    """What a report says about the weakness a rule looks for."""

    cwe: tuple[CweId, ...] = Field(default=(), max_length=8)
    owasp: tuple[str, ...] = Field(default=(), max_length=8)
    asvs: tuple[str, ...] = Field(default=(), max_length=16)
    capec: tuple[int, ...] = Field(default=(), max_length=16)
    references: tuple[str, ...] = Field(default=(), max_length=16)
    remediation: str = Field(default="", max_length=MAX_REMEDIATION)
    licence: str = Field(default="MIT", min_length=1, max_length=64)
    source: str | None = Field(default=None, max_length=256)
    added_in: str = Field(default="", max_length=32)

    @field_validator("owasp")
    @classmethod
    def _owasp_shape(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not re.fullmatch(OWASP_PATTERN, item):
                raise ValueError("an OWASP Top 10 entry looks like A03:2021")
        return value


class RuleDef(_RuleModel):
    """One rule: where it applies, what it matches and what a match means."""

    id: str = Field(max_length=128)
    languages: tuple[str, ...] = Field(default=(), max_length=16)
    message: str = Field(max_length=MAX_MESSAGE)
    severity: Severity
    confidence: Confidence
    kind: Literal["vulnerability", "hotspot"] = "vulnerability"
    metadata: RuleMeta = Field(default_factory=RuleMeta)
    match: MatchBlock = Field(default_factory=MatchBlock)
    taint: TaintSpec | None = None
    fixtures: tuple[str, ...] = Field(default=(), max_length=16)

    @property
    def patterns(self) -> tuple[str, ...]:
        """Every pattern text of the match block (not the regular expressions)."""
        found: list[str] = []
        for clause in self.match.clauses:
            for key in ("pattern", "pattern_inside", "pattern_not_inside"):
                value = getattr(clause, key)
                if value is not None:
                    found.append(value)
        return tuple(found)

    @property
    def regexes(self) -> tuple[str, ...]:
        """Every regular expression the rule uses, from clauses and constraints."""
        found: list[str] = []
        for clause in self.match.clauses:
            found.extend(x for x in (clause.pattern_regex, clause.function_regex) if x is not None)
            for constraint in clause.where:
                found.extend(x for x in (constraint.regex, constraint.not_regex) if x is not None)
        return tuple(found)

    @cached_property
    def compiled_regexes(self) -> dict[str, re.Pattern[str]]:
        """Each regular expression compiled once, cached on this instance (never module-wide).

        Raises ``re.error`` for a pattern that does not compile; the loader turns that into a load
        failure so a bad expression never reaches a scan.
        """
        return {text: re.compile(text) for text in self.regexes}
