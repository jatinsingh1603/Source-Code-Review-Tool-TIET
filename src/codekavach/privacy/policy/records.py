"""The path-free record of a policy decision, stored with the scan (E25-03).

A row names the candidate, the effective level, whether the path was withheld, the stable rule key
of the winning contribution and the hash of the policy document. It holds no path, pattern or
language, so it may be stored and shown outside the client environment.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field, field_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.ids import CandidateId, CandidateIdField
from codekavach.privacy.policy.engine import RULE_KEY_PATTERN, PolicyDecision


class PolicyDecisionRow(KavachModel):
    """One candidate's decision, without any path."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    candidate_id: CandidateIdField
    level: PrivacyLevel
    withheld: bool
    rule_key: str
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    classifications: tuple[str, ...] = ()

    @field_validator("rule_key")
    @classmethod
    def _path_free(cls, value: str) -> str:
        if not RULE_KEY_PATTERN.match(value):
            raise ValueError("rule_key must match ^[a-z_]+:[A-Za-z0-9_-]{0,64}$")
        return value

    @classmethod
    def of(
        cls, candidate_id: CandidateId, decision: PolicyDecision, *, withheld: bool
    ) -> PolicyDecisionRow:
        """The row of ``decision`` for ``candidate_id``."""
        return cls(
            candidate_id=candidate_id,
            level=decision.level,
            withheld=withheld,
            rule_key=decision.rule_key,
            policy_hash=decision.policy_hash,
            classifications=decision.classifications,
        )
