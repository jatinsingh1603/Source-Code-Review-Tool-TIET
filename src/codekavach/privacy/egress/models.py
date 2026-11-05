"""Egress decision models: the request metadata, the ticket, the decision and the block codes.

Owning epic: E12 (issue E12-01).

Everything here is metadata: hashes, ids, enums, counts and offsets. Nothing in this module can
hold client code, an identifier or a matched string, and no message built here quotes one. A block
code is a member of the closed set ``BLOCK_CODES``, never free text, because a free-text reason
could contain the very bytes that were blocked (invariant I6); ``EgressBlocked`` renders the code
and nothing else for the same reason.

``EgressTicket`` is minted by ``codekavach.privacy.egress.guard`` only. The transport (E12-04)
accepts a request only together with a ticket and calls ``EgressGuard.redeem`` before it opens a
connection (invariant I1).
"""

from typing import ClassVar, Final, Self

from pydantic import Field, model_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.egress import HEX64_PATTERN, TASK_PATTERN
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.ids import CandidateIdField
from codekavach.core.models.timeutil import UtcDatetime

# The closed vocabulary of block codes, in the order that decides which code names a decision
# when several checks fail at once (secrets first, then the identifiers the vault knows, ...).
BLOCK_CODE_ORDER: Final[tuple[str, ...]] = (
    "residual_secret",
    "vault_identifier",
    "domain_term",
    "residual_pii",
    "size_budget",
    "aggregation_budget",
    "rate_budget",
    "policy_never_send",
    "consent_missing",
    "provider_not_allowed",
    "level_not_permitted",
    "scanner_error",
    "ticket_expired",
    "hash_mismatch",
)
BLOCK_CODES: Final[frozenset[str]] = frozenset(BLOCK_CODE_ORDER)
TAG_PATTERN: Final = r"^[0-9a-f]{32}$"


def priority(block_code: str) -> int:
    """Rank of ``block_code`` in ``BLOCK_CODE_ORDER``; lower names a decision first."""
    return BLOCK_CODE_ORDER.index(block_code)


class EgressMeta(KavachModel):
    """What the guard is told about a request: the provider, the level and the payload hash.

    ``payload_hash`` is the SHA-256 of the sanitised payload text, not of the whole request body.
    The model carries no client code (``DATA_CLASSIFICATION`` is metadata).
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=128)
    level: PrivacyLevel
    payload_hash: str = Field(pattern=HEX64_PATTERN)
    candidate_id: CandidateIdField | None = None
    task: str | None = Field(default=None, pattern=TASK_PATTERN)


class LeakHit(KavachModel):
    """One scanner finding, reported as a count and an offset; the matched text is never kept."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    scanner_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,47}$")
    block_code: str
    count: int = Field(ge=1)
    first_offset: int = Field(ge=0)

    @model_validator(mode="after")
    def _known_code(self) -> Self:
        if self.block_code not in BLOCK_CODES:
            raise ValueError("block_code is not in the closed vocabulary")
        return self


class EgressTicket(KavachModel):
    """Permission to send exactly one request: bound to a payload hash, a provider and a level.

    Minted by ``EgressGuard.evaluate`` and by nothing else. The transport must, before it opens a
    connection, call ``EgressGuard.redeem`` with the payload hash, provider and level of the
    request it is about to send. Redemption fails closed unless the ticket is live (the ``tag`` is
    in the guard's registry, not used and not expired) and all three fields match. A ticket is
    consumed by its first redemption.

    Within one process this is a convention enforced by tests and an import contract, not a
    cryptographic guarantee: code that can read process memory can read the registry too. What it
    does give is that no code path reaches the transport without going through the guard.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    payload_hash: str = Field(pattern=HEX64_PATTERN)
    provider: str = Field(min_length=1, max_length=128)
    level: PrivacyLevel
    expires_at: UtcDatetime
    tag: str = Field(pattern=TAG_PATTERN, repr=False)


class EgressDecision(KavachModel):
    """The guard's answer: a ticket, or a closed-vocabulary block code (never both, never neither).

    ``hits`` carries counts and offsets for the audit trail and for ``privacy inspect``; it never
    carries matched text.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    allowed: bool
    block_code: str | None = None
    ticket: EgressTicket | None = None
    hits: tuple[LeakHit, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.allowed:
            if self.ticket is None or self.block_code is not None or self.hits:
                raise ValueError("an allowed decision carries a ticket and nothing else")
            return self
        if self.block_code is None or self.ticket is not None:
            raise ValueError("a blocked decision carries a block code and no ticket")
        if self.block_code not in BLOCK_CODES:
            raise ValueError("block_code is not in the closed vocabulary")
        return self


class EgressBlocked(Exception):  # noqa: N818 - the name is fixed by E12-01 and the CLI lookup
    """A request was blocked; the CLI maps this to the privacy exit code (E05-04).

    The exception carries the block code and nothing else, so no payload byte can reach a log, a
    traceback or a CI transcript through it.
    """

    __slots__ = ("block_code",)

    def __init__(self, block_code: str) -> None:
        if block_code not in BLOCK_CODES:
            block_code = "scanner_error"  # an unknown code must still block, never raise anew
        super().__init__(block_code)
        self.block_code = block_code

    def __str__(self) -> str:
        return self.block_code

    def __repr__(self) -> str:
        return f"EgressBlocked({self.block_code!r})"
