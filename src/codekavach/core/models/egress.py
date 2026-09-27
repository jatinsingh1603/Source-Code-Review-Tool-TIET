"""EgressRecord: one entry of the hash-chained egress ledger.

Owning epic: E02.

Every payload that is sent to (or blocked from) an LLM provider gets an entry. The entry holds
no payload text, paths, symbols, rule ids or fingerprints; only ``candidate_id`` links it to the
scan data, so a ledger can be handed to an auditor without revealing code structure. ``block_code``
is a closed-format code, never a message, because a free-text reason could quote the very string
that was blocked (invariant I6).

Entry hash (normative): ``sha256_hex(canonical_json(record, exclude={"entry_hash"}))``, checked on
every construction and load. Hash verification gives tamper evidence, not tamper prevention:
someone who can rewrite the whole ledger file can rebuild the whole chain.

Versioning: ``schema_version`` is part of the hashed bytes and entries are never migrated in place
(``MIGRATABLE = False``), because rewriting an entry would break the chain. When the format
changes, copy this class to ``EgressRecordV1`` (frozen, read-only, same hash rule), bump
``EgressRecord.SCHEMA_VERSION``, and let the ledger reader (E12) choose the class by each entry's
``schema_version``.
"""

import unicodedata
from datetime import UTC, datetime
from typing import Any, ClassVar, Self

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.canonical import canonical_json, sha256_hex
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.errors import ModelError
from codekavach.core.models.ids import CandidateId, CandidateIdField, ScanId, ScanIdField
from codekavach.core.models.timeutil import UtcDatetime

GENESIS_PREV_HASH = "0" * 64
HEX64_PATTERN = r"^[0-9a-f]{64}$"
TASK_PATTERN = r"^[a-z][a-z0-9_-]{0,47}$"
BLOCK_CODE_PATTERN = r"^[a-z][a-z0-9_]{1,47}$"


class TokenCounts(KavachModel):
    """Token counts of one request; estimated until the provider reports them."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    prompt: int = Field(ge=0)
    completion: int | None = Field(default=None, ge=0)
    estimated: bool = True


class EgressRecord(VersionedModel):
    """One ledger entry: what left (or would have left) the machine, and when."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA
    SCHEMA_VERSION: ClassVar[int] = 1
    MIGRATABLE: ClassVar[bool] = False

    seq: int = Field(ge=1)
    timestamp: UtcDatetime
    scan_id: ScanIdField
    candidate_id: CandidateIdField | None
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=128)
    task: str | None = Field(default=None, pattern=TASK_PATTERN)
    level: PrivacyLevel
    payload_hash: str = Field(pattern=HEX64_PATTERN)
    request_hash: str | None = Field(default=None, pattern=HEX64_PATTERN)
    prev_hash: str = Field(pattern=HEX64_PATTERN)
    entry_hash: str = Field(pattern=HEX64_PATTERN)
    token_counts: TokenCounts
    outcome: EgressOutcome
    block_code: str | None = Field(default=None, pattern=BLOCK_CODE_PATTERN)
    ref_seq: int | None = Field(default=None, ge=1)

    @field_validator("provider", "model")
    @classmethod
    def _no_control_characters(cls, value: str) -> str:
        if any(unicodedata.category(char) == "Cc" for char in value):
            raise ValueError("provider and model must not contain control characters")
        return value

    @model_validator(mode="after")
    def _check_record(self) -> Self:
        if self.seq == 1 and self.prev_hash != GENESIS_PREV_HASH:
            raise ValueError("the first entry must carry the genesis prev_hash")
        blocked = self.outcome is EgressOutcome.BLOCKED
        if blocked != (self.block_code is not None):
            raise ValueError("block_code is required for blocked entries and forbidden otherwise")
        follow_up = self.outcome in (EgressOutcome.COMPLETED, EgressOutcome.FAILED)
        if follow_up != (self.ref_seq is not None):
            raise ValueError("ref_seq is required for completed and failed entries only")
        if self.ref_seq is not None and self.ref_seq >= self.seq:
            raise ValueError("ref_seq must refer to an earlier entry")
        if self.entry_hash != self.compute_entry_hash():
            raise ValueError("entry_hash does not match the entry")
        return self

    def compute_entry_hash(self) -> str:
        """Return the SHA-256 of the canonical JSON of every field except ``entry_hash``."""
        return sha256_hex(canonical_json(self, exclude=frozenset({"entry_hash"})))

    @classmethod
    def seal(
        cls,
        *,
        prev: "EgressRecord | None",
        timestamp: datetime,
        scan_id: ScanId,
        candidate_id: CandidateId | None,
        provider: str,
        model: str,
        task: str | None,
        level: PrivacyLevel,
        payload_hash: str,
        token_counts: TokenCounts,
        outcome: EgressOutcome,
        request_hash: str | None = None,
        block_code: str | None = None,
        ref_seq: int | None = None,
    ) -> Self:
        """Build the next entry after ``prev`` (or the genesis entry) with its hashes filled in."""
        fields: dict[str, Any] = {
            "schema_version": cls.SCHEMA_VERSION,
            "seq": 1 if prev is None else prev.seq + 1,
            "timestamp": timestamp.astimezone(UTC),
            "scan_id": scan_id,
            "candidate_id": candidate_id,
            "provider": provider,
            "model": model,
            "task": task,
            "level": level,
            "payload_hash": payload_hash,
            "request_hash": request_hash,
            "prev_hash": GENESIS_PREV_HASH if prev is None else prev.entry_hash,
            "token_counts": token_counts,
            "outcome": outcome,
            "block_code": block_code,
            "ref_seq": ref_seq,
        }
        draft = cls.model_construct(**fields, entry_hash="")
        return cls.model_validate({**fields, "entry_hash": draft.compute_entry_hash()})

    def verify_link(self, prev: "EgressRecord | None") -> None:
        """Check this entry against its predecessor; messages contain sequence numbers only."""
        if prev is None:
            if self.seq != 1 or self.prev_hash != GENESIS_PREV_HASH:
                raise ModelError(f"bad genesis: entry {self.seq} has no predecessor")
            return
        if self.seq != prev.seq + 1:
            raise ModelError(f"sequence gap: entry {self.seq} follows entry {prev.seq}")
        if self.prev_hash != prev.entry_hash:
            raise ModelError(f"previous hash mismatch at entry {self.seq}")
        if self.timestamp < prev.timestamp:
            raise ModelError(f"timestamp regression at entry {self.seq}")
