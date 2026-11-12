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
(``MIGRATABLE = False``), because rewriting an entry would break the chain. Version 2 (E25-03)
adds ``policy_hash`` (the hash of the policy that governed the request) and ``policy_rule_key``
(the path-free key of the winning policy contribution, for example ``classification:pci``).
Version-1 entries are read by ``EgressRecordV1``, a read-only subclass that has neither field, so
their hashed bytes are exactly the bytes that were sealed; ``load_egress_record`` picks the class
by each entry's ``schema_version``, and a chain may mix both versions.
"""

import json
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
# The path-free key of a policy contribution: ``<axis>:<key>``; no ``/``, ``.``, ``*`` or space.
POLICY_RULE_KEY_PATTERN = r"^[a-z_]+:[A-Za-z0-9_-]{0,64}$"


class TokenCounts(KavachModel):
    """Token counts of one request; estimated until the provider reports them."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    prompt: int = Field(ge=0)
    completion: int | None = Field(default=None, ge=0)
    estimated: bool = True


class EgressRecord(VersionedModel):
    """One ledger entry: what left (or would have left) the machine, and when."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA
    SCHEMA_VERSION: ClassVar[int] = 2
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
    policy_hash: str | None = Field(default=None, pattern=HEX64_PATTERN)
    policy_rule_key: str | None = Field(default=None, pattern=POLICY_RULE_KEY_PATTERN)

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
        if (self.policy_hash is None) != (self.policy_rule_key is None):
            raise ValueError("policy_hash and policy_rule_key are set together")
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
        policy_hash: str | None = None,
        policy_rule_key: str | None = None,
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
        if cls.SCHEMA_VERSION >= 2:  # version 2 added the policy fields
            fields |= {"policy_hash": policy_hash, "policy_rule_key": policy_rule_key}
        elif policy_hash is not None or policy_rule_key is not None:
            raise ValueError("version-1 entries carry no policy fields")
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


class EgressRecordV1(EgressRecord):
    """A version-1 ledger entry, read-only: no policy fields, hashed exactly as it was sealed.

    The two fields are redeclared as excluded constants, so they are absent from the dump, from
    ``canonical_json`` and therefore from the entry hash; a version-1 line that names either one
    is rejected.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA
    SCHEMA_VERSION: ClassVar[int] = 1

    policy_hash: None = Field(default=None, exclude=True)
    policy_rule_key: None = Field(default=None, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _no_policy_keys(cls, data: Any) -> Any:
        if isinstance(data, dict) and ({"policy_hash", "policy_rule_key"} & data.keys()):
            raise ValueError("version-1 entries carry no policy fields")
        return data


EGRESS_RECORD_CLASSES: dict[int, type[EgressRecord]] = {1: EgressRecordV1, 2: EgressRecord}


def load_egress_record(raw: str | bytes) -> EgressRecord:
    """Validate one stored ledger line with the class of its ``schema_version``.

    Raises:
        pydantic.ValidationError: the line is not a valid entry of its version, or its version is
            not one this release reads.
    """
    version: object = 1
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        data = None  # model_validate_json below raises the ValidationError callers expect
    if isinstance(data, dict):
        version = data.get("schema_version", 1)
    model = EgressRecord
    if isinstance(version, int) and not isinstance(version, bool):
        model = EGRESS_RECORD_CLASSES.get(version, EgressRecord)
    return model.model_validate_json(raw)
