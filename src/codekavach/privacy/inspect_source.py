"""The payloads of a stored scan, rebuilt for ``privacy inspect``.

Owning epic: E13. MVP; extended by E11, which adds the context rounds of a scan.

A sanitised payload's text is held by the ledger only: no artefact serialises it. A scan therefore
stores a ``PayloadStub`` (the payload minus its text) beside the slices and the candidates, and this
source puts the two together again: the stub from the artefact store, the text from the ledger
entry with the same payload hash. A payload whose text the ledger no longer holds (pruned, or never
written because the scan sent nothing) is left out rather than shown without its text. The source
is read-only and never opens the vault (I3): showing the original and the payload side by side
needs no mapping.
"""

from collections.abc import Sequence

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.disclosure import PayloadStub
from codekavach.core.models.enums import EgressOutcome
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.slice import CodeSlice
from codekavach.core.pipeline import keys
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.ledger import LedgerReader, open_reader

_log = get_logger(__name__)
_RECORDED = frozenset({EgressOutcome.NOT_SENT_DRY_RUN})


class StoredPayloadSource:
    """Payloads, slices, candidates and ledger outcomes of one stored scan."""

    def __init__(self, layout: StateLayout, scan_id: str, settings: Settings | None) -> None:
        self._store = OnDiskArtefactStore.open_existing(layout, scan_id)
        self._reader: LedgerReader = open_reader(layout, settings=settings)
        self._scan_id = scan_id
        self._slices: dict[str, CodeSlice] | None = None
        self._candidates: dict[str, Candidate] | None = None

    def payloads(self, scan_id: str) -> Sequence[SanitisedPayload]:
        """Every payload of the scan whose text the ledger holds."""
        if not self._store.has(keys.PAYLOAD_INDEX):
            return ()
        rebuilt: list[SanitisedPayload] = []
        for stub in self._store.get_list(keys.PAYLOAD_INDEX, PayloadStub):
            text = self._reader.payload_text(stub.payload_hash)
            if text is None:
                _log.info("inspect_payload_not_in_ledger")
                continue
            payload = SanitisedPayload.build(
                candidate_id=stub.candidate_id,
                slice_id=stub.slice_id,
                text=text,
                level=stub.level,
                pseudonym_count=stub.pseudonym_count,
                line_map=stub.line_map,
                facts=stub.facts,
            ).evolve(id=stub.id)
            rebuilt.append(payload)
        return rebuilt

    def slice_for(self, candidate_id: str) -> CodeSlice | None:
        """The slice a payload was built from."""
        if self._slices is None:
            has = self._store.has(keys.SLICES)
            slices = self._store.get_list(keys.SLICES, CodeSlice) if has else []
            self._slices = {str(item.candidate_id): item for item in slices}
        return self._slices.get(candidate_id)

    def candidate(self, candidate_id: str) -> Candidate | None:
        """The candidate of a payload."""
        if self._candidates is None:
            found = self._store.get_list(keys.CANDIDATES, Candidate)
            self._candidates = {str(item.id): item for item in found}
        return self._candidates.get(candidate_id)

    def ledger_outcome(self, payload_hash: str) -> str | None:
        """``recorded``, ``sent``, ``blocked:<code>`` or ``None`` when not in the ledger."""
        records = self._reader.records_for_payload(payload_hash)
        if not records:
            return None
        last = records[-1]
        if last.outcome is EgressOutcome.BLOCKED:
            return f"blocked:{last.block_code or 'unknown'}"
        if last.outcome in _RECORDED:
            return "recorded"
        return "sent"


def open_payload_source(
    layout: StateLayout, scan_id: str, settings: Settings | None = None
) -> StoredPayloadSource:
    """The source for ``scan_id`` below ``layout``; ``settings`` select the ledger's key."""
    return StoredPayloadSource(layout, scan_id, settings)
