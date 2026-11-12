"""The constant payload of a provider probe (``codekavach providers test``, E22).

Owning epic: E12 (used by the provider probe of E22).

A probe must exercise the same path as a scan (guard, ledger, transport) without sending anything
of the client's. Its payload is therefore a fixed, synthetic snippet written here, at level L4 and
with no slice, built in the privacy package because only the privacy layer may wrap text as
``SanitisedText`` (invariant I2, rule R2 of the static guard).
"""

from typing import Final

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.ids import new_candidate_id, new_payload_id, new_scan_id
from codekavach.core.models.payload import PayloadFacts, SanitisedPayload
from codekavach.core.models.text import SanitisedText

PROBE_SNIPPET: Final = (
    "def handler(request):\n"
    "    value = request.args.get('q')\n"
    "    return 'Hello, ' + escape(value)\n"
)
PROBE_RULE: Final = "CK-PROBE-001"


def probe_scan_id() -> str:
    """A fresh scan id for the ledger entries of one probe."""
    return new_scan_id()


def probe_payload() -> SanitisedPayload:
    """A fresh payload around ``PROBE_SNIPPET``; its hash is constant, its ids are new."""
    return SanitisedPayload(
        id=new_payload_id(),
        candidate_id=new_candidate_id(),
        slice_id=None,
        text=SanitisedText(PROBE_SNIPPET),
        level=PrivacyLevel.L4,
        payload_hash=sha256_hex(PROBE_SNIPPET),
        facts=PayloadFacts(rule=PROBE_RULE, cwe=(79,), sink_family="xss", strategy="probe"),
    )
