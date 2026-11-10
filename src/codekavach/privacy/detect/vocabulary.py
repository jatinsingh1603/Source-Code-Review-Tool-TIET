"""The closed vocabulary of placeholder subtypes.

Owning epic: E08.

**E08 owns this vocabulary.** A placeholder such as ``<SECRET:aws_access_key:1>`` carries the
detector type because the type is evidence (CWE-798, CWE-359) while the value is not. The
subtype is therefore a constant from this module and **never derived from the matched text**: a
subtype computed from a value would put the value into the payload, which neither the placeholder
grammar (E02-12) nor ``SanitisedPayload`` can catch.

Adding a subtype needs three things in one change: a line here, a detector that emits it, and an
entry in the detector corpus (``tests/fixtures/detect/corpus``) that exercises it. The seed
members below are the ones E08-02 (secrets) and E08-03 (personal data and domain terms) implement.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from codekavach.core.models import PlaceholderKind

SECRET_SUBTYPES: Final = frozenset(
    {
        "aws_access_key",
        "aws_secret_key",
        "azure_client_secret",
        "azure_storage_connection_string",
        "basic_auth_url",
        "connection_string",
        "docker_registry_auth",
        "gcp_api_key",
        "gcp_service_account_key",
        "generic_credential",
        "github_token",
        "high_entropy_string",
        "jwt",
        "npm_token",
        "paytm_merchant_key",
        "private_key_block",
        "pypi_token",
        "razorpay_key_id",
        "razorpay_key_secret",
        "sendgrid_api_key",
        "slack_token",
        "slack_webhook",
        "ssh_private_key",
        "stripe_restricted_key",
        "stripe_secret_key",
        "twilio_api_key",
    }
)
PII_SUBTYPES: Final = frozenset(
    {
        "aadhaar_number",
        "credit_card",
        "date_of_birth",
        "email",
        "gstin",
        "ifsc_code",
        "indian_mobile",
        "iban",
        "ipv4",
        "ipv6",
        "mac_address",
        "pan_number",
        "passport_number",
        "phone_intl",
        "upi_id",
    }
)
# Subtypes only the optional named-entity detector emits (E08-04). They are in the vocabulary so
# a placeholder such as <PII:person_name:1> is valid, but no format detector produces them, so
# ``PII_SUBTYPES`` (the formats E08-03 implements) does not list them.
NER_SUBTYPES: Final = frozenset({"location", "nric_or_national_id", "organisation", "person_name"})
TERM_SUBTYPES: Final = frozenset({"domain"})

VOCABULARY: Final[Mapping[PlaceholderKind, frozenset[str]]] = MappingProxyType(
    {
        PlaceholderKind.SECRET: SECRET_SUBTYPES,
        PlaceholderKind.PII: PII_SUBTYPES | NER_SUBTYPES,
        PlaceholderKind.TERM: TERM_SUBTYPES,
    }
)

# Subtypes that name a broad class rather than a specific format. Overlap resolution prefers a
# specific subtype to one of these when everything else is equal.
GENERIC_SUBTYPES: Final = frozenset({"generic_credential", "high_entropy_string", "phone_intl"})


class UnknownSubtype(ValueError):  # noqa: N818 - the name is fixed by the E08-01 issue text
    """A subtype that is not in the closed vocabulary for its kind."""


def validate_subtype(kind: PlaceholderKind, subtype: str) -> None:
    """Raise :class:`UnknownSubtype` unless ``subtype`` is registered for ``kind``.

    The message does not repeat the subtype: a detector that built it from matched text would
    otherwise print that text.
    """
    if subtype not in VOCABULARY[kind]:
        raise UnknownSubtype(f"the subtype is not in the {kind.value} vocabulary")


def is_specific(subtype: str) -> bool:
    """True when ``subtype`` names a specific format (not one of the broad classes)."""
    return subtype not in GENERIC_SUBTYPES
