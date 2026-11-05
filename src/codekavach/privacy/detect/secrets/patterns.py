"""The provider pattern pack: ``SECRET_PATTERNS`` and the ``secret.pattern`` detector.

Owning epic: E08.

**Why prefixes and not entropy.** Every major provider publishes a fixed prefix and length for
its credential formats so that scanners can find them. Keying on the prefix gives high precision,
allows ``HIGH`` confidence and makes each pattern auditable: a reviewer can check it against the
vendor's documentation. Entropy (``entropy.py``) is the fallback for the long tail and the one
that produces false positives, which is why it lives in its own module and is ``LOW``.

Confidence rules used below:

* ``HIGH``: a vendor-documented prefix with a fixed length or charset (``AKIA`` plus 16, ``ghp_``
  plus 36, ``sk_live_`` ...), or a structure that a validator confirmed (a JWT whose header
  decodes, a PEM block with matching BEGIN and END lines).
* ``MEDIUM``: the format is not a documented prefix, so the match leans on a keyword or a shape
  seen in the wild (an Azure client secret's ``Q~`` marker, a value after ``razorpay`` and
  ``secret``), or a block that was cut off by the slice.

Every pattern is compiled through ``safe_compile`` at import time. Subtypes are constants of
``vocabulary.py`` and never computed from the matched text. A ``validator`` receives the matched
text and may reject it; it only ever inspects the text, never contacts a provider.

This module performs no network operation.
"""

import base64
import binascii
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.offsets import ByteOffsets
from codekavach.privacy.detect.safe_regex import safe_compile
from codekavach.privacy.detect.vocabulary import SECRET_SUBTYPES

DETECTOR_ID: Final = "secret.pattern"
_MAX_JSON_BYTES: Final = 16_000


_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def _b64url_decode(segment: str) -> bytes | None:
    if not _B64URL.fullmatch(segment):  # the decoder would silently skip other characters
        return None
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        return None


def valid_jwt(value: str) -> bool:
    """Three base64url segments whose header decodes to a JSON object containing ``alg``."""
    parts = value.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return False
    header = _b64url_decode(parts[0])
    if header is None or _b64url_decode(parts[1]) is None:
        return False
    try:
        decoded = json.loads(header)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(decoded, dict) and "alg" in decoded


_PEM = re.compile(
    r"-----BEGIN ([A-Z ]{0,24}PRIVATE KEY(?: BLOCK)?)-----(?P<body>[\s\S]*?)-----END ([A-Z ]+)-----"
)


def valid_private_key_block(value: str) -> bool:
    """A BEGIN line and an END line with the same label around a non-empty body."""
    match = _PEM.fullmatch(value.strip())
    return match is not None and match.group(1) == match.group(3) and match["body"].strip() != ""


def valid_connection_string(value: str) -> bool:
    """Parses as a URL with a non-empty password component."""
    candidate = value[len("jdbc:") :] if value.lower().startswith("jdbc:") else value
    try:
        return bool(urlsplit(candidate).password)
    except ValueError:
        return False


def valid_gcp_service_account(value: str) -> bool:
    """JSON that contains ``private_key`` and ``client_email``."""
    if len(value) > _MAX_JSON_BYTES:
        return False
    try:
        decoded = json.loads(value)
    except ValueError:
        return False
    return (
        isinstance(decoded, dict)
        and isinstance(decoded.get("private_key"), str)
        and isinstance(decoded.get("client_email"), str)
    )


def valid_docker_auth(value: str) -> bool:
    """A base64 value that decodes to ``user:password``."""
    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(padded.encode("ascii"), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    user, _, password = decoded.partition(":")
    return bool(user) and bool(password)


@dataclass(frozen=True)
class SecretPattern:
    """One credential format.

    ``regex`` is the source of the pattern; ``value_group`` is the capture group whose span is
    reported (0 for the whole match). ``hints`` are lowercase substrings, at least one of which
    must occur in a text before the pattern is run, so most patterns cost one substring search.
    """

    subtype: str
    regex: str
    confidence: Confidence
    description: str
    validator: Callable[[str], bool] | None = None
    hints: tuple[str, ...] = ()
    value_group: int = 0
    flags: int = 0

    def compiled(self) -> re.Pattern[str]:
        """The pattern, compiled through ``safe_compile``."""
        return safe_compile(self.regex, self.flags)


_NOT_WORD = r"(?<![A-Za-z0-9])"
_NOT_WORD_AFTER = r"(?![A-Za-z0-9])"
_VALUE_QUOTE = r"""[\s"'=:]{1,6}"""

SECRET_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    # --- AWS ------------------------------------------------------------------------------
    SecretPattern(
        "aws_access_key",
        # AWS documents the four-letter prefix by principal type (AKIA long-term user key,
        # ASIA temporary STS key, ...) followed by 16 upper-case letters or digits.
        _NOT_WORD + r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "AWS access key id: documented prefix plus 16 characters (20 in all).",
        hints=("akia", "asia", "agpa", "aida", "aroa", "aipa", "anpa", "anva"),
    ),
    SecretPattern(
        "aws_secret_key",
        # The secret key has no prefix, only a length (40 base64 characters), so it is keyed on
        # the variable name AWS uses for it.
        r"aws[\w.\-]{0,24}?secret[\w.\-]{0,24}?"
        + _VALUE_QUOTE
        + r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        Confidence.MEDIUM,
        "AWS secret access key: 40 base64 characters after an aws...secret... name.",
        hints=("secret",),
        value_group=1,
        flags=re.IGNORECASE,
    ),
    # --- Google / Azure -------------------------------------------------------------------
    SecretPattern(
        "gcp_service_account_key",
        r'\{[^{}]{0,8000}"type"\s*:\s*"service_account"[^{}]{0,8000}\}',
        Confidence.HIGH,
        "Google service-account key file: JSON with private_key and client_email.",
        validator=valid_gcp_service_account,
        hints=("service_account",),
    ),
    SecretPattern(
        "gcp_api_key",
        _NOT_WORD + r"AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])",
        Confidence.HIGH,
        "Google API key: the documented AIza prefix plus 35 characters (39 in all).",
        hints=("aiza",),
    ),
    SecretPattern(
        "azure_storage_connection_string",
        r"DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/]{86}==",
        Confidence.HIGH,
        "Azure storage connection string: documented layout, 88-character account key.",
        hints=("accountkey",),
    ),
    SecretPattern(
        "azure_client_secret",
        # Entra ID client secrets carry the marker 'Q~' after eight characters; the layout is
        # seen in scanner rule sets rather than in a vendor page, hence MEDIUM.
        r"(?<![A-Za-z0-9_.~\-])[A-Za-z0-9_.\-]{3}\dQ~[A-Za-z0-9_.~\-]{31,34}(?![A-Za-z0-9_.~\-])",
        Confidence.MEDIUM,
        "Azure AD client secret: the Q~ marker at a fixed position and 31 to 34 characters after.",
        hints=("q~",),
    ),
    # --- Code hosts, chat and payments ----------------------------------------------------
    SecretPattern(
        "github_token",
        _NOT_WORD + r"gh[pousr]_[A-Za-z0-9]{36}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "GitHub token: ghp_, gho_, ghu_, ghs_ or ghr_ plus 36 characters.",
        hints=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    SecretPattern(
        "github_token",
        _NOT_WORD + r"github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9_])",
        Confidence.HIGH,
        "GitHub fine-grained personal access token: github_pat_ plus 82 characters.",
        hints=("github_pat_",),
    ),
    SecretPattern(
        "slack_token",
        _NOT_WORD + r"xox[abprs]-(?:[0-9]{8,15}-){1,3}[A-Za-z0-9]{20,40}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "Slack bot, user or workspace token: xox? prefix, numeric ids, then a 20 to 40 char tail.",
        hints=("xox",),
    ),
    SecretPattern(
        "slack_token",
        _NOT_WORD + r"xapp-[0-9]-[A-Z0-9]{9,12}-[0-9]{12,16}-[a-f0-9]{60,70}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "Slack app-level token: xapp- prefix and a hexadecimal tail.",
        hints=("xapp-",),
    ),
    SecretPattern(
        "slack_webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}",
        Confidence.HIGH,
        "Slack incoming webhook URL: the documented path with team, bot and 24-character secret.",
        hints=("hooks.slack.com",),
    ),
    SecretPattern(
        "stripe_secret_key",
        _NOT_WORD + r"sk_(?:live|test)_[A-Za-z0-9]{24,99}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "Stripe secret key: sk_live_ or sk_test_ plus 24 or more characters.",
        hints=("sk_live_", "sk_test_"),
    ),
    SecretPattern(
        "stripe_restricted_key",
        _NOT_WORD + r"rk_(?:live|test)_[A-Za-z0-9]{24,99}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "Stripe restricted key: rk_live_ or rk_test_ plus 24 or more characters.",
        hints=("rk_live_", "rk_test_"),
    ),
    SecretPattern(
        "razorpay_key_id",
        _NOT_WORD + r"rzp_(?:live|test)_[A-Za-z0-9]{14}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "Razorpay key id: rzp_live_ or rzp_test_ plus 14 characters.",
        hints=("rzp_live_", "rzp_test_"),
    ),
    SecretPattern(
        "razorpay_key_secret",
        # The key secret is 24 alphanumeric characters with no prefix: keyed on the name.
        r"razorpay[\w.\-]{0,24}?secret[\w.\-]{0,24}?"
        + _VALUE_QUOTE
        + r"([A-Za-z0-9]{24})(?![A-Za-z0-9])",
        Confidence.MEDIUM,
        "Razorpay key secret: 24 alphanumeric characters after a razorpay...secret... name.",
        hints=("razorpay",),
        value_group=1,
        flags=re.IGNORECASE,
    ),
    SecretPattern(
        "paytm_merchant_key",
        # The merchant key is 16 characters with no prefix: keyed on the name.
        r"paytm[\w.\-]{0,24}?key[\w.\-]{0,12}?"
        + _VALUE_QUOTE
        + r"([A-Za-z0-9@#$%&*!_+\-]{16})(?![A-Za-z0-9@#$%&*!_+\-])",
        Confidence.MEDIUM,
        "Paytm merchant key: 16 characters after a paytm...key... name.",
        hints=("paytm",),
        value_group=1,
        flags=re.IGNORECASE,
    ),
    # --- Tokens and keys ------------------------------------------------------------------
    SecretPattern(
        "jwt",
        # Matched loosely (two or three segments) so that the validator, not the regex, decides:
        # a header that is not JSON or a missing segment is not a token.
        _NOT_WORD + r"eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]*)?",
        Confidence.HIGH,
        "JSON Web Token: base64url header starting eyJ, payload and signature.",
        validator=valid_jwt,
        hints=("eyj",),
    ),
    SecretPattern(
        "private_key_block",
        r"-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----"
        r"[\s\S]{0,16000}?-----END \1-----",
        Confidence.HIGH,
        "PEM or PGP private key with matching BEGIN and END lines.",
        validator=valid_private_key_block,
        hints=("-----begin",),
    ),
    SecretPattern(
        "private_key_block",
        # A slice can cut a key in half; the header and a few base64 lines are still the key.
        r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:\r?\n[A-Za-z0-9+/=:, \-]{16,100}){2,200}",
        Confidence.MEDIUM,
        "A private key block whose END line is missing, as when a slice cuts it off.",
        hints=("-----begin",),
    ),
    SecretPattern(
        "ssh_private_key",
        r"-----BEGIN (OPENSSH PRIVATE KEY)-----[\s\S]{0,16000}?-----END \1-----",
        Confidence.HIGH,
        "OpenSSH private key with matching BEGIN and END lines.",
        validator=valid_private_key_block,
        hints=("-----begin openssh",),
    ),
    SecretPattern(
        "connection_string",
        r"(?<![A-Za-z0-9+.\-])(?:jdbc:[a-z0-9]{2,12}:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle)"
        r"://[^\s:/@'\"`]{1,64}:[^\s@'\"`/]{1,128}@[^\s'\"`]{1,256}",
        Confidence.HIGH,
        "Database or broker URL with a user and a non-empty password.",
        validator=valid_connection_string,
        hints=("://",),
        flags=re.IGNORECASE,
    ),
    SecretPattern(
        "basic_auth_url",
        r"(?<![A-Za-z0-9+.\-])https?://[^\s:/@'\"`]{1,64}:[^\s@'\"`/]{1,128}@[^\s'\"`/?#]{1,255}"
        r"(?:[/?#][^\s'\"`]*)?",
        Confidence.HIGH,
        "HTTP(S) URL with a user and a non-empty password in the authority.",
        validator=valid_connection_string,
        hints=("http",),
        flags=re.IGNORECASE,
    ),
    SecretPattern(
        "npm_token",
        _NOT_WORD + r"npm_[A-Za-z0-9]{36}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "npm access token: npm_ plus 36 characters.",
        hints=("npm_",),
    ),
    SecretPattern(
        "pypi_token",
        # 'AgEIcHlwaS5vcmc' is base64 for the macaroon location 'pypi.org', which every PyPI
        # upload token starts with after the 'pypi-' prefix.
        _NOT_WORD + r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}" + r"(?![A-Za-z0-9_\-])",
        Confidence.HIGH,
        "PyPI upload token: pypi- prefix, the encoded pypi.org marker and a long macaroon.",
        hints=("pypi-",),
    ),
    SecretPattern(
        "docker_registry_auth",
        r'"auth"\s*:\s*"([A-Za-z0-9+/]{16,}={0,2})"',
        Confidence.MEDIUM,
        "Docker config auth entry: base64 of user:password.",
        validator=valid_docker_auth,
        hints=('"auth"',),
        value_group=1,
    ),
    SecretPattern(
        "docker_registry_auth",
        _NOT_WORD + r"dckr_pat_[A-Za-z0-9_\-]{27}(?![A-Za-z0-9_\-])",
        Confidence.HIGH,
        "Docker Hub personal access token: dckr_pat_ plus 27 characters.",
        hints=("dckr_pat_",),
    ),
    SecretPattern(
        "twilio_api_key",
        _NOT_WORD + r"SK[0-9a-f]{32}" + _NOT_WORD_AFTER,
        Confidence.HIGH,
        "Twilio API key SID: SK plus 32 hexadecimal characters.",
        hints=("sk",),
    ),
    SecretPattern(
        "sendgrid_api_key",
        _NOT_WORD + r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-])",
        Confidence.HIGH,
        "SendGrid API key: SG. prefix, a 22-character id and a 43-character secret.",
        hints=("sg.",),
    ),
)


class PatternDetector:
    """The ``secret.pattern`` detector: runs the provider patterns over a text.

    ``patterns`` can be narrowed for tests. A pattern runs only when one of its hints occurs in
    the text, so a text with no credential-looking prefix costs a handful of substring searches
    and not 24 regular-expression scans.
    """

    id = DETECTOR_ID
    kinds = frozenset({PlaceholderKind.SECRET})

    def __init__(self, patterns: Sequence[SecretPattern] = SECRET_PATTERNS) -> None:
        self._patterns = tuple((pattern, pattern.compiled()) for pattern in patterns)

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        """Every credential-shaped value in ``text`` that its pattern's validator accepts."""
        raw = text.expose()
        lowered = raw.lower()
        offsets: ByteOffsets | None = None
        spans: list[TypedSpan] = []
        for pattern, compiled in self._patterns:
            if pattern.hints and not any(hint in lowered for hint in pattern.hints):
                continue
            for match in compiled.finditer(raw):
                if pattern.validator is not None and not pattern.validator(
                    match.group(pattern.value_group)
                ):
                    continue
                offsets = offsets or ByteOffsets(raw)
                start, end = match.span(pattern.value_group)
                spans.append(
                    TypedSpan(
                        kind=PlaceholderKind.SECRET,
                        subtype=pattern.subtype,
                        start_byte=offsets.at(start),
                        end_byte=offsets.at(end),
                        confidence=pattern.confidence,
                        detector=self.id,
                    )
                )
        return spans


def pattern_subtypes() -> frozenset[str]:
    """The subtypes the pack uses (a walking test asserts each is in the closed vocabulary)."""
    used = frozenset(pattern.subtype for pattern in SECRET_PATTERNS)
    unknown = used - SECRET_SUBTYPES
    if unknown:
        raise ValueError(f"patterns use subtypes outside the vocabulary: {sorted(unknown)}")
    return used
