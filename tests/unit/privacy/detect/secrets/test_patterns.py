"""``SECRET_PATTERNS`` and the ``secret.pattern`` detector: one positive and one near miss each."""

import pytest

from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect.secrets.patterns import (
    SECRET_PATTERNS,
    PatternDetector,
    SecretPattern,
    pattern_subtypes,
    valid_connection_string,
)
from codekavach.privacy.detect.vocabulary import SECRET_SUBTYPES
from tests.support.synthetic import AWS_EXAMPLE_ACCESS_KEY_ID, synthetic_value

ISSUE_SUBTYPES = frozenset(
    {
        "aws_access_key", "aws_secret_key", "gcp_service_account_key", "gcp_api_key",
        "azure_storage_connection_string", "azure_client_secret", "github_token", "slack_token",
        "slack_webhook", "stripe_secret_key", "stripe_restricted_key", "razorpay_key_id",
        "razorpay_key_secret", "paytm_merchant_key", "jwt", "private_key_block",
        "ssh_private_key", "connection_string", "basic_auth_url", "npm_token", "pypi_token",
        "docker_registry_auth", "twilio_api_key", "sendgrid_api_key",
    }
)  # fmt: skip

# subtype -> (index of the synthetic value, how it appears in a text)
CONTEXT = {
    "aws_secret_key": 'AWS_SECRET_ACCESS_KEY = "{}"',
    "razorpay_key_secret": 'RAZORPAY_KEY_SECRET = "{}"',
    "paytm_merchant_key": 'PAYTM_MERCHANT_KEY = "{}"',
    "docker_registry_auth": '{{"auth": "{}"}}',
}
INDEX = {"jwt": 1}


def sv(subtype: str, index: int = 0) -> str:
    return synthetic_value("secret", subtype, index)


def found(text: str, subtype: str | None = None) -> list[tuple[str, str, str]]:
    """``(subtype, confidence, value)`` of what the pattern detector reports in ``text``."""
    data = text.encode()
    spans = PatternDetector().detect(RawCode(text), path="src/app.py", language=Language.PYTHON)
    return [
        (s.subtype, s.confidence.value, data[s.start_byte : s.end_byte].decode())
        for s in spans
        if subtype is None or s.subtype == subtype
    ]


def test_every_issue_subtype_has_a_pattern_and_all_are_in_the_vocabulary() -> None:
    assert pattern_subtypes() >= ISSUE_SUBTYPES
    assert pattern_subtypes() <= SECRET_SUBTYPES  # the walking test of the issue


def test_every_pattern_has_a_description_and_a_compiled_form() -> None:
    for pattern in SECRET_PATTERNS:
        assert isinstance(pattern, SecretPattern)
        assert pattern.description.endswith(".")
        assert pattern.compiled().pattern == pattern.regex


@pytest.mark.parametrize("subtype", sorted(ISSUE_SUBTYPES))
def test_the_synthetic_value_is_detected_with_its_subtype_and_a_justified_confidence(
    subtype: str,
) -> None:
    value = sv(subtype, INDEX.get(subtype, 0))
    text = CONTEXT.get(subtype, "x = {}").format(value)
    matches = found(text, subtype)
    assert any(item[2] == value for item in matches), matches
    patterns = [p for p in SECRET_PATTERNS if p.subtype == subtype]
    expected = {p.confidence.value for p in patterns}
    assert {item[1] for item in matches if item[2] == value} <= expected
    # HIGH for a documented prefix or a validated structure; MEDIUM only when it keys on a name
    # or the block was cut off.
    if subtype in {"aws_secret_key", "razorpay_key_secret", "paytm_merchant_key"}:
        assert expected == {Confidence.MEDIUM.value}


def test_the_synthetic_aws_example_key_is_aws_access_key_with_high_confidence() -> None:
    assert found(f'k = "{AWS_EXAMPLE_ACCESS_KEY_ID}"') == [
        ("aws_access_key", "high", AWS_EXAMPLE_ACCESS_KEY_ID)
    ]


SHORT_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE"  # pragma: allowlist secret


def armor(edge: str, label: str) -> str:
    """A PEM armor line, assembled so that no literal header sits in this file."""
    return "-----" + edge + " " + label + "-----"


MISMATCHED_PEM = armor("BEGIN", "RSA PRIVATE KEY") + "\nAAAA\n" + armor("END", "EC PRIVATE KEY")

# subtype -> a text that has the right prefix or name but the wrong length, charset or structure
NEAR_MISSES = {
    "aws_access_key": 'k = "AKIAIOSFODNN7EXAMPL"',
    "aws_secret_key": f'AWS_SECRET_ACCESS_KEY = "{SHORT_AWS_SECRET}"',
    "gcp_service_account_key": '{"type": "service_account", "client_email": "a@b.test"}',
    "gcp_api_key": 'k = "AIzaabcdefghijklmnopqrstuvwxyzABCDEFGH"',  # pragma: allowlist secret
    "azure_storage_connection_string": (
        "DefaultEndpointsProtocol=https;AccountName=examplestore;AccountKey=abc=="
    ),
    "azure_client_secret": "abc8Q~tooshort",  # pragma: allowlist secret
    "github_token": "k = ghp_abcdefghijklmnopqrstuvwxyzABCD00000",
    "slack_token": "xoxb-123-abc",
    "slack_webhook": "https://hooks.slack.com/services/T1/B2/short",
    "stripe_secret_key": "k = sk_test_abcdefghijklmnopqrstuvw",  # pragma: allowlist secret
    "stripe_restricted_key": "k = rk_live_short",
    "razorpay_key_id": "k = rzp_test_abcdefghijklm",
    "razorpay_key_secret": 'RAZORPAY_KEY_SECRET = "abcdefghijklmnopqrstuvw"',
    "paytm_merchant_key": 'PAYTM_MERCHANT_KEY = "abcdefghijklmno"',
    "jwt": "x = eyJhbGciOiJIUzI1NiJ9.e30",  # pragma: allowlist secret
    "private_key_block": MISMATCHED_PEM,
    "ssh_private_key": armor("BEGIN", "OPENSSH PRIVATE KEY") + "\nAAAA",
    "connection_string": 'url = "postgres://svc@db.internal/app"',
    "basic_auth_url": 'url = "https://svc@host.test/path"',
    "npm_token": "k = npm_abcdefghijklmnopqrstuvwxyzABCDEFGHI",
    "pypi_token": "k = pypi-AgEIcHlwaS5vcmcshort",
    "docker_registry_auth": '{"auth": "c2VjcmV0c2VjcmV0c2VjcmV0"}',
    "twilio_api_key": "k = SK0123456789abcdef0123456789abcde",  # pragma: allowlist secret
    "sendgrid_api_key": "k = SG.abcdefghijklmnopqrstu.short",  # pragma: allowlist secret
}


def test_every_issue_subtype_has_a_near_miss_case() -> None:
    assert set(NEAR_MISSES) == ISSUE_SUBTYPES


@pytest.mark.parametrize(("subtype", "text"), sorted(NEAR_MISSES.items()))
def test_a_near_miss_is_not_detected_as_that_subtype(subtype: str, text: str) -> None:
    assert found(text, subtype) == []


def test_a_key_with_the_right_prefix_and_the_wrong_length_is_not_detected_by_the_pattern() -> None:
    assert found('k = "AKIAIOSFODNN7EXAMPLEX"') == []  # 21 characters  # pragma: allowlist secret
    assert found('k = "AKIAIOSFODNN7EXAMPL"') == []  # 19 characters


def test_an_identifier_that_contains_a_key_is_not_a_key() -> None:
    assert found(f"prefixed{AWS_EXAMPLE_ACCESS_KEY_ID}") == []
    assert found(f"{AWS_EXAMPLE_ACCESS_KEY_ID}0") == []


def test_a_value_is_reported_once_per_occurrence_with_byte_offsets_in_utf8() -> None:
    text = f"café {AWS_EXAMPLE_ACCESS_KEY_ID} \U0001f600 {AWS_EXAMPLE_ACCESS_KEY_ID}"
    spans = PatternDetector().detect(RawCode(text), path="a.py", language=Language.PYTHON)
    data = text.encode()
    assert [data[s.start_byte : s.end_byte].decode() for s in spans] == [
        AWS_EXAMPLE_ACCESS_KEY_ID
    ] * 2


def test_the_detector_declares_the_secret_kind_and_its_id() -> None:
    detector = PatternDetector()
    assert detector.id == "secret.pattern"
    assert detector.kinds == frozenset({PlaceholderKind.SECRET})


def test_a_text_with_no_hint_costs_no_pattern_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    detector = PatternDetector(
        [SecretPattern("npm_token", r"npm_[A-Za-z0-9]{36}", Confidence.HIGH, "x.", hints=("npm_",))]
    )
    compiled = detector._patterns[0][1]
    calls: list[str] = []

    class Spy:
        def finditer(self, text: str) -> list[object]:
            calls.append(text)
            return []

    monkeypatch.setattr(detector, "_patterns", ((detector._patterns[0][0], Spy()),))
    detector.detect(RawCode("nothing to see"), path="a.py", language=Language.PYTHON)
    assert calls == []
    detector.detect(RawCode("an npm_ prefix"), path="a.py", language=Language.PYTHON)
    assert len(calls) == 1
    assert compiled is not None


def test_connection_validator_accepts_jdbc_prefixes() -> None:
    assert valid_connection_string(
        "jdbc:postgresql://svc:pw1234@db.internal/app"  # pragma: allowlist secret
    )  # pragma: allowlist secret
    assert not valid_connection_string("jdbc:postgresql://svc@db.internal/app")
