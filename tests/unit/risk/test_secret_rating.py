"""A secret's severity and CVSS follow its type and the detector's confidence, not CWE-798 alone."""

import pytest

from codekavach.analysis.secrets.stage import severity_for
from codekavach.core.models.enums import CandidateKind, Confidence, Severity
from codekavach.risk.context import RatingContext
from codekavach.risk.rating import RatingEngine
from codekavach.risk.taxonomy.loader import default_data_dir, parse_knowledge_base

KB = parse_knowledge_base(default_data_dir())


@pytest.mark.parametrize(
    ("subtype", "confidence", "expected"),
    [
        ("private_key_block", Confidence.HIGH, Severity.CRITICAL),
        ("aws_secret_key", Confidence.HIGH, Severity.CRITICAL),
        ("razorpay_key_secret", Confidence.MEDIUM, Severity.CRITICAL),
        ("aws_access_key", Confidence.HIGH, Severity.HIGH),
        ("github_token", Confidence.HIGH, Severity.HIGH),
        ("razorpay_key_id", Confidence.HIGH, Severity.LOW),
        ("generic_credential", Confidence.MEDIUM, Severity.MEDIUM),
        ("generic_credential", Confidence.LOW, Severity.LOW),
        ("high_entropy_string", Confidence.LOW, Severity.LOW),
        ("private_key_block", Confidence.LOW, Severity.HIGH),
    ],
)
def test_secret_severity_depends_on_type_and_confidence(
    subtype: str, confidence: Confidence, expected: Severity
) -> None:
    assert severity_for(subtype, confidence) is expected


@pytest.mark.parametrize(
    ("engine", "low", "high"),
    [
        (Severity.CRITICAL, 9.0, 10.0),
        (Severity.HIGH, 7.0, 8.9),
        (Severity.MEDIUM, 4.0, 6.9),
        (Severity.LOW, 0.1, 3.9),
    ],
)
def test_secret_rating_and_cvss_agree_with_the_secret_engine(
    engine: Severity, low: float, high: float
) -> None:
    context = RatingContext(cwe=(798,), kind=CandidateKind.SECRET, engine_severity=engine)
    result = RatingEngine(KB).rate(context, confidence=Confidence.HIGH)
    assert result.severity is engine
    assert low <= result.cvss4_score <= high
    assert "severity_ladder" in result.adjustments
