"""Performance budget of literal shaping (E09-03).

Shaping a slice with 100 literals of mixed kinds takes under 15 ms, because a scan shapes every
candidate's literals. The budget is scaled by the performance factor.
"""

import pytest

from codekavach.core.models import Location, PrivacyLevel
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing.models import LiteralKind, LiteralSpan
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.literals import shape
from tests.support.perf import assert_within_budget, measure

BUDGET_SECONDS = 0.015
SALT = ScanSalt(bytes(range(32)))

SAMPLES: tuple[tuple[LiteralKind, str], ...] = (
    ("sql", "SELECT balance, festival_bonus FROM premium_accounts WHERE customer_id = '%s'"),
    ("url", "https://billing.example.test:8443/v2/customers/{id}/invoices?token=abc123"),
    ("path", "../templates/welcome_email/customer_reports/q3_summary.html"),
    ("format", "Dear {customer_name}, your balance is {0:>10.2f} for %s today"),
    ("regex", r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"),
    ("natural", "Customer festival bonus is ready soon for the premium account"),
)


class Allow:
    def is_public(self, word: str) -> bool:
        return False


def _spans() -> list[LiteralSpan]:
    spans: list[LiteralSpan] = []
    for index in range(100):
        kind, text = SAMPLES[index % len(SAMPLES)]
        location = Location(
            path="svc.py", start_line=index + 1, end_line=index + 1, start_col=1, end_col=2
        )
        spans.append(LiteralSpan(location=location, kind=kind, raw_text=text))
    return spans


@pytest.mark.perf
def test_one_hundred_literals_stay_within_budget() -> None:
    spans = _spans()

    def shape_all() -> None:
        generator = PseudonymGenerator(SALT)
        for span in spans:
            shape(span, generator=generator, allowlist=Allow(), level=PrivacyLevel.L3)

    shape_all()  # warm the regular-expression caches

    assert_within_budget(measure(shape_all, repeat=10), BUDGET_SECONDS, label="100 literals")
