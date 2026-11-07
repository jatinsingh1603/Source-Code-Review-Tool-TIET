"""Loan eligibility: a score from income, tenure and the internal risk band."""

from decimal import Decimal

RISK_BAND_POINTS = {"A1": 40, "A2": 32, "B1": 24, "B2": 16, "C1": 8, "D1": -20}
MAX_SCORE = 100
APPROVAL_SCORE = 60
REFERRAL_SCORE = 45
INCOME_MULTIPLE = {"home": Decimal("60"), "vehicle": Decimal("36"), "personal": Decimal("12")}
MAX_EMI_TO_INCOME = Decimal("0.45")
MIN_TENURE_MONTHS = 6


def income_points(monthly_income):
    """Up to 35 points for a steady monthly income."""
    if monthly_income >= Decimal("150000"):
        return 35
    if monthly_income >= Decimal("75000"):
        return 28
    if monthly_income >= Decimal("40000"):
        return 20
    if monthly_income >= Decimal("20000"):
        return 10
    return 0


def tenure_points(tenure_months):
    """Up to 25 points for how long the customer has banked with KavachBank."""
    if tenure_months < MIN_TENURE_MONTHS:
        return 0
    return min(25, tenure_months // 6 * 2)


def eligibility_score(monthly_income, tenure_months, risk_band, existing_emi):
    """The eligibility score, capped to ``MAX_SCORE``."""
    score = income_points(monthly_income) + tenure_points(tenure_months)
    score += RISK_BAND_POINTS[risk_band]
    if existing_emi > monthly_income * MAX_EMI_TO_INCOME:
        score -= 30
    return max(0, min(MAX_SCORE, score))


def decision(score):
    """approve, refer to an officer, or decline."""
    if score >= APPROVAL_SCORE:
        return "approve"
    if score >= REFERRAL_SCORE:
        return "refer"
    return "decline"


def maximum_loan(monthly_income, loan_type, risk_band):
    """The largest loan we would offer, before the officer's review."""
    ceiling = monthly_income * INCOME_MULTIPLE[loan_type]
    if risk_band in ("C1", "D1"):
        ceiling = ceiling / 2
    return ceiling.quantize(Decimal("1"))
