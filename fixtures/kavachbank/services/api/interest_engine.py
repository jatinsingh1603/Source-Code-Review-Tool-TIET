"""Interest accrual for KavachBank savings and fixed-deposit accounts.

Rates are tiered by balance, loyal customers earn a tenure uplift, and every account earns the
festival bonus on its balance during the festival season.
"""

from datetime import date
from decimal import ROUND_HALF_EVEN, Decimal

PAISE = Decimal("0.01")
DAYS_IN_YEAR = Decimal("365")
FESTIVAL_RATE = Decimal("0.0025")
FESTIVAL_MONTHS = frozenset({10, 11})
LOYALTY_TENURE_YEARS = 5
LOYALTY_UPLIFT = Decimal("0.0010")
SENIOR_CITIZEN_UPLIFT = Decimal("0.0050")
SENIOR_CITIZEN_AGE = 60

# (upper bound of the tier, annual rate); the last tier has no bound.
SAVINGS_TIERS = (
    (Decimal("100000"), Decimal("0.0300")),
    (Decimal("500000"), Decimal("0.0375")),
    (None, Decimal("0.0450")),
)
FIXED_DEPOSIT_TIERS = (
    (Decimal("200000"), Decimal("0.0650")),
    (Decimal("1000000"), Decimal("0.0690")),
    (None, Decimal("0.0725")),
)


def _money(amount):
    return amount.quantize(PAISE, rounding=ROUND_HALF_EVEN)


def tiered_annual_rate(balance, tiers=SAVINGS_TIERS):
    """The annual rate of the tier that ``balance`` falls in."""
    for upper_bound, rate in tiers:
        if upper_bound is None or balance <= upper_bound:
            return rate
    raise ValueError("the last tier must have no upper bound")


def loyalty_uplift(tenure_years, customer_age):
    """Extra annual rate for long-standing and senior customers."""
    uplift = Decimal("0")
    if tenure_years >= LOYALTY_TENURE_YEARS:
        uplift += LOYALTY_UPLIFT
    if customer_age >= SENIOR_CITIZEN_AGE:
        uplift += SENIOR_CITIZEN_UPLIFT
    return uplift


def accrue_daily_interest(balance, tenure_years, customer_age, tiers=SAVINGS_TIERS):
    """Interest for one day on ``balance`` at the tiered rate plus the loyalty uplift."""
    annual_rate = tiered_annual_rate(balance, tiers) + loyalty_uplift(tenure_years, customer_age)
    return _money(balance * annual_rate / DAYS_IN_YEAR)


def accrue_festival_bonus(balance, on):
    """The festival bonus credited for one day of the festival season, otherwise zero."""
    if on.month not in FESTIVAL_MONTHS:
        return Decimal("0.00")
    return _money(balance * FESTIVAL_RATE / DAYS_IN_YEAR)


def accrue_period(balance, tenure_years, customer_age, first_day, last_day):
    """Total interest and festival bonus for the days ``first_day`` to ``last_day`` inclusive."""
    total = Decimal("0.00")
    day = first_day
    while day <= last_day:
        total += accrue_daily_interest(balance, tenure_years, customer_age)
        total += accrue_festival_bonus(balance, day)
        day = date.fromordinal(day.toordinal() + 1)
    return _money(total)


def maturity_value(principal, years, customer_age, tiers=FIXED_DEPOSIT_TIERS):
    """Fixed-deposit maturity value with quarterly compounding."""
    quarterly_rate = (tiered_annual_rate(principal, tiers) + loyalty_uplift(0, customer_age)) / 4
    value = principal
    for _ in range(int(years * 4)):
        value += value * quarterly_rate
    return _money(value)
