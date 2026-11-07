"""The KavachBank fee schedule: monthly maintenance, transfers and penalties, with waivers."""

from decimal import Decimal

MAINTENANCE_FEE = {
    "basic": Decimal("0.00"),
    "silver": Decimal("150.00"),
    "gold": Decimal("300.00"),
    "premium": Decimal("500.00"),
}
MINIMUM_AVERAGE_BALANCE = {
    "basic": Decimal("0"),
    "silver": Decimal("25000"),
    "gold": Decimal("100000"),
    "premium": Decimal("500000"),
}
SALARY_ACCOUNT_WAIVER_MONTHS = 6
STUDENT_AGE_LIMIT = 25

# (largest amount of the slab, fee); transfers above the last slab cost the last fee.
NEFT_SLABS = (
    (Decimal("10000"), Decimal("2.50")),
    (Decimal("100000"), Decimal("5.00")),
    (Decimal("200000"), Decimal("15.00")),
    (None, Decimal("25.00")),
)
CHEQUE_BOUNCE_PENALTY = Decimal("350.00")
OVERDRAFT_DAILY_RATE = Decimal("0.0006")
GST_RATE = Decimal("0.18")


def maintenance_waived(account_type, average_balance, is_salary_account, months_since_credit):
    """Whether this month's maintenance fee is waived."""
    if average_balance >= MINIMUM_AVERAGE_BALANCE[account_type]:
        return True
    if is_salary_account and months_since_credit < SALARY_ACCOUNT_WAIVER_MONTHS:
        return True
    return False


def monthly_maintenance_fee(account_type, average_balance, customer_age, is_salary_account):
    """The maintenance fee including GST, after the waivers."""
    if customer_age <= STUDENT_AGE_LIMIT and account_type == "basic":
        return Decimal("0.00")
    if maintenance_waived(account_type, average_balance, is_salary_account, 0):
        return Decimal("0.00")
    fee = MAINTENANCE_FEE[account_type]
    return (fee * (1 + GST_RATE)).quantize(Decimal("0.01"))


def neft_fee(amount):
    """The NEFT transfer fee for ``amount``."""
    for largest, fee in NEFT_SLABS:
        if largest is None or amount <= largest:
            return fee
    raise ValueError("the last slab must have no bound")


def overdraft_penalty(overdrawn_amount, days):
    """Penalty interest on an overdrawn balance."""
    return (overdrawn_amount * OVERDRAFT_DAILY_RATE * days).quantize(Decimal("0.01"))


def cheque_return_charge(reason):
    """The charge for a returned cheque; a bank error is never charged."""
    if reason == "bank_error":
        return Decimal("0.00")
    return CHEQUE_BOUNCE_PENALTY
