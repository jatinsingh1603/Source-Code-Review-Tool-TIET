"""Fraud thresholds by channel, and the rules that use them."""

from decimal import Decimal

# Largest single transfer allowed without a step-up check, by channel.
SINGLE_TRANSFER_LIMIT = {
    "upi": Decimal("100000"),
    "card": Decimal("200000"),
    "netbanking": Decimal("500000"),
    "branch": Decimal("1000000"),
}
# Transfers allowed in ten minutes before the velocity rule fires, by channel.
VELOCITY_LIMIT = {"upi": 8, "card": 5, "netbanking": 6, "branch": 3}
NEW_BENEFICIARY_COOLDOWN_HOURS = 24
NEW_BENEFICIARY_LIMIT = Decimal("50000")
NIGHT_HOURS = range(0, 5)
NIGHT_LIMIT_FACTOR = Decimal("0.5")
HIGH_RISK_COUNTRIES = frozenset({"KP", "IR", "SY"})


def transfer_limit(channel, hour):
    """The single-transfer limit for ``channel`` at ``hour``."""
    limit = SINGLE_TRANSFER_LIMIT[channel]
    if hour in NIGHT_HOURS:
        limit = limit * NIGHT_LIMIT_FACTOR
    return limit


def velocity_breached(channel, recent_transfers):
    """Whether ``recent_transfers`` in the last ten minutes exceeds the channel's velocity limit."""
    return recent_transfers > VELOCITY_LIMIT[channel]


def new_beneficiary_blocked(amount, hours_since_added):
    """A new beneficiary may only receive a small amount during the cooling-off period."""
    return hours_since_added < NEW_BENEFICIARY_COOLDOWN_HOURS and amount > NEW_BENEFICIARY_LIMIT


def assess(channel, amount, hour, recent_transfers, hours_since_added, country):
    """The fraud reasons for one transfer; an empty list means the transfer may proceed."""
    reasons = []
    if amount > transfer_limit(channel, hour):
        reasons.append("over_channel_limit")
    if velocity_breached(channel, recent_transfers):
        reasons.append("velocity")
    if new_beneficiary_blocked(amount, hours_since_added):
        reasons.append("new_beneficiary")
    if country in HIGH_RISK_COUNTRIES:
        reasons.append("high_risk_country")
    return reasons
