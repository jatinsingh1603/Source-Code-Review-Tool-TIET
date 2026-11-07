from billing.bonus import compute_bonus


def accrue(account_id, rate):
    bonus = compute_bonus(rate, account_id)
    return bonus
