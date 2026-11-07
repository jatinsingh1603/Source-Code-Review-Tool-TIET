from billing.engine import accrue_interest


def charge(account, rate):
    return accrue_interest(account, rate=rate)
