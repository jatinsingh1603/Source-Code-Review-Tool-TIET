from billing import ledger
from billing.engine import accrue_interest


def run(account):
    return accrue_interest(account, ledger)
