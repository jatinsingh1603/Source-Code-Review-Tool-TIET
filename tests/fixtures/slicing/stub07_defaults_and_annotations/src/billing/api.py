from billing.charge import charge


def bill(account):
    receipt = charge(account, 10)
    return receipt
