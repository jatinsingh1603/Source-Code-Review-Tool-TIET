def charge(account: Account, amount: Decimal = Decimal("0.00"), *, memo: str = "festival bonus", tags=("a", "b"), **extra) -> Receipt:
    """Charge it."""
    # note: KavachBank only
    return Receipt(account, amount)
