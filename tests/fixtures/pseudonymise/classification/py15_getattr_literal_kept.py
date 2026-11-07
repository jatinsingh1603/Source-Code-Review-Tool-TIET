def read_bonus(account):
    return getattr(account, "festival_bonus_rate", 0.0)
