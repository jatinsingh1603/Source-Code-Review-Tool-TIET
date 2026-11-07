def festival_rate():
    return 1.1


def read_rate(account):
    return getattr(account, "festival_rate")()
