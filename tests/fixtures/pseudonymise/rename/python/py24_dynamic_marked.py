class Settings:
    festival_bonus_rate = 5


def read_bonus(settings):
    return getattr(settings, "festival_bonus_rate")
