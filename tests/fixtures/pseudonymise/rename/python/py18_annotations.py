from typing import Optional


class Money:
    cents: int


def convert(amount: Money, rate: float = 1.0) -> Optional[Money]:
    return amount
