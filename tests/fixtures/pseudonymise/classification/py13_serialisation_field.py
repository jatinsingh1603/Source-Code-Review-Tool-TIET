from dataclasses import dataclass


@dataclass
class Account:
    festival_bonus_rate: float = 0.0
    owner_name: str = ""
