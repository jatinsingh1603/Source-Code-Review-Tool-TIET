from dataclasses import dataclass


@dataclass
class Receipt:
    receipt_number: str
    total_paid: int


def to_json(receipt):
    return {"receipt_number": receipt.receipt_number, "total_paid": receipt.total_paid}
