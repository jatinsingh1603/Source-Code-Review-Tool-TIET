from flask import request
from billing.engine import accrue_interest


def handle(:
    rate = request.args.get("rate")
    return accrue_interest(rate=rate)
