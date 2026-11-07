import json
from billing.rates import RATE_TABLE


def post(entry):
    data = json.dumps(entry)
    return RATE_TABLE[data]
