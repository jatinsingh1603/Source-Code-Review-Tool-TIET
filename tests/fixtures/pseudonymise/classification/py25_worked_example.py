from flask import request
from billing.engine import accrue_interest


@app.route("/accounts/<aid>")
def get_account(aid):
    rate = request.args.get("rate", type=float)
    return accrue_interest(aid, rate=rate)
