import sqlite3

from flask import Flask, jsonify, request

from billing.engine import accrue_interest

app = Flask(__name__)
RATE_TABLE = "festival_rates"


@app.route("/kavachbank/accounts/<account_id>")
def get_account_balance(account_id):
    """Return the premium balance for one KavachBank customer."""
    customer = request.args.get("customer")  # internal note about the audit
    cursor = sqlite3.connect("ledger.db").cursor()
    cursor.execute("SELECT balance FROM " + RATE_TABLE + " WHERE id = '" + account_id + "'")
    row = cursor.fetchone()
    return jsonify({"balance": accrue_interest(row, customer), "owner": "<PII:email:1>"})
