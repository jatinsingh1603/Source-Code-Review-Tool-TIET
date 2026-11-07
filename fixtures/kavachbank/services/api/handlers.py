"""HTTP request handlers of the KavachBank API."""

from datetime import date

from flask import Flask, abort, g, jsonify, request

import accounts
import db
import interest_engine
import loan_scoring
import reports
import serialisation
from security import require_auth

app = Flask(__name__)


def _owned_account(conn, account_id):
    account = accounts.find_account_by_id(conn, account_id)
    if account is None or account["owner_id"] != g.user["id"]:
        abort(404)
    return account


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/accounts/<account_id>/statement")
@require_auth
def account_statement(account_id):
    conn = db.connect()
    statement = accounts.get_statement(conn, account_id)
    return jsonify(serialisation.dump_statement(statement))


@app.route("/api/accounts/<account_id>/close", methods=["POST"])
def close_account(account_id):
    conn = db.connect()
    accounts.close(conn, account_id)
    return jsonify(status="closed")


@app.route("/api/me/accounts/<account_id>")
@require_auth
def my_account(account_id):
    conn = db.connect()
    account = accounts.find_account_by_id(conn, account_id)
    if account is None or account["owner_id"] != g.user["id"]:
        abort(404)
    return jsonify(account)


@app.route("/api/accounts/<account_id>/interest")
@require_auth
def account_interest(account_id):
    conn = db.connect()
    account = _owned_account(conn, account_id)
    interest = interest_engine.accrue_period(
        account["balance"], account["tenure_years"], account["customer_age"], date.today(), date.today()
    )
    return jsonify(interest=str(interest))


@app.route("/api/loans/eligibility", methods=["POST"])
@require_auth
def loan_eligibility():
    body = request.get_json()
    score = loan_scoring.eligibility_score(
        body["monthly_income"], body["tenure_months"], body["risk_band"], body["existing_emi"]
    )
    return jsonify(score=score, decision=loan_scoring.decision(score))


@app.route("/api/transfers", methods=["POST"])
@require_auth
def create_transfer():
    body = request.get_json()
    conn = db.connect()
    source = _owned_account(conn, body["source_id"])
    result = accounts.transfer(
        conn, source["id"], body["target_id"], body["amount"], body["channel"], body["hour"]
    )
    return jsonify(result)


@app.route("/api/statements/archive", methods=["POST"])
@require_auth
def archive():
    body = request.get_json()
    return jsonify(archive=reports.archive_statements_safely(body["folder"], body["name"]))
