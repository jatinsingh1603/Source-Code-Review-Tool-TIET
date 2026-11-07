from app.audit import record_event
from app.db import run_query
from app.rates import monthly_rate


def get_balance(account_id):
    sql = "SELECT balance FROM accounts WHERE id = " + account_id
    row = run_query(sql)
    record_event(account_id)
    return row


def show_rate(account):
    base = monthly_rate(account)
    return base + helper(account)


def helper(account):
    return account * 2
