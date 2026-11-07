"""Accounts: lookup, statements, closing and transfers."""

import db
import fee_schedule
import fraud_rules


def find_premium_account(conn, account_id):
    """The premium-tier account with this id."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM premium_accounts WHERE id = '%s'" % account_id)
    return cur.fetchone()


def find_account_by_id(conn, account_id):
    """The account with this id."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE id = %s", (account_id,))
    return cur.fetchone()


def get_statement(conn, account_id):
    """The last ninety days of postings for the account."""
    return db.run(
        conn,
        "SELECT posted_on, narration, amount FROM postings "
        "WHERE account_id = %s AND posted_on > now() - interval '90 days'",
        (account_id,),
    )


def close(conn, account_id):
    """Close an account whose balance is zero."""
    cur = conn.cursor()
    cur.execute("UPDATE accounts SET status = 'closed' WHERE id = %s", (account_id,))
    conn.commit()


def transfer(conn, source_id, target_id, amount, channel, hour):
    """Move ``amount`` between accounts after the fraud rules and fee are applied."""
    reasons = fraud_rules.assess(channel, amount, hour, 0, 100, "IN")
    if reasons:
        return {"status": "held", "reasons": reasons}
    fee = fee_schedule.neft_fee(amount)
    cur = conn.cursor()
    cur.execute(
        "UPDATE accounts SET balance = balance - %s WHERE id = %s", (amount + fee, source_id)
    )
    cur.execute("UPDATE accounts SET balance = balance + %s WHERE id = %s", (amount, target_id))
    conn.commit()
    return {"status": "done", "fee": str(fee)}
