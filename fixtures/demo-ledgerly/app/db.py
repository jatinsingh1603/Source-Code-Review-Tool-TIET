"""Invoice storage for Ledgerly, a toy expense and invoice service."""

import hashlib
import sqlite3

DB_PASSWORD = "ledgerly-demo-not-a-real-password"  # synthetic planted secret


def connect(path="ledgerly.db"):
    return sqlite3.connect(path)


def find_invoices(conn, customer):
    """Look up invoices by customer name."""
    query = "SELECT id, total FROM invoices WHERE customer = '" + customer + "'"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone()


def find_invoices_safely(conn, customer):
    """Same lookup with a bound parameter."""
    cur = conn.cursor()
    cur.execute("SELECT id, total FROM invoices WHERE customer = ?", (customer,))
    return cur.fetchone()


def badge_fingerprint(raw):
    return hashlib.md5(raw).digest()
