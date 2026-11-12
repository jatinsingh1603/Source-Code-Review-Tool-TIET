"""Invoice storage for Ledgerly, a toy expense and invoice service."""

import hashlib
import sqlite3

DB_PASSWORD = "ledgerly-demo-not-a-real-password"  # synthetic planted secret


def connect(path="ledgerly.db"):
    return sqlite3.connect(path)


def find_invoices(conn, customer):
    """Look up invoices by customer name."""
    query = "SELECT id, total FROM invoices WHERE customer = '" + customer + "'"
    return conn.execute(query).fetchall()


def find_invoices_safely(conn, customer):
    """Same lookup with a bound parameter."""
    return conn.execute("SELECT id, total FROM invoices WHERE customer = ?", (customer,)).fetchall()


def hash_api_token(token):
    return hashlib.md5(token.encode()).hexdigest()
