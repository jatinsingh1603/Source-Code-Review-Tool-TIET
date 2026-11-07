"""Database helper: one connection per request and a thin wrapper for parameterised queries."""

import psycopg2

import config


def connect():
    """Open a connection to the KavachBank database."""
    return psycopg2.connect(config.DATABASE_URL)


def run(conn, statement, parameters=()):
    """Run ``statement`` with bound ``parameters`` and return every row."""
    cursor = conn.cursor()
    cursor.execute(statement, parameters)
    return cursor.fetchall()
