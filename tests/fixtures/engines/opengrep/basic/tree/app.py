"""Synthetic sample for the engine conformance cases. Not real code."""
import hashlib
import sqlite3
import subprocess

DB_PASSWORD = "synthetic-placeholder"  # pragma: allowlist secret


def find_account(conn: sqlite3.Connection, owner: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE owner = '" + owner + "'")
    return cur.fetchall()


def digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def run(command: str) -> int:
    return subprocess.call(command, shell=True)
