import sqlite3


def run_query(statement):
    connection = sqlite3.connect("ledger.db")
    cursor = connection.cursor()
    cursor.execute(statement)
    return cursor.fetchone()
