import sqlite3


def find(conn, values):
    cur = conn.cursor()
    cur.execute("SELECT 1", params=values)
    return cur.fetchall()
