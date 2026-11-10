def report(rows):
    total = 0
    clause = ""
    for row in rows:
        clause = clause + row.filter
        total += row.amount
    cur.execute("SELECT * FROM t WHERE " + clause)
    return total
