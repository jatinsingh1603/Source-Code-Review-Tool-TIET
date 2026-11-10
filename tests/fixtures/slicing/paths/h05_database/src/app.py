def lookup(cur, ident):
    query = "SELECT * FROM t WHERE id = " + ident
    cur.execute(query)
    return cur.fetchall()
