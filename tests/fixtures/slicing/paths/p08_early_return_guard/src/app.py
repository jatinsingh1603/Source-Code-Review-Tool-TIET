def fetch(req):
    ident = req.args["id"]
    if ident is None:
        return None
    other = compute(ident)
    cur.execute("SELECT * FROM t WHERE id = " + ident)
    return other
