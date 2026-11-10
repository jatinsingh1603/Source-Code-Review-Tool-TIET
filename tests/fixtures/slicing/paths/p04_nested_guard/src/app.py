def update(req, db):
    ident = req.args["id"]
    if req.user.is_staff:
        if ident:
            db.execute("DELETE FROM t WHERE id = " + ident)
    return None
