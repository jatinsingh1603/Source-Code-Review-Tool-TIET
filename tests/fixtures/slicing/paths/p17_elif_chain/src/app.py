def route(req, db):
    kind = req.args["kind"]
    value = req.args["value"]
    if kind == "a":
        db.execute("A " + value)
    elif kind == "b":
        db.execute("B " + value)
    else:
        raise ValueError(kind)
