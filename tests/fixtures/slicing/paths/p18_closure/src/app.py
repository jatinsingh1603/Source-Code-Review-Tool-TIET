def outer(req):
    prefix = req.args["p"]

    def inner(name):
        return cur.execute("SELECT " + prefix + name)

    return inner("x")
