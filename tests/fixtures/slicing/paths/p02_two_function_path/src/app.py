def handler(req):
    name = req.args["name"]
    unused = req.args["unused"]
    return lookup(name)


def lookup(term):
    sql = "SELECT * FROM users WHERE name = '" + term + "'"
    return cur.execute(sql)
