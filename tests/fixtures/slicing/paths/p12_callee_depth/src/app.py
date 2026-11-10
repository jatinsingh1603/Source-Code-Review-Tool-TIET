def entry(req):
    value = req.args["v"]
    return first(value)


def first(a):
    return second(a)


def second(b):
    return third(b)


def third(c):
    cur.execute("SELECT " + c)
