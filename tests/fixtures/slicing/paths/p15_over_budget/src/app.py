def big(req):
    a1 = req.args["a1"]
    a2 = a1 + "1"
    a3 = a2 + "2"
    a4 = a3 + "3"
    a5 = a4 + "4"
    a6 = a5 + "5"
    a7 = a6 + "6"
    a8 = a7 + "7"
    if not req.user.ok:
        raise Forbidden()
    cur.execute("SELECT " + a8)
