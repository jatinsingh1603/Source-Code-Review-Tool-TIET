def clean(req):
    value = req.args["v"]
    value = "safe"
    value = value + req.args["w"]
    cur.execute("SELECT " + value)
