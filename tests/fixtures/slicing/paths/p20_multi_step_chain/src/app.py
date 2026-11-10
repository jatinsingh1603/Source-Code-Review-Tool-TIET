def chain(req):
    raw = req.args["x"]
    step1 = raw.strip()
    step2 = step1.lower()
    step3 = step2 + "%"
    cur.execute("SELECT * FROM t WHERE c LIKE '" + step3 + "'")
