def save(req):
    target = req.args["t"]
    with open(target, "w") as out:
        out.write(req.data)
    return 1
