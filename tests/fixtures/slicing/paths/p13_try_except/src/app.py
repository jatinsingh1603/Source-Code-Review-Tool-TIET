def read(req):
    name = req.args["f"]
    try:
        handle = open("/srv/" + name)
        return handle.read()
    except OSError:
        return None
