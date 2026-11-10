from secrets_store.keys import wrap


def post(req):
    token = req.args["t"]
    wrapped = wrap(token)
    return run(wrapped)


def run(command):
    import os
    os.system(command)
