from core.store import save


def post(req):
    body = req.data
    return save(body)
