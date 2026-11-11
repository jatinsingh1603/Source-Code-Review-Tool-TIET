def a(resp):
# ruleid: python.session.cookie-no-httponly
    resp.set_cookie("sid", "v", secure=True)


def b(resp):
# ok: python.session.cookie-no-httponly
    resp.set_cookie("sid", "v", secure=True, httponly=True)
