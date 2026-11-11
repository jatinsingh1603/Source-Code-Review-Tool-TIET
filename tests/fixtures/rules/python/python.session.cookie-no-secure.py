def a(resp):
# ruleid: python.session.cookie-no-secure
    resp.set_cookie("sid", "v", httponly=True)


def b(resp):
# ok: python.session.cookie-no-secure
    resp.set_cookie("sid", "v", secure=True, httponly=True)
