import jwt


def a(p):
# ruleid: python.crypto.jwt-hardcoded-secret
    return jwt.encode(p, "changeme", algorithm="HS256")


def b(p, key):
# ok: python.crypto.jwt-hardcoded-secret
    return jwt.encode(p, key, algorithm="HS256")
