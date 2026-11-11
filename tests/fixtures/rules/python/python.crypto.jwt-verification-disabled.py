import jwt


def a(t):
# ruleid: python.crypto.jwt-verification-disabled
    return jwt.decode(t, options={"verify_signature": False})


def b(t):
# ruleid: python.crypto.jwt-verification-disabled
    return jwt.decode(t, verify=False)


def c(t, key):
# ok: python.crypto.jwt-verification-disabled
    return jwt.decode(t, key, algorithms=["HS256"])
