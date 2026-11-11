import hashlib


def d(p, s):
# ruleid: python.crypto.weak-kdf-iterations
    return hashlib.pbkdf2_hmac("sha256", p, s, 1000)


def d2(p, s):
# ok: python.crypto.weak-kdf-iterations
    return hashlib.pbkdf2_hmac("sha256", p, s, 600000)
