import hashlib


def h(password):
# ruleid: python.crypto.weak-hash
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def h2(data):
# ok: python.crypto.weak-hash
    return hashlib.sha256(data).hexdigest()


def h3(data):
# ok: python.crypto.weak-hash
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
