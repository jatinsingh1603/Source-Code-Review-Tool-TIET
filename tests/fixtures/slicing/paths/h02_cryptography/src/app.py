import hashlib


def digest(password):
    salt = "s"
    return hashlib.md5((salt + password).encode()).hexdigest()
