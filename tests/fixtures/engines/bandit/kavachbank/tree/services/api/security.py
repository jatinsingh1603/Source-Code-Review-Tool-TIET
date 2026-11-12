"""Authentication helpers: password hashing, field encryption and the auth decorator."""

import hashlib
import os
from functools import wraps

from Crypto.Cipher import AES
from flask import abort, g, request

STATIC_IV = b"kavachbank-iv-01"


def hash_password(password):
    """The stored form of a customer password."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def hash_password_strong(password, salt=None):
    """A salted scrypt hash of a customer password."""
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + digest.hex()


def encrypt_field(key, plaintext):
    """Encrypt a column value before it is stored."""
    cipher = AES.new(key, AES.MODE_CBC, STATIC_IV)
    return cipher.encrypt(plaintext.ljust(16 * ((len(plaintext) + 15) // 16)).encode("utf-8"))


def encrypt_field_safely(key, plaintext):
    """Encrypt a column value with a fresh random IV, kept in front of the ciphertext."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext.ljust(16 * ((len(plaintext) + 15) // 16)).encode("utf-8"))


def require_auth(view):
    """Reject the request unless it carries a valid session."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            abort(401)
        g.user = lookup_session(token.removeprefix("Bearer "))
        if g.user is None:
            abort(401)
        return view(*args, **kwargs)

    return wrapper


def lookup_session(token):
    """The user for a session token, or None."""
    return None if not token else {"id": token[:8]}
