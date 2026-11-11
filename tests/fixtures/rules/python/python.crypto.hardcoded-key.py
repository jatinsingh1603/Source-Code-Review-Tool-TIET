from Crypto.Cipher import AES
from cryptography.fernet import Fernet


def k():
# ruleid: python.crypto.hardcoded-key
    return AES.new(b"0123456789abcdef", AES.MODE_GCM)


def f():
# ruleid: python.crypto.hardcoded-key
    return Fernet(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


def k2(key):
# ok: python.crypto.hardcoded-key
    return AES.new(key, AES.MODE_GCM)
