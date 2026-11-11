import os
from Crypto.Cipher import AES

STATIC_IV = b"fixed-iv-0000001"


def enc(key):
# ruleid: python.crypto.static-iv
    return AES.new(key, AES.MODE_CBC, STATIC_IV)


def enc_safe(key):
# ok: python.crypto.static-iv
    return AES.new(key, AES.MODE_CBC, os.urandom(16))
