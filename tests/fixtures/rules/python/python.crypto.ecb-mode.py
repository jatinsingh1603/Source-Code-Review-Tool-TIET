from Crypto.Cipher import AES


def e(key):
# ruleid: python.crypto.ecb-mode
    return AES.new(key, AES.MODE_ECB)


def g(key, nonce):
# ok: python.crypto.ecb-mode
    return AES.new(key, AES.MODE_GCM, nonce)
