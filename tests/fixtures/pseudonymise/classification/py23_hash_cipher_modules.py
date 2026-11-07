import hashlib
import hmac


def digest(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()
