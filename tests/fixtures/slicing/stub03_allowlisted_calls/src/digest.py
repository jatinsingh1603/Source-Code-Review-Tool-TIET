import json
import hashlib


def digest(payload):
    text = json.dumps(payload)
    return hashlib.sha256(text.encode()).hexdigest()
