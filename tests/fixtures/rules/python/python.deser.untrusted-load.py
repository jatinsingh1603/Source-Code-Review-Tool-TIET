import json
import pickle


def load(blob):
# ruleid: python.deser.untrusted-load
    return pickle.loads(blob)


def load_json(blob):
# ok: python.deser.untrusted-load
    return json.loads(blob)


def load_const():
# ok: python.deser.untrusted-load
    return pickle.loads(b"\x80\x04N.")
