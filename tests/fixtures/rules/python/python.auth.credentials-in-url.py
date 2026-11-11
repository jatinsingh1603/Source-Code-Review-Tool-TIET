import requests


def a(t):
# ruleid: python.auth.credentials-in-url
    return requests.get("https://x.example/api?token=" + t)


def b(t):
# ok: python.auth.credentials-in-url
    return requests.get("https://x.example/api", headers={"X-Token": t})
