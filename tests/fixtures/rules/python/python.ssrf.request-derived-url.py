import requests
from urllib.parse import urlparse


def fetch(url):
# ruleid: python.ssrf.request-derived-url
    return requests.get(url)


def fetch_fixed():
# ok: python.ssrf.request-derived-url
    return requests.get("https://api.example.com/rates")


def fetch_allowed(url):
    if urlparse(url).hostname not in ALLOWED:
        raise ValueError(url)
# ok: python.ssrf.request-derived-url
    return requests.get(url)
