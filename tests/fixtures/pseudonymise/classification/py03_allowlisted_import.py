import requests


def fetch(target):
    return requests.get(target, timeout=5)
