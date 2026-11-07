import requests


def fetch(endpoint, wait):
    return requests.get(endpoint, timeout=wait, verify=True)
