import requests
import ssl


def a(u):
# ruleid: python.crypto.tls-verify-disabled
    return requests.get(u, verify=False)


def b(ctx):
# ruleid: python.crypto.tls-verify-disabled
    ctx.check_hostname = False


def c(u):
# ok: python.crypto.tls-verify-disabled
    return requests.get(u, timeout=5)
