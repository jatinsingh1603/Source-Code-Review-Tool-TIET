from flask import request


def create():
# ruleid: python.mass-assignment.request-splat
    return Account(**request.json)


def create_safe():
# ok: python.mass-assignment.request-splat
    return Account(name=request.json["name"])
