import os


def read(name):
# ruleid: python.path.file-from-dynamic-path
    return open("/data/" + name)


from flask import request

def read2():
# ruleid: python.path.file-from-dynamic-path
    return open(request.args["f"])


def read_fixed():
# ok: python.path.file-from-dynamic-path
    return open("/data/report.txt")


def read_safe(name):
# ok: python.path.file-from-dynamic-path
    return open("/data/" + os.path.basename(name))
