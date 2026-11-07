import os
from json import dumps


def show(path):
    return dumps({"cwd": os.getcwd(), "name": path})
