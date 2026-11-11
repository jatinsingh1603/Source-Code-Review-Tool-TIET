import os


def a(p):
    if os.path.exists(p):
# ruleid: python.race.exists-then-open
        return open(p).read()


def b(p):
    if os.path.exists(p):
# ok: python.race.exists-then-open
        return True
