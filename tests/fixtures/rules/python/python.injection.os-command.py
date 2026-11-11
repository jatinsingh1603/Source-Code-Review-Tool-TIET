import os
import shlex


def f(name):
# ruleid: python.injection.os-command
    os.system("ping " + name)


def g(cmd):
# ruleid: python.injection.os-command
    os.popen(cmd)


def h():
# ok: python.injection.os-command
    os.system("uptime")


def i(name):
# ok: python.injection.os-command
    os.system("ping " + shlex.quote(name))
