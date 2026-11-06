import subprocess


def run(cmd):
    out = subprocess.run("ls " + cmd, shell=True)
    return out


def other():
    return 1
