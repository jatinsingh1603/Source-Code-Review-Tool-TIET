import subprocess
from shlex import quote


def run_report(name):
    safe = quote(name)
    subprocess.run(["report", safe])
    if not safe:
        raise ValueError("bad name")
    return safe
