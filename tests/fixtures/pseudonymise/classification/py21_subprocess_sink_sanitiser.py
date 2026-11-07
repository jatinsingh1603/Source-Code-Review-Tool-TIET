import shlex
import subprocess


def run_tool(target):
    return subprocess.run(["tool", shlex.quote(target)], check=True)
