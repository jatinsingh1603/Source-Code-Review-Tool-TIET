import shlex
import subprocess


def archive(folder, name):
# ruleid: python.injection.subprocess-shell
    subprocess.run(f"zip -r {name} {folder}", shell=True, check=True)


def archive_safe(folder, name):
# ok: python.injection.subprocess-shell
    subprocess.run(["zip", "-r", name, folder], check=True)


def archive_quoted(folder):
# ok: python.injection.subprocess-shell
    subprocess.run("zip " + shlex.quote(folder), shell=True)
