"""Statement archives for the relationship managers."""

import shlex
import subprocess


def archive_statements(folder, archive_name):
    """Pack a folder of statements into an archive for download."""
    subprocess.run(f"zip -r {archive_name} {folder}", shell=True, check=True)
    return archive_name


def archive_statements_safely(folder, archive_name):
    """Pack a folder of statements into an archive, quoting every argument for the shell."""
    quoted = f"zip -r {shlex.quote(archive_name)} {shlex.quote(folder)}"
    subprocess.run(quoted, shell=True, check=True)
    return archive_name
