import shutil
import subprocess
import sys
from pathlib import Path

import codekavach


def test_console_script_resolves_in_project_environment() -> None:
    executable = shutil.which("codekavach", path=str(Path(sys.executable).parent))
    assert executable is not None
    result = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"codekavach {codekavach.__version__}\n"
