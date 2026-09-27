import subprocess
import sys

import codekavach


def test_python_m_codekavach_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "codekavach", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"codekavach {codekavach.__version__}"
