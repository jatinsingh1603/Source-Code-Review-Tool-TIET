import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings

EXPECTED: dict[str, dict[str, Any]] = {
    "dev": {"max_examples": 50, "deadline": timedelta(milliseconds=500), "derandomize": False},
    "ci": {"max_examples": 200, "deadline": None, "derandomize": True},
    "nightly": {"max_examples": 2000, "deadline": None, "derandomize": False},
}


def test_active_profile_matches_table() -> None:
    name = os.environ.get("HYPOTHESIS_PROFILE", "dev")
    current = settings()
    for key, value in EXPECTED[name].items():
        assert getattr(current, key) == value, key
    if name == "ci":
        assert current.derandomize is True
        assert current.deadline is None
        assert current.print_blob is True


@pytest.mark.parametrize("name", ["dev", "nightly"])
def test_a_ci_environment_does_not_derandomise_the_other_profiles(name: str) -> None:
    """CI=true derandomises hypothesis defaults; dev and nightly must not inherit that."""
    code = (
        "import tests.conftest; "
        "from hypothesis import settings; "
        f"settings.load_profile({name!r}); "
        "print(settings().derandomize)"
    )
    env = {**os.environ, "CI": "true"}
    env.pop("HYPOTHESIS_PROFILE", None)
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env, cwd=root, check=False, timeout=60,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
