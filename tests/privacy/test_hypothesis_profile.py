import os
from datetime import timedelta
from typing import Any

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
