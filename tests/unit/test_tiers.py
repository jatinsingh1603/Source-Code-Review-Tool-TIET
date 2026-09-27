from pathlib import Path

import pytest

from tests.support.tiers import TIERS, tier_of

ROOT = Path("/repo/tests")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (ROOT / "unit/core/test_x.py", "unit"),
        (ROOT / "privacy/test_y.py", "privacy"),
        (ROOT / "process/test_z.py", None),
        (ROOT / "conftest.py", None),
        (Path("/elsewhere/tests/unit/test_x.py"), None),
    ],
)
def test_tier_of(path: Path, expected: str | None) -> None:
    assert tier_of(path, ROOT) == expected


def test_only_own_tier_marker_is_applied(request: pytest.FixtureRequest) -> None:
    assert request.node.get_closest_marker("unit") is not None
    for other in TIERS:
        if other != "unit":
            assert request.node.get_closest_marker(other) is None
