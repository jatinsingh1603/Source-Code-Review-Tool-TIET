import pytest


def test_privacy_marker_is_applied(request: pytest.FixtureRequest) -> None:
    assert request.node.get_closest_marker("privacy") is not None
    assert request.node.get_closest_marker("unit") is None
