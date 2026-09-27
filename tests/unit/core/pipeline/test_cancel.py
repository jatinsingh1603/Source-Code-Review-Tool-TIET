import threading

import pytest

from codekavach.core.pipeline.cancel import CancellationToken, ScanCancelledError
from codekavach.core.pipeline.errors import PipelineError


def cancelled(token: CancellationToken) -> bool:
    """Read the flag through a call so that mypy does not narrow it between assertions."""
    return token.is_cancelled


def test_transitions() -> None:
    token = CancellationToken()
    assert not cancelled(token)
    assert token.reason is None or cancelled(token)
    token.raise_if_cancelled()
    token.cancel("user_interrupt")
    token.cancel("later")
    assert token.is_cancelled
    assert token.reason == "user_interrupt"
    with pytest.raises(ScanCancelledError) as error:
        token.raise_if_cancelled()
    assert error.value.reason == "user_interrupt"
    assert isinstance(error.value, PipelineError)


def test_wait() -> None:
    token = CancellationToken()
    assert token.wait(0.01) is False
    threading.Timer(0.01, token.cancel).start()
    assert token.wait(5) is True


def test_parent_and_child() -> None:
    parent = CancellationToken()
    child = parent.child()
    grandchild = child.child()
    sibling = parent.child()
    sibling.cancel()
    assert not cancelled(parent)
    assert not cancelled(child)
    parent.cancel("deadline")
    assert child.is_cancelled
    assert grandchild.reason == "deadline"


def test_child_of_cancelled_parent_starts_cancelled() -> None:
    parent = CancellationToken()
    parent.cancel("deadline")
    assert parent.child().reason == "deadline"
