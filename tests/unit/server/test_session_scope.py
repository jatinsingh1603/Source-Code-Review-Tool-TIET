"""The request session commits before the response leaves the server.

With FastAPI's default "request" scope a dependency with ``yield`` ends after the response has
been sent, so a client that created a project and uploaded to it straight away got 404.
"""

from typing import get_args

from codekavach.server.auth.dependencies import SessionDep


def test_the_session_dependency_ends_before_the_response_is_sent() -> None:
    depends = get_args(SessionDep)[1]
    assert depends.scope == "function"
