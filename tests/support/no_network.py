"""Refuse and record network access and record subprocesses (regression guard for I1).

The default test run already blocks sockets through ``pytest-socket``. This helper adds a record
of every attempt, so that a test can assert that the count is zero even when the code under test
swallowed the exception. DNS lookups are refused too: they are network access and leak host names.
"""

import contextlib
import os
import socket
import ssl
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

import pytest


@dataclass
class NetworkAttempts:
    """What tried to reach the network while ``refuse_network`` was active."""

    attempts: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        """How many attempts were made."""
        return len(self.attempts)

    def refuse(self, what: str) -> NoReturn:
        """Record the attempt and fail the caller."""
        self.attempts.append(what)
        raise AssertionError(f"network access attempted: {what}")


@contextlib.contextmanager
def refuse_network() -> Iterator[NetworkAttempts]:
    """Make ``socket.socket``, ``create_connection``, ``getaddrinfo`` and TLS wrapping raise."""
    recorder = NetworkAttempts()
    original_socket: Any = socket.socket

    class RefusedSocket(original_socket):  # type: ignore[misc]
        """Stands in for ``socket.socket``; creating one is an attempt."""

        def __new__(cls, *args: Any, **kwargs: Any) -> "RefusedSocket":
            recorder.refuse(f"socket.socket{args!r}")

    def create_connection(address: Any, *_args: Any, **_kwargs: Any) -> NoReturn:
        recorder.refuse(f"socket.create_connection({address!r})")

    def getaddrinfo(host: Any, port: Any, *_args: Any, **_kwargs: Any) -> NoReturn:
        recorder.refuse(f"socket.getaddrinfo({host!r}, {port!r})")

    def wrap_socket(_self: Any, *_args: Any, **kwargs: Any) -> NoReturn:
        recorder.refuse(
            f"ssl.SSLContext.wrap_socket(server_hostname={kwargs.get('server_hostname')!r})"
        )

    saved = (
        socket.socket,
        socket.create_connection,
        socket.getaddrinfo,
        ssl.SSLContext.wrap_socket,
    )
    socket.socket = RefusedSocket  # type: ignore[misc]
    socket.create_connection = create_connection
    socket.getaddrinfo = getaddrinfo
    ssl.SSLContext.wrap_socket = wrap_socket  # type: ignore[method-assign,assignment]
    try:
        yield recorder
    finally:
        socket.socket = saved[0]  # type: ignore[misc]
        socket.create_connection = saved[1]
        socket.getaddrinfo = saved[2]
        ssl.SSLContext.wrap_socket = saved[3]  # type: ignore[method-assign]


@pytest.fixture
def no_network() -> Iterator[NetworkAttempts]:
    """``refuse_network`` for the duration of a test."""
    with refuse_network() as recorder:
        yield recorder


def executable_name(args: Any) -> str:
    """The base name, without extension and in lower case, of the program ``args`` starts."""
    if isinstance(args, str | bytes | os.PathLike):
        text = os.fsdecode(args)
        first = text.split()[0] if isinstance(args, str | bytes) and text.split() else text
    else:
        first = os.fsdecode(next(iter(args)))
    return Path(first).stem.lower()


@contextlib.contextmanager
def recorded_subprocesses() -> Iterator[list[str]]:
    """Record the program of every ``subprocess.Popen`` (and so of ``run`` and ``check_output``)."""
    started: list[str] = []
    original: Any = subprocess.Popen

    class RecordingPopen(original):  # type: ignore[misc]
        """Records what is started, then starts it."""

        def __init__(self, args: Any, *rest: Any, **kwargs: Any) -> None:
            started.append(executable_name(args))
            super().__init__(args, *rest, **kwargs)

    subprocess.Popen = RecordingPopen  # type: ignore[misc]
    try:
        yield started
    finally:
        subprocess.Popen = original  # type: ignore[misc]
