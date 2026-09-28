"""I1, runtime half: the test process cannot reach the network unless a test says so."""

import socket
import sys
import threading

import pytest
from pytest_socket import SocketBlockedError, SocketConnectBlockedError

DOCUMENTATION_ADDRESS = "192.0.2.1"  # TEST-NET-1, never routable


def test_inet_socket_is_blocked() -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(SocketBlockedError):
        socket.create_connection(("example.invalid", 80))


@pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX socket pairs are POSIX only")
def test_unix_socket_pair_is_allowed() -> None:
    left, right = socket.socketpair(getattr(socket, "AF_UNIX"))  # noqa: B009 - absent on Windows
    try:
        left.sendall(b"x")
        assert right.recv(1) == b"x"
    finally:
        left.close()
        right.close()


@pytest.mark.allow_hosts(["127.0.0.1"])
def test_declared_loopback_is_allowed_and_nothing_else() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[socket.socket] = []
    thread = threading.Thread(target=lambda: accepted.append(server.accept()[0]))
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        thread.join(timeout=5)
        with pytest.raises(SocketConnectBlockedError):
            socket.create_connection((DOCUMENTATION_ADDRESS, 80), timeout=5)
    finally:
        for connection in accepted:
            connection.close()
        server.close()
