# ruff: noqa: T201, PTH110, PTH123, PTH208, PLR0911, PLR0912
"""A scripted fake engine for the sandbox and runner tests (E14-01).

Synthetic, standard library only. The first argument picks the behaviour; the rest are its
arguments. It never reads or writes anything outside the paths it is given.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time

GRANDCHILD = (
    "import os, signal, sys, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
    "time.sleep(120)\n"
)


def write_json(path: str, document: object) -> None:
    with open(path, "w", encoding="utf-8") as sink:
        json.dump(document, sink)


def main(argv: list[str]) -> int:
    mode, rest = argv[1], argv[2:]
    if mode == "ok":
        write_json(rest[0], {"results": [{"rule": "fake.rule", "line": 1}]})
        print("done")
        return 0
    if mode == "env":
        write_json(rest[0], dict(os.environ))
        return 0
    if mode == "sleep":
        time.sleep(float(rest[0]))
        return 0
    if mode == "grandchild":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        subprocess.Popen([sys.executable, "-c", GRANDCHILD, rest[0]])
        time.sleep(120)
        return 0
    if mode == "flood":
        chunk = b"x" * 1024 * 1024
        for _ in range(int(rest[0])):
            sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        return 0
    if mode == "exit":
        return int(rest[0])
    if mode == "binary":
        sys.stdout.buffer.write(b"\xff\xfe\x00\x80")
        return 0
    if mode == "silent":
        return 0
    if mode == "config":
        write_json(
            rest[0],
            {"files": sorted(os.listdir(".")), "rc_present": os.path.exists(".fakerc")},
        )
        return 0
    if mode == "write":
        try:
            with open(rest[0], "w", encoding="utf-8") as sink:
                sink.write("changed")
            outcome = "written"
        except OSError:
            outcome = "refused"
        write_json(rest[1], {"outcome": outcome})
        return 0
    if mode == "connect":
        try:
            socket.create_connection((rest[0], int(rest[1])), timeout=2).close()
            outcome = "connected"
        except OSError:
            outcome = "blocked"
        write_json(rest[2], {"outcome": outcome})
        return 0
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
