"""The subprocess and container sandboxes (E14-01, ADR-0002 rules 2 to 9)."""

import json
import os
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Literal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.analysis.engines.base import OUTPUT_TOKEN, ROOT_TOKEN
from codekavach.analysis.engines.errors import EngineSandboxError, EngineUnavailable
from codekavach.analysis.engines.sandbox import (
    CONTAINER_OUT,
    CONTAINER_ROOT,
    NETWORK_WARNING,
    ContainerSandbox,
    SandboxLimits,
    SandboxRequest,
    SandboxSet,
    SubprocessSandbox,
    build_environment,
    check_workdir_inside,
    substitute,
)
from tests.support.engines import FAKE_ENGINE

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
SENSITIVE = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "CODEKAVACH_VAULT_KEY",
    "CODEKAVACH_ANYTHING",
]
DIGEST = "b" * 64
IMAGE = f"registry.example/tool@sha256:{DIGEST}"


def make_request(
    tmp_path: Path,
    *arguments: str,
    timeout: float = 30.0,
    limits: SandboxLimits | None = None,
    env: dict[str, str] | None = None,
    passthrough: tuple[str, ...] = (),
    workdir: str = ROOT_TOKEN,
    image: str | None = None,
) -> SandboxRequest:
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    out = tmp_path / "out"
    return SandboxRequest(
        engine_id="fake",
        argv=(sys.executable, str(FAKE_ENGINE), *arguments),
        root=root,
        out_dir=out,
        stdout_path=out / "stdout.txt",
        stderr_path=out / "stderr.txt",
        timeout_seconds=timeout,
        workdir=workdir,
        env=env or {},
        passthrough=passthrough,
        limits=limits or SandboxLimits(),
        image=image,
    )


def sandbox() -> SubprocessSandbox:
    return SubprocessSandbox(isolate_network=False)


@pytest.mark.parametrize("name", SENSITIVE)
def test_the_environment_is_built_from_scratch(name: str) -> None:
    source = {"PATH": "/bin", name: "secret", "OTHER": "x", "SYSTEMROOT": "C:\\Windows"}
    env = build_environment(home="/h", tmp="/t", extra={}, passthrough=(), environ=source)
    assert name not in env
    assert "OTHER" not in env
    assert {"PATH", "HOME", "TMPDIR", "LANG"} <= set(env)
    assert env["HOME"] == "/h"


def test_only_listed_names_pass_and_codekavach_names_never_do() -> None:
    source = {"PATH": "p", "PROXY_SETTING": "v", "CODEKAVACH_X": "1", "UNLISTED": "u"}
    env = build_environment(
        home="/h",
        tmp="/t",
        extra={"CODEKAVACH_Y": "2", "EXTRA": "e"},
        passthrough=("PROXY_SETTING", "CODEKAVACH_X", "MISSING"),
        environ=source,
    )
    assert env["PROXY_SETTING"] == "v" and env["EXTRA"] == "e"
    assert "CODEKAVACH_X" not in env and "CODEKAVACH_Y" not in env
    assert "UNLISTED" not in env and "MISSING" not in env


def test_a_real_child_sees_none_of_the_sensitive_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in SENSITIVE:
        monkeypatch.setenv(name, "must-not-reach-the-engine")
    request = make_request(tmp_path, "env", f"{OUTPUT_TOKEN}/env.json")
    result = sandbox().run(request)
    assert result.exit_code == 0
    seen = json.loads((request.out_dir / "env.json").read_text(encoding="utf-8"))
    assert not [name for name in SENSITIVE if name in seen]
    assert not [name for name in seen if name.upper().startswith("CODEKAVACH_")]
    assert Path(seen["HOME"]).is_relative_to(request.out_dir)


def test_a_listed_passthrough_variable_reaches_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY_NAME", "proxy.internal")
    request = make_request(
        tmp_path, "env", f"{OUTPUT_TOKEN}/env.json", passthrough=("HTTP_PROXY_NAME",)
    )
    sandbox().run(request)
    seen = json.loads((request.out_dir / "env.json").read_text(encoding="utf-8"))
    assert seen["HTTP_PROXY_NAME"] == "proxy.internal"


def test_the_exit_code_is_reported(tmp_path: Path) -> None:
    result = sandbox().run(make_request(tmp_path, "exit", "3"))
    assert (result.exit_code, result.timed_out, result.truncated) == (3, False, False)


def test_a_missing_executable_is_unavailable(tmp_path: Path) -> None:
    request = make_request(tmp_path)
    missing = replace(request, argv=(str(tmp_path / "no-such-engine"),))
    with pytest.raises(EngineUnavailable):
        sandbox().run(missing)
    named = replace(request, argv=("no-such-engine-on-path-xyz",))
    with pytest.raises(EngineUnavailable):
        sandbox().run(named)


def test_a_slow_engine_is_killed_at_the_timeout(tmp_path: Path) -> None:
    started = time.monotonic()
    limits = SandboxLimits(kill_grace_seconds=0.5)
    result = sandbox().run(make_request(tmp_path, "sleep", "60", timeout=1.0, limits=limits))
    assert result.timed_out is True
    assert result.exit_code is None
    assert time.monotonic() - started < 30


@posix_only
def test_a_grandchild_that_ignores_sigterm_is_killed_with_the_group(tmp_path: Path) -> None:
    pidfile = tmp_path / "grandchild.pid"
    limits = SandboxLimits(kill_grace_seconds=0.5)
    result = sandbox().run(
        make_request(tmp_path, "grandchild", str(pidfile), timeout=3.0, limits=limits)
    )
    assert result.timed_out is True
    assert pidfile.is_file(), "the grandchild never started"
    pid = int(pidfile.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(pid, 9)
    pytest.fail("the grandchild survived the timeout")


def test_output_over_the_cap_is_truncated_without_growing_memory(tmp_path: Path) -> None:
    cap = 1024 * 1024
    request = make_request(tmp_path, "flood", "12", limits=SandboxLimits(max_output_bytes=cap))
    result = sandbox().run(request)
    assert result.truncated is True
    assert result.exit_code == 0
    assert request.stdout_path.stat().st_size == cap


def test_binary_and_empty_output_do_not_raise(tmp_path: Path) -> None:
    binary = make_request(tmp_path, "binary")
    assert sandbox().run(binary).exit_code == 0
    assert binary.stdout_path.read_bytes() == b"\xff\xfe\x00\x80"
    silent = make_request(tmp_path, "silent")
    assert sandbox().run(silent).exit_code == 0
    assert silent.stdout_path.stat().st_size == 0


def test_the_network_warning_is_recorded_once_per_sandbox(tmp_path: Path) -> None:
    isolated = SubprocessSandbox(isolate_network=False)
    assert isolated.network_isolated is False
    isolated.run(make_request(tmp_path, "silent"))
    isolated.run(make_request(tmp_path, "silent"))
    assert isolated.notes == [NETWORK_WARNING]


def test_a_working_directory_outside_the_view_is_refused(tmp_path: Path) -> None:
    request = make_request(tmp_path, "silent", workdir=f"{ROOT_TOKEN}/../..")
    with pytest.raises(EngineSandboxError, match="outside"):
        sandbox().run(request)


def test_substitute_replaces_both_tokens() -> None:
    assert substitute(f"{ROOT_TOKEN}/a:{OUTPUT_TOKEN}/b", root="/r", out="/o") == "/r/a:/o/b"


def container() -> ContainerSandbox:
    return ContainerSandbox("docker", which=lambda name: f"/usr/bin/{name}")


def test_the_container_command_isolates_the_engine(tmp_path: Path) -> None:
    request = make_request(
        tmp_path,
        "ok",
        f"{OUTPUT_TOKEN}/out.json",
        image=IMAGE,
        env={"TOOL_NO_TELEMETRY": "1", "CODEKAVACH_LEAK": "x"},
        passthrough=("CODEKAVACH_ALSO",),
    )
    command = container().build_command(request, "ck-engine-test")
    assert command[:2] == ["/usr/bin/docker", "run"]
    for flag in (
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in command
    assert any(part.startswith("--pids-limit=") for part in command)
    assert any(part.startswith("--memory=") for part in command)
    assert any(part.startswith("--cpus=") for part in command)
    mounts = [part for part in command if part.startswith("type=bind")]
    assert len(mounts) == 2
    assert mounts[0].endswith(f"target={CONTAINER_ROOT},readonly")
    assert mounts[1].endswith(f"target={CONTAINER_OUT}")
    assert "-e" in command and "TOOL_NO_TELEMETRY=1" in command
    assert not [part for part in command if part.startswith("CODEKAVACH_")]
    assert not [part for part in command if part.startswith("PATH=")]
    assert command[command.index(IMAGE) + 1 :][-1] == f"{CONTAINER_OUT}/out.json"
    assert str(tmp_path / "root") in "".join(mounts)


def test_a_container_needs_a_runtime_and_a_pinned_image(tmp_path: Path) -> None:
    with pytest.raises(EngineSandboxError, match="image"):
        container().build_command(make_request(tmp_path), "n")
    bare = ContainerSandbox("podman", which=lambda name: None)
    assert bare.available is False
    with pytest.raises(EngineSandboxError, match="runtime"):
        bare.build_command(make_request(tmp_path, image=IMAGE), "n")


def test_a_container_working_directory_stays_inside_the_mounts(tmp_path: Path) -> None:
    ok = make_request(tmp_path, image=IMAGE, workdir=f"{ROOT_TOKEN}/sub")
    assert f"{CONTAINER_ROOT}/sub" in container().build_command(ok, "n")
    bad = make_request(tmp_path, image=IMAGE, workdir=f"{ROOT_TOKEN}/../etc")
    with pytest.raises(EngineSandboxError, match="outside"):
        container().build_command(bad, "n")


def test_the_sandbox_set_picks_by_mode_and_image(tmp_path: Path) -> None:
    local, box = sandbox(), container()
    assert SandboxSet(local, box, "auto").pick("e", IMAGE) is box
    assert SandboxSet(local, box, "auto").pick("e", None) is local
    assert SandboxSet(local, None, "auto").pick("e", IMAGE) is local
    assert SandboxSet(local, box, "subprocess").pick("e", IMAGE) is local
    with pytest.raises(EngineSandboxError):
        SandboxSet(local, box, "container").pick("e", None)


@pytest.mark.skipif(
    not os.environ.get("CODEKAVACH_TEST_CONTAINER_IMAGE"),
    reason="set CODEKAVACH_TEST_CONTAINER_IMAGE to an image with python3 to run a live container",
)
def test_a_live_container_has_no_network(tmp_path: Path) -> None:
    script = (
        "import socket,sys\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 80), timeout=3).close()\n"
        "    print('connected')\n"
        "except OSError:\n"
        "    print('blocked')\n"
    )
    image = os.environ["CODEKAVACH_TEST_CONTAINER_IMAGE"]
    request = make_request(tmp_path, image=image, timeout=120)
    request = replace(request, argv=("python3", "-c", script))
    result = ContainerSandbox().run(request)
    assert result.exit_code == 0
    assert request.stdout_path.read_text(encoding="utf-8").strip() == "blocked"


SURROGATES: tuple[Literal["Cs"], ...] = ("Cs",)
ARGV_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=SURROGATES, blacklist_characters="\x00"),
    min_size=1,
    max_size=30,
)


@settings(max_examples=60, deadline=None)
@given(parts=st.lists(ARGV_TEXT, min_size=1, max_size=6))
def test_argument_vectors_are_never_split_joined_or_interpreted(parts: list[str]) -> None:
    command = SubprocessSandbox(isolate_network=False)._command(parts, SandboxLimits())
    assert command[len(command) - len(parts) :] == parts
    request = SandboxRequest(
        engine_id="fake",
        argv=tuple(parts),
        root=Path("/r"),
        out_dir=Path("/o"),
        stdout_path=Path("/o/out"),
        stderr_path=Path("/o/err"),
        timeout_seconds=1.0,
        image=IMAGE,
    )
    built = container().build_command(request, "n")
    expected = [substitute(p, root=CONTAINER_ROOT, out=CONTAINER_OUT) for p in parts]
    assert built[built.index(IMAGE) + 1 :] == expected


@settings(max_examples=60, deadline=None)
@given(segments=st.lists(st.sampled_from(["..", ".", "a", "b"]), max_size=6))
def test_a_working_directory_never_escapes_the_view(segments: list[str]) -> None:
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        root, out = base / "root", base / "out"
        (root / "a" / "b").mkdir(parents=True)
        out.mkdir()
        target = root.joinpath(*segments)
        try:
            resolved = check_workdir_inside("fake", target, root, out)
        except EngineSandboxError:
            assert not target.resolve().is_relative_to(root.resolve())
            assert not target.resolve().is_relative_to(out.resolve())
        else:
            assert resolved.is_relative_to(root.resolve()) or resolved.is_relative_to(out.resolve())
