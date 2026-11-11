"""Sandboxes that run one engine process under limits (E14-01, ADR-0002 rules 2 to 9).

Owning epic: E14.

Both sandboxes start the engine with an argument vector and ``shell=False``, give it an
environment built from scratch (``PATH``, a private ``HOME`` and ``TMPDIR``, ``LANG`` and only the
variables the operator listed in ``env_passthrough``; never a ``CODEKAVACH_*`` variable), cap what
it may write to stdout and stderr, kill its whole process group on timeout, and hand it a
read-only view of the source.

**What is isolated and what is not (measured statements only).**

* :class:`ContainerSandbox` runs ``docker`` or ``podman`` with ``--network=none --read-only
  --cap-drop=ALL --security-opt=no-new-privileges`` and limits on processes, memory and CPUs. The
  source is a read-only bind mount and the output directory is the only writable mount. It needs a
  container runtime and an image pinned by digest.
* :class:`SubprocessSandbox` applies ``RLIMIT_AS``, ``RLIMIT_NOFILE``, ``RLIMIT_CPU`` and
  ``RLIMIT_FSIZE`` on POSIX through a small launcher, and puts the engine in a new session so the
  group can be killed. It isolates the network only on Linux when ``unshare --user --net`` works
  for the current user. Everywhere else (macOS, Windows, a Linux without user namespaces) the
  engine can reach the network: the sandbox logs ``engine_network_not_isolated`` once per scan and
  records the fact in :attr:`SubprocessSandbox.notes`, and the coverage appendix states it. On
  Windows no resource limits are applied and the process tree is ended with ``taskkill``.

A container's own caches and the engine's start-up cost are not reduced by either sandbox.
"""

import contextlib
import os
import posixpath
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Final, Literal, Protocol

from codekavach.analysis.engines.base import OUTPUT_TOKEN, ROOT_TOKEN
from codekavach.analysis.engines.errors import EngineSandboxError, EngineUnavailable
from codekavach.config import Settings
from codekavach.core.log import get_logger

CONTAINER_ROOT: Final = "/src"
CONTAINER_OUT: Final = "/out"
CONTAINER_TMP: Final = "/tmp"  # noqa: S108 - the path inside the container, not on the host
FORBIDDEN_PREFIX: Final = "CODEKAVACH_"
NETWORK_WARNING: Final = "engine_network_not_isolated"
_CHUNK: Final = 65_536
_JOIN_SECONDS: Final = 5.0
_PUMP_SETTLE_SECONDS: Final = 2.0
_NOFILE: Final = 1024
_WINDOWS_NAMES: Final = ("SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR")
_RUNTIME_NAMES: Final = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "CONTAINER_HOST",
    "XDG_RUNTIME_DIR",
    "USERPROFILE",
    "SYSTEMROOT",
)
_LAUNCHER: Final = """\
import os, sys
import resource

def cap(kind, value):
    if value > 0:
        try:
            resource.setrlimit(kind, (value, value))
        except (ValueError, OSError):
            pass

memory, nofile, cpu, fsize = (int(v) for v in sys.argv[1:5])
cap(resource.RLIMIT_AS, memory)
cap(resource.RLIMIT_NOFILE, nofile)
cap(resource.RLIMIT_CPU, cpu)
cap(resource.RLIMIT_FSIZE, fsize)
os.execvp(sys.argv[5], sys.argv[5:])
"""

_log = get_logger("codekavach.analysis.engines.sandbox")


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Limits for one engine process; 0 disables a limit where that makes sense."""

    max_output_bytes: int = 64 * 1024 * 1024
    memory_mb: int = 4096
    cpu_seconds: int = 0
    pids_limit: int = 512
    cpus: float = 2.0
    kill_grace_seconds: float = 2.0


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    """Everything a sandbox needs to run one engine; ``argv`` and ``env`` may hold path tokens."""

    engine_id: str
    argv: tuple[str, ...]
    root: Path
    out_dir: Path
    stdout_path: Path
    stderr_path: Path
    timeout_seconds: float
    workdir: str = ROOT_TOKEN
    env: Mapping[str, str] = field(default_factory=dict)
    passthrough: tuple[str, ...] = ()
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    image: str | None = None


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """How the process ended."""

    exit_code: int | None
    timed_out: bool
    truncated: bool
    duration_seconds: float


class Sandbox(Protocol):
    """Runs one engine process."""

    name: str

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run the engine; raises :class:`EngineUnavailable` or :class:`EngineSandboxError`."""


def substitute(text: str, *, root: str, out: str) -> str:
    """``text`` with the path tokens replaced."""
    return text.replace(ROOT_TOKEN, root).replace(OUTPUT_TOKEN, out)


def build_environment(
    *,
    home: Path | str,
    tmp: Path | str,
    extra: Mapping[str, str],
    passthrough: Sequence[str],
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The environment of an engine process, built from scratch.

    Nothing is inherited except ``PATH`` (and the few names Windows cannot start a process
    without). ``passthrough`` names are copied from ``environ`` when present; a ``CODEKAVACH_*``
    name is never passed, whoever asks.
    """
    source = os.environ if environ is None else environ
    env = {
        "PATH": source.get("PATH", ""),
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "LANG": "C.UTF-8",
    }
    if sys.platform == "win32":
        env.update({"USERPROFILE": str(home), "TEMP": str(tmp), "TMP": str(tmp)})
        for name in _WINDOWS_NAMES:
            if name in source:
                env[name] = source[name]
    for name in passthrough:
        if name.upper().startswith(FORBIDDEN_PREFIX):
            continue
        if name in source:
            env[name] = source[name]
    env.update({k: v for k, v in extra.items() if not k.upper().startswith(FORBIDDEN_PREFIX)})
    return env


def _pump(stream: IO[bytes], path: Path, cap: int, truncated: list[bool]) -> None:
    """Copy ``stream`` to ``path`` up to ``cap`` bytes; drain and discard the rest."""
    written = 0
    with path.open("wb") as sink:
        while True:
            chunk = stream.read(_CHUNK)
            if not chunk:
                return
            room = cap - written
            if room > 0:
                part = chunk[:room]
                sink.write(part)
                written += len(part)
                if len(part) < len(chunk):
                    truncated[0] = True
            else:
                truncated[0] = True


def _end_process_tree(process: "subprocess.Popen[bytes]", grace: float) -> None:
    """End ``process`` and everything in its group; the leader is reaped."""
    if sys.platform == "win32":
        taskkill = shutil.which("taskkill")
        if taskkill is not None:
            subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                check=False,
                timeout=30,
            )
        else:
            process.kill()
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
        # Always follow with SIGKILL: a grandchild may ignore SIGTERM after the leader is gone.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=_JOIN_SECONDS)


def _execute(
    argv: Sequence[str],
    *,
    engine_id: str,
    cwd: Path | None,
    env: Mapping[str, str],
    request: SandboxRequest,
    on_timeout: Callable[[], None] | None = None,
) -> SandboxResult:
    """Start ``argv`` without a shell and supervise it."""
    kwargs: dict[str, Any] = {
        "cwd": None if cwd is None else str(cwd),
        "env": dict(env),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    started = time.monotonic()
    try:
        process = subprocess.Popen(list(argv), **kwargs)
    except FileNotFoundError:
        raise EngineUnavailable(engine_id, "executable not found") from None
    except OSError:
        raise EngineSandboxError(engine_id, "the process could not be started") from None
    assert process.stdout is not None and process.stderr is not None  # noqa: S101 - PIPE
    cap = request.limits.max_output_bytes
    out_flag, err_flag = [False], [False]
    pumps = [
        threading.Thread(
            target=_pump, args=(process.stdout, request.stdout_path, cap, out_flag), daemon=True
        ),
        threading.Thread(
            target=_pump, args=(process.stderr, request.stderr_path, cap, err_flag), daemon=True
        ),
    ]
    for pump in pumps:
        pump.start()
    timed_out = False
    try:
        process.wait(timeout=request.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        if on_timeout is not None:
            with contextlib.suppress(Exception):
                on_timeout()
        _end_process_tree(process, request.limits.kill_grace_seconds)
    for pump in pumps:
        pump.join(timeout=_PUMP_SETTLE_SECONDS if not timed_out else _JOIN_SECONDS)
    if any(pump.is_alive() for pump in pumps) and sys.platform != "win32":
        # A descendant still holds a pipe open after the leader ended: finish the group.
        _end_process_tree(process, 0.0)
        for pump in pumps:
            pump.join(timeout=_JOIN_SECONDS)
    for stream in (process.stdout, process.stderr):
        with contextlib.suppress(OSError):
            stream.close()
    return SandboxResult(
        exit_code=None if timed_out else process.returncode,
        timed_out=timed_out,
        truncated=out_flag[0] or err_flag[0],
        duration_seconds=time.monotonic() - started,
    )


def check_workdir_inside(engine_id: str, workdir: Path, *roots: Path) -> Path:
    """``workdir`` resolved, which must be inside one of ``roots`` (CWE-22); else an error."""
    resolved = workdir.resolve()
    for root in roots:
        if resolved == root.resolve() or root.resolve() in resolved.parents:
            return resolved
    raise EngineSandboxError(engine_id, "the working directory is outside the source view")


def check_container_workdir(engine_id: str, workdir: str) -> str:
    """``workdir`` normalised, which must be ``/src`` or ``/out`` or below them."""
    normal = posixpath.normpath(workdir)
    for base in (CONTAINER_ROOT, CONTAINER_OUT):
        if normal == base or normal.startswith(base + "/"):
            return normal
    raise EngineSandboxError(engine_id, "the working directory is outside the source view")


def _prepare_directories(request: SandboxRequest) -> tuple[Path, Path]:
    home = request.out_dir / "home"
    tmp = request.out_dir / "tmp"
    for directory in (request.out_dir, home, tmp):
        directory.mkdir(parents=True, exist_ok=True)
    return home, tmp


def _probe_user_network_namespace() -> bool:
    """Whether ``unshare --user --net`` works for the current user (Linux only)."""
    unshare = shutil.which("unshare") if sys.platform.startswith("linux") else None
    if unshare is None:
        return False
    try:
        completed = subprocess.run(
            [unshare, "--user", "--net", "--", "true"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


class SubprocessSandbox:
    """Runs the engine as a child process with resource limits (see the module docstring)."""

    name = "subprocess"

    def __init__(self, *, isolate_network: bool | None = None) -> None:
        self._requested = isolate_network
        self._isolated: bool | None = None
        self._warned = False
        self._lock = threading.Lock()
        self.notes: list[str] = []

    @property
    def network_isolated(self) -> bool:
        """Whether engine processes get their own network namespace."""
        with self._lock:
            if self._isolated is None:
                self._isolated = (
                    False if self._requested is False else _probe_user_network_namespace()
                )
            return self._isolated

    def _warn_once(self) -> None:
        with self._lock:
            if self._warned:
                return
            self._warned = True
            self.notes.append(NETWORK_WARNING)
        _log.warning(NETWORK_WARNING)

    def _command(self, argv: Sequence[str], limits: SandboxLimits) -> list[str]:
        if sys.platform == "win32":
            return list(argv)
        else:  # noqa: RET505 - keeps both branches reachable for mypy on every platform
            return self._posix_command(argv, limits)

    def _posix_command(self, argv: Sequence[str], limits: SandboxLimits) -> list[str]:
        command = [
            sys.executable,
            "-I",
            "-c",
            _LAUNCHER,
            str(limits.memory_mb * 1024 * 1024 if limits.memory_mb > 0 else 0),
            str(_NOFILE),
            str(limits.cpu_seconds),
            str(limits.max_output_bytes * 4),
            *argv,
        ]
        unshare = shutil.which("unshare") if self.network_isolated else None
        return command if unshare is None else [unshare, "--user", "--net", "--", *command]

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run the engine in ``request.root``; the working directory is substituted first."""
        home, tmp = _prepare_directories(request)
        root, out = str(request.root), str(request.out_dir)
        argv = [substitute(part, root=root, out=out) for part in request.argv]
        extra = {k: substitute(v, root=root, out=out) for k, v in request.env.items()}
        env = build_environment(home=home, tmp=tmp, extra=extra, passthrough=request.passthrough)
        workdir = check_workdir_inside(
            request.engine_id,
            Path(substitute(request.workdir, root=root, out=out)),
            request.root,
            request.out_dir,
        )
        executable = argv[0]
        if os.sep not in executable and "/" not in executable:
            if shutil.which(executable, path=env["PATH"]) is None:
                raise EngineUnavailable(request.engine_id, "executable not found")
        elif not Path(executable).exists():
            raise EngineUnavailable(request.engine_id, "executable not found")
        if not self.network_isolated:
            self._warn_once()
        return _execute(
            self._command(argv, request.limits),
            engine_id=request.engine_id,
            cwd=workdir,
            env=env,
            request=request,
        )


class ContainerSandbox:
    """Runs the engine in a container with no network (see the module docstring)."""

    name = "container"

    def __init__(
        self,
        runtime: Literal["auto", "docker", "podman"] = "auto",
        *,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._which = which
        names = ("docker", "podman") if runtime == "auto" else (runtime,)
        self._runtime = next((path for n in names if (path := which(n)) is not None), None)

    @property
    def available(self) -> bool:
        """Whether a container runtime was found."""
        return self._runtime is not None

    def build_command(self, request: SandboxRequest, container_name: str) -> list[str]:
        """The full ``docker run`` or ``podman run`` argument vector for ``request``."""
        if self._runtime is None:
            raise EngineSandboxError(request.engine_id, "no container runtime found")
        if request.image is None:
            raise EngineSandboxError(request.engine_id, "no pinned image for this engine")
        limits = request.limits
        command = [
            self._runtime,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={limits.pids_limit}",
            f"--memory={limits.memory_mb}m",
            f"--cpus={limits.cpus}",
            "--tmpfs",
            f"{CONTAINER_TMP}:rw,size=256m",
            "--mount",
            f"type=bind,source={request.root},target={CONTAINER_ROOT},readonly",
            "--mount",
            f"type=bind,source={request.out_dir},target={CONTAINER_OUT}",
            "-w",
            check_container_workdir(
                request.engine_id,
                substitute(request.workdir, root=CONTAINER_ROOT, out=CONTAINER_OUT),
            ),
        ]
        if sys.platform != "win32":
            command += ["--user", f"{os.getuid()}:{os.getgid()}"]
        environment = build_environment(
            home=f"{CONTAINER_OUT}/home",
            tmp=CONTAINER_TMP,
            extra={
                k: substitute(v, root=CONTAINER_ROOT, out=CONTAINER_OUT)
                for k, v in request.env.items()
            },
            passthrough=request.passthrough,
        )
        environment.pop("PATH", None)  # the image defines its own
        for name in sorted(environment):
            command += ["-e", f"{name}={environment[name]}"]
        command.append(request.image)
        command += [substitute(p, root=CONTAINER_ROOT, out=CONTAINER_OUT) for p in request.argv]
        return command

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run the engine in a fresh container."""
        _prepare_directories(request)
        name = f"ck-engine-{secrets.token_hex(6)}"
        command = self.build_command(request, name)
        runtime = command[0]
        host_env = {k: v for k, v in os.environ.items() if k.upper() in _RUNTIME_NAMES}

        def kill_container() -> None:
            subprocess.run([runtime, "kill", name], capture_output=True, check=False, timeout=30)

        return _execute(
            command,
            engine_id=request.engine_id,
            cwd=None,
            env=host_env,
            request=request,
            on_timeout=kill_container,
        )


@dataclass(slots=True)
class SandboxSet:
    """The sandboxes of one scan and the rule that picks one per engine."""

    subprocess_sandbox: SubprocessSandbox
    container_sandbox: ContainerSandbox | None
    mode: Literal["subprocess", "container", "auto"] = "auto"

    def pick(self, engine_id: str, image: str | None) -> Sandbox:
        """The sandbox for ``engine_id``; ``auto`` prefers a container when it can be used."""
        container = self.container_sandbox
        usable = container is not None and container.available and image is not None
        if self.mode == "subprocess":
            return self.subprocess_sandbox
        if self.mode == "container":
            if not usable or container is None:
                raise EngineSandboxError(engine_id, "the container sandbox cannot be used")
            return container
        if usable and container is not None:
            return container
        return self.subprocess_sandbox

    @property
    def notes(self) -> list[str]:
        """Limitations the sandboxes recorded during the scan."""
        return list(self.subprocess_sandbox.notes)


def limits_from_settings(settings: Settings) -> SandboxLimits:
    """The :class:`SandboxLimits` of ``engines.sandbox``."""
    section = settings.engines.sandbox
    return SandboxLimits(
        max_output_bytes=section.max_output_bytes,
        memory_mb=section.memory_mb,
        cpu_seconds=section.cpu_seconds,
        pids_limit=section.pids_limit,
        cpus=section.cpus,
        kill_grace_seconds=section.kill_grace_seconds,
    )


def build_sandboxes(settings: Settings) -> SandboxSet:
    """The sandboxes for one scan, from ``engines.sandbox``."""
    section = settings.engines.sandbox
    container = (
        None if section.mode == "subprocess" else ContainerSandbox(section.container_runtime)
    )
    return SandboxSet(SubprocessSandbox(), container, section.mode)
