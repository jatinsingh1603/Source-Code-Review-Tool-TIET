"""``GitSource``: a shallow clone of a repository URL into the working root (E06-03).

Owning epic: E06.

A repository is untrusted input and ``git`` is an execution vector (CVE-2024-32002: a crafted
submodule and symlink pair ran attacker code during ``git clone --recursive``; hooks and
``core.fsmonitor`` are the older ones). The clone is therefore run with these switches, each for
a stated reason:

``--no-optional-locks``             no background index refresh that could race another process
``-c core.hooksPath=/dev/null``      no hook of the repository or of git's templates runs
``-c core.fsmonitor=false``          no fsmonitor program named by a config file is started
``-c core.symlinks=false``           a symlink is checked out as a plain file holding its target, so
                                     a checkout-time escape through a link cannot happen
``-c protocol.ext.allow=never``      the ``ext::`` transport runs a command named by the URL
``-c core.autocrlf=false``           a file is checked out as committed, so its hash
                                     does not depend on line-ending settings
``-c advice.detachedHead=false``     a clone at a tag or a commit prints no advice
``--no-recurse-submodules``          submodules are not fetched; they are recorded as not scanned
``GIT_LFS_SKIP_SMUDGE=1``            no LFS object is downloaded
``GIT_TERMINAL_PROMPT=0``            a missing credential fails; git never asks on the terminal
``GIT_ASKPASS=/bin/false``           no askpass helper from the environment is run
``GIT_ALLOW_PROTOCOL=https:ssh:file`` only these transports, whatever a config file says

The child gets a short allow-list of environment variables, so ``GIT_DIR``, ``GIT_EXEC_PATH`` and
similar variables of the caller cannot redirect it.

**Credentials.** A credential is a secret reference (``env:NAME``, ``keyring:...``) resolved with
``resolve_secret``. It reaches git through ``GIT_CONFIG_*`` environment variables as an
``http.extraHeader`` for https URLs, never in the argument vector, where any local user could read
it in the process list. A URL that carries a password is refused. Neither the URL nor git's
standard error appears in a message or a log line.

**After the clone** the tree is walked once: the number of files and bytes is checked against
``ingest.max_files`` and ``ingest.max_total_bytes`` (``.git`` excluded), and every entry must
resolve inside the working root. On any failure the working root is removed.
"""

import base64
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Final

from codekavach.config.keys import resolve_secret
from codekavach.core.log import get_logger
from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources.base import UnsafeArchiveEntry, UnsupportedSource
from codekavach.ingest.sources.workdir import private_directory, remove_tree

_log = get_logger("codekavach.ingest.sources.git")

DEFAULT_DEPTH: Final = 1
MAX_DEPTH: Final = 1_000_000
CLONE_TIMEOUT_SECONDS: Final = 600.0
FETCH_TIMEOUT_SECONDS: Final = 300.0
REMOTE_PREFIXES: Final = ("https://", "ssh://", "git@", "file://")
_FORBIDDEN_URL: Final = re.compile(r"[\x00-\x20\x7f]")
_PASSWORD_IN_URL: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/@]*:[^/@]*@")
_REF: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,254}$")
_COMMIT: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PASSED_ENVIRONMENT: Final = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSH_AUTH_SOCK",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)
HARDENING: Final = (
    "--no-optional-locks",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.symlinks=false",
    "-c",
    "core.autocrlf=false",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "advice.detachedHead=false",
)
_SAFE_ENVIRONMENT: Final = {
    "GIT_LFS_SKIP_SMUDGE": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "/bin/false",
    "GIT_ALLOW_PROTOCOL": "https:ssh:file",
    "GIT_SSH_COMMAND": "ssh -o BatchMode=yes",
    "GIT_OPTIONAL_LOCKS": "0",
}


@dataclass(frozen=True, slots=True)
class GitResult:
    """The exit status and standard output of one git call; standard error is dropped."""

    returncode: int
    stdout: bytes = b""


GitRunner = Callable[[Sequence[str], Mapping[str, str], Path | None, float], GitResult]


def run_git(
    argv: Sequence[str], env: Mapping[str, str], cwd: Path | None, timeout: float
) -> GitResult:
    """Run ``argv`` without a shell, without stdin and with exactly ``env`` as its environment."""
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            check=False,
            timeout=timeout,
            env=dict(env),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return GitResult(returncode=-1)
    return GitResult(returncode=completed.returncode, stdout=completed.stdout)


def looks_like_git_target(target: str) -> bool:
    """Whether ``target`` is a git URL form: a remote scheme, ``git@host:path`` or ``*.git``."""
    return target.startswith(REMOTE_PREFIXES) or target.endswith(".git")


def hardened_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """The environment of a git child: a short allow-list of ``environ`` plus the safe switches."""
    env = {name: environ[name] for name in _PASSED_ENVIRONMENT if name in environ}
    env.update(_SAFE_ENVIRONMENT)
    return env


def check_git_url(target: str) -> str:
    """``target`` if it is a URL this source accepts.

    Raises:
        UnsupportedSource: it starts with ``-``, holds a control character or a space, names a
            transport that is not allowed, or carries a password.
    """
    if not target or target.startswith("-") or _FORBIDDEN_URL.search(target):
        raise UnsupportedSource("the target is not a valid git URL")
    if "::" in target.split("/", maxsplit=1)[0] or _PASSWORD_IN_URL.match(target):
        raise UnsupportedSource("the target is not a valid git URL, or carries a credential")
    scheme = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", target)
    if scheme is not None and scheme.group(1).lower() not in {"https", "ssh", "file"}:
        raise UnsupportedSource("the git transport of the target is not allowed")
    return target


def check_ref(ref: str) -> str:
    """``ref`` if it is a plain branch, tag or commit name.

    Raises:
        UnsupportedSource: it starts with ``-`` or holds a character outside the plain set.
    """
    if not _REF.match(ref) or ".." in ref or ref.endswith(("/", ".lock")):
        raise UnsupportedSource("the git ref is not a plain branch, tag or commit name")
    return ref


class GitSource:
    """Clones a repository to ``into`` at ``depth`` (default 1) and, optionally, at ``ref``."""

    owns_root: ClassVar[bool] = True

    def __init__(
        self,
        *,
        ref: str | None = None,
        depth: int = DEFAULT_DEPTH,
        credential: str | None = None,
        fetch_base: str | None = None,
        runner: GitRunner = run_git,
        environ: Mapping[str, str] | None = None,
        executable: str | None = None,
    ) -> None:
        if not 1 <= depth <= MAX_DEPTH:
            raise UnsupportedSource("--depth must be between 1 and 1000000")
        self._ref = check_ref(ref) if ref else None
        self._depth = depth
        self._credential = credential
        self._fetch_base = check_ref(fetch_base) if fetch_base else None
        self._runner = runner
        self._environ = os.environ if environ is None else environ
        self._executable = executable

    def _git(self) -> str:
        found = self._executable or shutil.which("git")
        if found is None:
            raise UnsupportedSource("git is not installed, so the target cannot be cloned")
        return found

    def _environment(self, url: str) -> dict[str, str]:
        env = hardened_environment(self._environ)
        if self._credential and url.startswith("https://"):
            env.update(_credential_header(self._credential, self._environ))
        return env

    def materialise(self, target: str, *, limits: IngestLimits, into: Path) -> Path:
        """Clone ``target`` into ``into`` and return it; ``into`` is removed on any failure."""
        url = check_git_url(target)
        git = self._git()
        env = self._environment(url)
        if into.exists() and any(into.iterdir()):
            raise UnsupportedSource("the working root for the clone is not empty")
        private_directory(into)
        try:
            self._clone(git, url, into, env)
            if self._fetch_base is not None:
                self._deepen(git, into, env)
            check_tree(into, limits)
        except BaseException:
            remove_tree(into)
            raise
        _log.info("git_cloned", depth=self._depth, ref_given=self._ref is not None)
        return into

    def _clone(self, git: str, url: str, into: Path, env: Mapping[str, str]) -> None:
        commit = self._ref is not None and _COMMIT.match(self._ref) is not None
        argv = [git, *HARDENING, "clone", "--no-recurse-submodules", "--depth", str(self._depth)]
        if self._ref is not None and not commit:
            argv += ["--branch", self._ref]
        if commit:
            argv.append("--no-checkout")
        argv += ["--", url, str(into)]
        if self._runner(argv, env, None, CLONE_TIMEOUT_SECONDS).returncode != 0:
            raise UnsupportedSource("git could not clone the target")
        if commit and self._ref is not None:
            fetch = [git, *HARDENING, "fetch", "--depth", str(self._depth), "origin", self._ref]
            if self._runner(fetch, env, into, FETCH_TIMEOUT_SECONDS).returncode != 0:
                raise UnsupportedSource("git could not fetch the requested commit")
            checkout = [git, *HARDENING, "checkout", "--detach", "--force", self._ref]
            if self._runner(checkout, env, into, FETCH_TIMEOUT_SECONDS).returncode != 0:
                raise UnsupportedSource("git could not check out the requested commit")

    def _deepen(self, git: str, into: Path, env: Mapping[str, str]) -> None:
        """Fetch the base of a diff scan when the shallow clone lacks it; a miss is not an error."""
        assert self._fetch_base is not None  # noqa: S101 - narrowed by the caller
        probe = [
            git,
            *HARDENING,
            "rev-parse",
            "--verify",
            "--quiet",
            f"{self._fetch_base}^{{commit}}",
        ]
        if self._runner(probe, env, into, FETCH_TIMEOUT_SECONDS).returncode == 0:
            return
        fetch = [
            git,
            *HARDENING,
            "fetch",
            "--depth",
            str(self._depth),
            "--no-recurse-submodules",
            "origin",
            self._fetch_base,
        ]
        if self._runner(fetch, env, into, FETCH_TIMEOUT_SECONDS).returncode != 0:
            _log.warning("git_base_not_fetched")
            return
        if _COMMIT.match(self._fetch_base) is None:
            # Name what was fetched, so the diff can find the base by the name it was given.
            name = f"refs/tags/{self._fetch_base}"
            keep = [git, *HARDENING, "update-ref", name, "FETCH_HEAD"]
            self._runner(keep, env, into, FETCH_TIMEOUT_SECONDS)


def _credential_header(reference: str, environ: Mapping[str, str]) -> dict[str, str]:
    """``GIT_CONFIG_*`` variables that send the resolved secret as a Basic header."""
    secret = resolve_secret(reference, env=environ).get_secret_value()
    token = base64.b64encode(f"x-access-token:{secret}".encode()).decode("ascii")
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {token}",
    }


def check_tree(root: Path, limits: IngestLimits) -> None:
    """Check the budgets and the containment of a freshly cloned tree (``.git`` is not counted).

    Raises:
        LimitExceededError: more files or bytes than ``ingest.max_files`` or ``max_total_bytes``.
        UnsafeArchiveEntry: an entry resolves outside ``root``.
    """
    resolved = root.resolve()
    files = 0
    total = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        if Path(directory) == root and ".git" in names:
            names.remove(".git")
        for name in [*names, *filenames]:
            entry = Path(directory) / name
            try:
                entry.resolve().relative_to(resolved)
            except (OSError, ValueError):
                raise UnsafeArchiveEntry("tree_escape") from None
        for name in filenames:
            files += 1
            if files > limits.max_files:
                raise LimitExceededError(LimitKind.FILE_COUNT, limits.max_files)
            try:
                total += (Path(directory) / name).lstat().st_size
            except OSError:
                continue
            if total > limits.max_total_bytes:
                raise LimitExceededError(LimitKind.TOTAL_BYTES, limits.max_total_bytes)
