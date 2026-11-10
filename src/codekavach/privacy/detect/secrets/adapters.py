"""Adapters that run external secret scanners as subprocesses (E08-04).

Owning epic: E08.

No single secret scanner dominates on the published benchmarks, so redaction recall improves
with a union of engines (``docs/research/INSIGHTS.md`` section 5.3). The engines are **untrusted
code running on a host that holds client source** (section 7 there records a repository-supplied
linter configuration that led to remote code execution, and a trojanised scanner release), so
every control below is a property of the invocation and is asserted by a test through a fake
runner:

- **Staged copy, read-only.** The engine never sees the repository. The files to scan are copied
  into a private temporary tree (regular files only, no symlinks, a size cap) and the tree is made
  read-only. A file the repository uses to configure an engine (``.gitleaks.toml``,
  ``.secrets.baseline`` and the like) is not staged, so there is no repository-supplied
  configuration for the engine to read, and the engines' inline suppression comments are switched
  off where the engine has a switch for it.
- **Live validation off.** Validation transmits the candidate secret to its issuer. Gitleaks has
  none; ``detect-secrets`` is run with ``--no-verify``.
- **No network.** No proxy variable and no credential is passed, the home and configuration
  directories are private, and the arguments request no remote resource. Blocking sockets at the
  operating-system level belongs to the sandbox, not to this module; the adapter tests run with
  the test suite's network block active.
- **Timeout and memory.** Every run has a wall-clock timeout (120 seconds by default). Go's soft
  memory limit is set through ``GOMEMLIMIT``; for other engines the runner applies an address-space
  limit on POSIX systems (it is not available on Windows).
- **Output is data.** The engines' JSON is parsed strictly. Malformed output raises
  :class:`AdapterError` and no partial span list is returned. Error messages never quote output,
  because an engine's report holds the secret it found.

An engine's rule identifier maps to a subtype of the closed vocabulary through an explicit table.
A rule that is not in the table maps to ``generic_credential`` at ``LOW`` confidence and is
counted in :attr:`EngineScan.unmapped`; it is neither dropped nor allowed to invent a subtype.
Mapped findings are ``MEDIUM`` so that on a conflict the native ``HIGH`` detectors win, and
:func:`~codekavach.privacy.detect.overlap.resolve_overlaps` (through the registry) does the union.
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final, Protocol, runtime_checkable

from codekavach.core.log import get_logger
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.privacy.detect.base import TypedSpan

_log = get_logger("codekavach.privacy.detect")

DEFAULT_TIMEOUT_SECONDS: Final = 120.0
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
MAX_FILES: Final = 50_000
MEMORY_LIMIT_BYTES: Final = 2 * 1024**3
FALLBACK_SUBTYPE: Final = "generic_credential"

# File names an engine reads as configuration or as a suppression list. They are never staged.
REFUSED_NAMES: Final = frozenset(
    {
        ".gitleaks.toml",
        ".gitleaks.yaml",
        ".gitleaks.yml",
        ".gitleaksignore",
        ".secrets.baseline",
        ".pre-commit-config.yaml",
        "gitleaks.toml",
    }
)
_PASSED_ENVIRONMENT: Final = ("PATH", "SYSTEMROOT", "LANG", "LC_ALL")

GITLEAKS_RULES: Final[Mapping[str, str]] = {
    "aws-access-token": "aws_access_key",
    "azure-ad-client-secret": "azure_client_secret",  # pragma: allowlist secret
    "gcp-api-key": "gcp_api_key",
    "generic-api-key": "generic_credential",
    "github-app-token": "github_token",
    "github-fine-grained-pat": "github_token",
    "github-oauth": "github_token",
    "github-pat": "github_token",
    "github-refresh-token": "github_token",
    "jwt": "jwt",
    "jwt-base64": "jwt",
    "npm-access-token": "npm_token",
    "private-key": "private_key_block",
    "pypi-upload-token": "pypi_token",
    "sendgrid-api-token": "sendgrid_api_key",
    "slack-app-token": "slack_token",
    "slack-bot-token": "slack_token",
    "slack-legacy-token": "slack_token",
    "slack-user-token": "slack_token",
    "slack-webhook-url": "slack_webhook",
    "stripe-access-token": "stripe_secret_key",
    "twilio-api-key": "twilio_api_key",
}

DETECT_SECRETS_TYPES: Final[Mapping[str, str]] = {
    "AWS Access Key": "aws_access_key",
    "Azure Storage Account access key": "azure_storage_connection_string",
    "Basic Auth Credentials": "basic_auth_url",
    "Base64 High Entropy String": "high_entropy_string",
    "GitHub Token": "github_token",
    "Hex High Entropy String": "high_entropy_string",
    "JSON Web Token": "jwt",
    "NPM tokens": "npm_token",
    "Private Key": "private_key_block",
    "PyPI Token": "pypi_token",
    "Secret Keyword": "generic_credential",
    "SendGrid API Key": "sendgrid_api_key",
    "Slack Token": "slack_token",
    "Stripe Access Key": "stripe_secret_key",
    "Twilio API Key": "twilio_api_key",
}


class AdapterError(RuntimeError):
    """An engine failed, timed out or produced output that is not what it should be.

    The message names the engine and the kind of failure, never the output.
    """


@dataclass(frozen=True)
class RunSpec:
    """Everything about one subprocess call, so a fake runner can assert on all of it."""

    argv: tuple[str, ...]
    env: Mapping[str, str]
    cwd: Path
    timeout_seconds: float
    address_space_limit_bytes: int | None = None


@dataclass(frozen=True)
class RunResult:
    """The exit code and standard output of one call."""

    returncode: int
    stdout: bytes = b""


type Runner = Callable[[RunSpec], RunResult]


def subprocess_runner(spec: RunSpec) -> RunResult:
    """Run ``spec`` without a shell, without stdin and with exactly ``spec.env`` as environment.

    Raises:
        AdapterError: the process could not start or did not finish within the timeout.
    """
    limit = spec.address_space_limit_bytes
    preexec: Callable[[], None] | None = None
    if limit is not None and sys.platform != "win32":

        def preexec() -> None:  # pragma: no cover - runs in the child
            import resource  # noqa: PLC0415 - POSIX only

            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    try:
        completed = subprocess.run(
            list(spec.argv),
            capture_output=True,
            check=False,
            timeout=spec.timeout_seconds,
            env=dict(spec.env),
            cwd=spec.cwd,
            stdin=subprocess.DEVNULL,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired:
        raise AdapterError("the engine did not finish within its timeout") from None
    except (OSError, subprocess.SubprocessError):
        raise AdapterError("the engine could not be started") from None
    return RunResult(returncode=completed.returncode, stdout=completed.stdout)


@dataclass(frozen=True)
class EngineScan:
    """What one engine found: spans by repository path, and counts that show what was lost."""

    engine: str
    spans: Mapping[str, tuple[TypedSpan, ...]] = field(default_factory=dict)
    lengths: Mapping[str, int] = field(default_factory=dict)
    unmapped: int = 0
    located_by_line: int = 0
    skipped_files: int = 0


@runtime_checkable
class ExternalSecretEngine(Protocol):
    """A secret scanner that runs as a separate process.

    ``scan`` reads ``paths`` (relative to ``workdir``) and returns spans **by path**: a
    :class:`~codekavach.privacy.detect.base.TypedSpan` has no path of its own.
    """

    id: str

    def available(self) -> bool:
        """Whether the engine's executable can be found."""
        ...

    def scan(self, paths: Sequence[str], *, workdir: Path) -> EngineScan:
        """Scan ``paths`` and return the spans found."""
        ...


def _safe_relative(path: str) -> PurePosixPath | None:
    candidate = PurePosixPath(path.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        return None
    if any(part in {"", "."} for part in candidate.parts):
        return None
    return candidate


@dataclass
class StagedTree:
    """The private copy of the files to scan: where it is and what is in it."""

    root: Path
    files: dict[str, Path]  # repository path -> staged path
    contents: dict[str, bytes]
    skipped: int


def _force_remove(function: Callable[..., Any], target: str, _excinfo: object) -> None:
    Path(target).chmod(stat.S_IRWXU)
    function(target)


def _remove_tree(root: Path) -> None:
    for directory, names, _files in os.walk(root):
        for name in names:
            try:
                (Path(directory) / name).chmod(stat.S_IRWXU)
            except OSError:
                continue
    shutil.rmtree(root, onerror=_force_remove)


@contextmanager
def staged_copy(paths: Sequence[str], workdir: Path) -> Iterator[StagedTree]:
    """Copy ``paths`` into a private read-only tree and remove it afterwards.

    A path that is absolute, climbs out of ``workdir``, is not a regular file (a symbolic link is
    not followed), is larger than :data:`MAX_FILE_BYTES`, or is an engine configuration file is
    counted in ``skipped`` and left out.
    """
    root = Path(tempfile.mkdtemp(prefix="codekavach-engine-"))
    tree = root / "tree"
    tree.mkdir()
    staged = StagedTree(root=root, files={}, contents={}, skipped=0)
    try:
        base = workdir.resolve()
        for path in sorted(set(paths))[:MAX_FILES]:
            relative = _safe_relative(path)
            if relative is None or relative.name in REFUSED_NAMES:
                staged.skipped += 1
                continue
            source = base.joinpath(*relative.parts)
            try:
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                    staged.skipped += 1
                    continue
                data = source.read_bytes()
            except OSError:
                staged.skipped += 1
                continue
            target = tree.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            staged.files[relative.as_posix()] = target
            staged.contents[relative.as_posix()] = data
        for target in staged.files.values():
            target.chmod(stat.S_IRUSR)
        for directory, names, _files in os.walk(tree, topdown=False):
            for name in names:
                (Path(directory) / name).chmod(stat.S_IRUSR | stat.S_IXUSR)
        tree.chmod(stat.S_IRUSR | stat.S_IXUSR)
        yield staged
    finally:
        _remove_tree(root)


def engine_environment(environ: Mapping[str, str], home: Path) -> dict[str, str]:
    """A short allow-list of ``environ`` plus private home and configuration directories.

    No proxy variable, token or other credential is passed on.
    """
    env = {name: environ[name] for name in _PASSED_ENVIRONMENT if name in environ}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "NO_COLOR": "1",
            "NO_PROXY": "*",
        }
    )
    return env


def _line_starts(data: bytes) -> list[int]:
    starts = [0]
    starts.extend(index + 1 for index, byte in enumerate(data) if byte == 0x0A)
    return starts


def _line_bounds(data: bytes, starts: list[int], first: int, last: int) -> tuple[int, int] | None:
    """Byte range of lines ``first``..``last`` (1-based), without the final line break."""
    if not 1 <= first <= last <= len(starts):
        return None
    begin = starts[first - 1]
    end = starts[last] - 1 if last < len(starts) else len(data)
    if end > begin and data[end - 1 : end] == b"\r":
        end -= 1
    return (begin, end) if end > begin else None


def _span(subtype: str, start: int, end: int, confidence: Confidence, detector: str) -> TypedSpan:
    return TypedSpan(
        kind=PlaceholderKind.SECRET,
        subtype=subtype,
        start_byte=start,
        end_byte=end,
        confidence=confidence,
        detector=detector,
    )


def _as_list(raw: bytes, engine: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8") or "[]")
    except (UnicodeDecodeError, ValueError):
        raise AdapterError(f"{engine} produced output that is not JSON") from None


def _staged_name(reported: object, staged: StagedTree) -> str | None:
    """The repository path of a file an engine reported by its staged path."""
    if not isinstance(reported, str):
        return None
    try:
        tree = (staged.root / "tree").resolve()
        relative = Path(reported).resolve().relative_to(tree)
    except (OSError, ValueError):
        return None
    name = relative.as_posix()
    return name if name in staged.files else None


class _BaseEngine:
    """What the two engines share: finding the executable and one controlled run."""

    id: str
    executable_name: str

    def __init__(
        self,
        *,
        executable: str | None = None,
        runner: Runner = subprocess_runner,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._executable = executable
        self._runner = runner
        self._timeout = timeout_seconds
        self._environ = os.environ if environ is None else environ

    def _path(self) -> str | None:
        return self._executable or shutil.which(self.executable_name)

    def available(self) -> bool:
        """Whether the engine's executable can be found."""
        return self._path() is not None

    def _run(self, argv: Sequence[str], staged: StagedTree, extra_env: Mapping[str, str]) -> bytes:
        executable = self._path()
        if executable is None:
            raise AdapterError(f"{self.id} is not installed")
        home = staged.root / "home"
        home.mkdir(exist_ok=True)
        env = engine_environment(self._environ, home)
        env.update(extra_env)
        spec = RunSpec(
            argv=(executable, *argv),
            env=env,
            cwd=staged.root,
            timeout_seconds=self._timeout,
            address_space_limit_bytes=self.address_space_limit(),
        )
        result = self._runner(spec)
        if result.returncode != 0:
            raise AdapterError(f"{self.id} exited with status {result.returncode}")
        return result.stdout

    def address_space_limit(self) -> int | None:
        return None


class GitleaksEngine(_BaseEngine):
    """Gitleaks, a Go regular-expression and entropy scanner (MIT; version 8.19 or later).

    Flags: ``dir`` scans a directory without git history; ``--report-path -`` writes the JSON
    report to standard output so the engine writes no file; ``--exit-code 0`` keeps a finding from
    being an error; ``--ignore-gitleaks-allow`` ignores ``gitleaks:allow`` comments, which are
    repository-supplied suppressions; no ``--config`` is passed and the staged tree holds no
    configuration file. The engine has no live validation.
    """

    id = "gitleaks"
    executable_name = "gitleaks"

    def scan(self, paths: Sequence[str], *, workdir: Path) -> EngineScan:
        """Scan ``paths`` with Gitleaks."""
        with staged_copy(paths, workdir) as staged:
            if not staged.files:
                return EngineScan(self.id, skipped_files=staged.skipped)
            argv = (
                "dir", str(staged.root / "tree"), "--no-banner", "--no-color",
                "--report-format", "json", "--report-path", "-", "--exit-code", "0",
                "--log-level", "error", "--ignore-gitleaks-allow",
                "--max-target-megabytes", str(MAX_FILE_BYTES // (1024 * 1024)),
            )  # fmt: skip
            raw = self._run(argv, staged, {"GOMEMLIMIT": f"{MEMORY_LIMIT_BYTES}B"})
            return parse_gitleaks(raw, staged, detector=f"secret.{self.id}")


class DetectSecretsEngine(_BaseEngine):
    """detect-secrets, a Python baseline scanner (Apache-2.0), run as a command.

    Flags: ``scan --all-files`` reads the named files whatever git says; ``--no-verify`` turns
    live verification off. No baseline file is passed, so a repository's ``.secrets.baseline`` is
    not read.
    """

    id = "detect_secrets"
    executable_name = "detect-secrets"

    def address_space_limit(self) -> int | None:
        """A 2 GiB address-space limit, applied by the runner on POSIX systems."""
        return MEMORY_LIMIT_BYTES

    def scan(self, paths: Sequence[str], *, workdir: Path) -> EngineScan:
        """Scan ``paths`` with detect-secrets."""
        with staged_copy(paths, workdir) as staged:
            if not staged.files:
                return EngineScan(self.id, skipped_files=staged.skipped)
            names = sorted(staged.files)
            argv = (
                "scan", "--all-files", "--no-verify",
                *(str(staged.files[name]) for name in names),
            )  # fmt: skip
            raw = self._run(argv, staged, {})
            return parse_detect_secrets(raw, staged, detector=f"secret.{self.id}")


def _finish(
    engine: str,
    found: dict[str, list[TypedSpan]],
    staged: StagedTree,
    *,
    unmapped: int,
    by_line: int,
) -> EngineScan:
    if unmapped:
        _log.warning("external_secret_rules_unmapped", engine=engine, count=unmapped)
    return EngineScan(
        engine=engine,
        spans={name: tuple(spans) for name, spans in found.items()},
        lengths={name: len(staged.contents[name]) for name in staged.files},
        unmapped=unmapped,
        located_by_line=by_line,
        skipped_files=staged.skipped,
    )


def parse_gitleaks(raw: bytes, staged: StagedTree, *, detector: str) -> EngineScan:
    """Turn a Gitleaks JSON report into spans, locating each secret in its staged file.

    Raises:
        AdapterError: the report is not a list of findings with the expected fields.
    """
    report = _as_list(raw, "gitleaks")
    if report is None:
        report = []
    if not isinstance(report, list):
        raise AdapterError("gitleaks produced an unexpected report")
    found: dict[str, list[TypedSpan]] = {}
    unmapped = by_line = 0
    starts: dict[str, list[int]] = {}
    for entry in report:
        if not isinstance(entry, dict):
            raise AdapterError("gitleaks produced an unexpected finding")
        rule, first, last = entry.get("RuleID"), entry.get("StartLine"), entry.get("EndLine")
        secret = entry.get("Secret", "")
        if (
            not isinstance(rule, str)
            or not isinstance(first, int)
            or not isinstance(last, int)
            or not isinstance(secret, str)
        ):
            raise AdapterError("gitleaks produced a finding without the expected fields")
        name = _staged_name(entry.get("File"), staged)
        if name is None:
            continue
        data = staged.contents[name]
        subtype = GITLEAKS_RULES.get(rule)
        confidence = Confidence.MEDIUM
        if subtype is None:
            subtype, confidence = FALLBACK_SUBTYPE, Confidence.LOW
            unmapped += 1
        starts.setdefault(name, _line_starts(data))
        bounds = _line_bounds(data, starts[name], first, last)
        if bounds is None:
            continue
        begin = data.find(secret.encode("utf-8"), bounds[0], bounds[1]) if secret else -1
        if begin >= 0:
            span = _span(subtype, begin, begin + len(secret.encode("utf-8")), confidence, detector)
        else:
            by_line += 1
            span = _span(subtype, bounds[0], bounds[1], Confidence.LOW, detector)
        found.setdefault(name, []).append(span)
    return _finish("gitleaks", found, staged, unmapped=unmapped, by_line=by_line)


_ATOM_SPLIT: Final = re.compile(rb"[\s'\"`=:,;(){}\[\]<>@/]+")


def _candidates(line: bytes) -> Iterator[tuple[int, bytes]]:
    """Substrings of ``line`` that may be the secret: whole runs and the atoms inside them."""
    for run in re.finditer(rb"\S+", line):
        yield run.start(), run.group()
    position = 0
    for piece in _ATOM_SPLIT.split(line):
        index = line.find(piece, position)
        if piece and index >= 0:
            yield index, piece
            position = index + len(piece)


def parse_detect_secrets(raw: bytes, staged: StagedTree, *, detector: str) -> EngineScan:
    """Turn a detect-secrets report into spans.

    The report holds the SHA-1 of each secret and its line, not the secret. The secret is found
    on its line as the substring with that hash; if no substring matches, the span is the whole
    line at ``LOW`` confidence.

    Raises:
        AdapterError: the report is not the expected JSON object.
    """
    report = _as_list(raw, "detect-secrets")
    results = report.get("results") if isinstance(report, dict) else None
    if not isinstance(results, dict):
        raise AdapterError("detect-secrets produced an unexpected report")
    found: dict[str, list[TypedSpan]] = {}
    unmapped = by_line = 0
    for reported, entries in results.items():
        name = _staged_name(reported, staged)
        if name is None:
            continue
        if not isinstance(entries, list):
            raise AdapterError("detect-secrets produced an unexpected finding list")
        data = staged.contents[name]
        starts = _line_starts(data)
        for entry in entries:
            kind, number = (
                (entry.get("type"), entry.get("line_number"))
                if isinstance(entry, dict)
                else (None, None)
            )
            digest = entry.get("hashed_secret") if isinstance(entry, dict) else None
            if not isinstance(kind, str) or not isinstance(number, int):
                raise AdapterError("detect-secrets produced a finding without the expected fields")
            subtype = DETECT_SECRETS_TYPES.get(kind)
            confidence = Confidence.MEDIUM
            if subtype is None:
                subtype, confidence = FALLBACK_SUBTYPE, Confidence.LOW
                unmapped += 1
            bounds = _line_bounds(data, starts, number, number)
            if bounds is None:
                continue
            line = data[bounds[0] : bounds[1]]
            span = None
            for offset, text in _candidates(line):
                if isinstance(digest, str) and hashlib.sha1(text).hexdigest() == digest:  # noqa: S324 - matches the engine's own digest
                    start = bounds[0] + offset
                    span = _span(subtype, start, start + len(text), confidence, detector)
                    break
            if span is None:
                by_line += 1
                span = _span(subtype, bounds[0], bounds[1], Confidence.LOW, detector)
            found.setdefault(name, []).append(span)
    return _finish("detect_secrets", found, staged, unmapped=unmapped, by_line=by_line)


class ExternalFindingsDetector:
    """A :class:`~codekavach.privacy.detect.base.Detector` that replays an engine's findings.

    The engine ran once over the tree; this object hands the spans of one file to the registry
    when that file's text is detected, so the union with the native detectors is made by
    ``resolve_overlaps`` like any other overlap. A span is byte offsets into the scanned file, so
    a text of a different length (a slice, an edited file) gets no spans.
    """

    kinds = frozenset({PlaceholderKind.SECRET})

    def __init__(self, scan: EngineScan) -> None:
        self._scan = scan
        self.id = f"secret.{scan.engine.replace('-', '_')}"

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> Sequence[TypedSpan]:
        """The engine's spans for ``path`` when ``text`` is the file it scanned."""
        del language
        key = str(path)
        spans = self._scan.spans.get(key, ())
        if not spans:
            return ()
        if len(text.expose().encode("utf-8", errors="surrogatepass")) != self._scan.lengths.get(
            key
        ):
            return ()
        return spans
