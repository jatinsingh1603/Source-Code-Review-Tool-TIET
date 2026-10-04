"""``codekavach doctor``: diagnose the local environment before a scan fails on it (E05-20).

Owning epic: E05.

The command runs the registered checks one after another and prints one row per check with the
status ``PASS``, ``WARN``, ``FAIL`` or ``SKIP`` and, for a check that did not pass, a remediation
hint. It exits 1 when a required check failed (with ``--strict`` also on any failure or warning)
and 0 otherwise: it completed and reports what it was asked to look for, so it never uses the
exit code for defects. It only diagnoses; it repairs nothing and creates nothing.

Adding a check. A check is an object with ``name`` (``category:detail``), ``category``,
``required``, ``needs_network`` and ``run(ctx) -> CheckResult``; ``LocalCheck`` wraps a function
that returns an ``Outcome``. Another epic registers its checks from its own CLI module::

    from codekavach.cli.doctor import LocalCheck, Outcome, CheckStatus, register_check


    def _probe(ctx: CliContext) -> Outcome:
        return Outcome(CheckStatus.PASS, "3 engines found")


    register_check(LocalCheck("engines:installed", "engines", _probe, remediation="..."))

A probe that belongs to an epic that has not landed is obtained with ``load_backend``; the
resulting ``BackendUnavailableError`` is shown as ``SKIP not available in this build``.

Output is routinely pasted into public issue trackers, so it holds versions, paths and statuses
only: no environment variable values, key names, configuration values or exception messages. A
crashed check is reported by its exception class. The keyring check looks at the backend only and
never reads an entry, which could trigger an unlock prompt. No check here uses the network.
"""

import importlib.metadata
import locale
import os
import platform
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Final, Protocol

import typer
from pydantic import JsonValue
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.context import CliContext, get_context
from codekavach.cli.errors import BackendUnavailableError, ThresholdExceeded, UsageError
from codekavach.cli.output import get_output

DEFAULT_TIMEOUT_SECONDS: Final = 10.0
NOT_IN_BUILD: Final = "not available in this build"
MINIMUM_PYTHON: Final = (3, 12)
STATE_DIR_MODE: Final = 0o700
REQUIRED_GRAMMARS: Final = ("python", "javascript")


class CheckStatus(StrEnum):
    """How one check ended."""

    PASS = "pass"  # noqa: S105 - a status name
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class CheckResult:
    """The result of one check; every field is safe to paste into a bug report."""

    name: str
    category: str
    status: CheckStatus
    summary: str
    remediation: str | None = None
    details: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))
    duration_ms: int = 0
    required: bool = False

    def to_json(self) -> dict[str, JsonValue]:
        """The entry of ``data.checks``."""
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "summary": self.summary,
            "remediation": self.remediation,
            "details": dict(self.details),
            "duration_ms": self.duration_ms,
            "required": self.required,
        }


class Check(Protocol):
    """One diagnosis."""

    @property
    def name(self) -> str:
        """``category:detail``, unique among the checks."""

    @property
    def category(self) -> str:
        """The group selected by ``--category``."""

    @property
    def required(self) -> bool:
        """Whether a failure makes the command exit 1 without ``--strict``."""

    @property
    def needs_network(self) -> bool:
        """Whether the check is skipped under ``--offline``."""

    def run(self, ctx: CliContext) -> CheckResult:
        """Examine the environment; may raise, which the runner reports as a crash."""


@dataclass(frozen=True)
class Outcome:
    """What a probe function found."""

    status: CheckStatus
    summary: str
    details: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True)
class LocalCheck:
    """A check made from a probe function; the hint is shown when the check does not pass."""

    name: str
    category: str
    probe: Callable[[CliContext], Outcome]
    required: bool = False
    needs_network: bool = False
    remediation: str | None = None

    def run(self, ctx: CliContext) -> CheckResult:
        """Run the probe and attach the remediation hint to a result that did not pass."""
        outcome = self.probe(ctx)
        passed = outcome.status in {CheckStatus.PASS, CheckStatus.SKIP}
        return CheckResult(
            name=self.name,
            category=self.category,
            status=outcome.status,
            summary=outcome.summary,
            remediation=None if passed else self.remediation,
            details=outcome.details,
            required=self.required,
        )


_REGISTRY: dict[str, Check] = {}


def register_check(check: Check) -> None:
    """Add ``check``; a check registered under the same name is replaced, keeping its place."""
    _REGISTRY[check.name] = check


def all_checks() -> tuple[Check, ...]:
    """The registered checks in registration order."""
    return tuple(_REGISTRY.values())


# the runner


def _blank(check: Check, status: CheckStatus, summary: str, duration_ms: int = 0) -> CheckResult:
    return CheckResult(
        name=check.name,
        category=check.category,
        status=status,
        summary=summary,
        duration_ms=duration_ms,
        required=check.required,
    )


def run_check(check: Check, ctx: CliContext, *, timeout: float) -> CheckResult:
    """Run one check under ``timeout`` seconds; a crash or an overrun becomes a failed result.

    The check runs in a daemon thread that is abandoned when it overruns, so that a hanging
    probe can neither block the command nor keep the process alive.
    """
    if check.needs_network and ctx.offline:
        return _blank(check, CheckStatus.SKIP, "offline")
    box: list[CheckResult | BaseException] = []

    def target() -> None:
        try:
            box.append(check.run(ctx))
        except BaseException as error:  # noqa: BLE001 - reported by its class name only
            box.append(error)

    started = time.perf_counter()
    thread = threading.Thread(target=target, name=f"ck-doctor-{check.name}", daemon=True)
    thread.start()
    thread.join(timeout)
    duration_ms = int((time.perf_counter() - started) * 1000)
    if not box:
        return _blank(check, CheckStatus.FAIL, "timed out", duration_ms)
    found = box[0]
    if isinstance(found, BackendUnavailableError):
        return _blank(check, CheckStatus.SKIP, NOT_IN_BUILD, duration_ms)
    if isinstance(found, BaseException):
        summary = f"check crashed: {type(found).__name__}"
        return _blank(check, CheckStatus.FAIL, summary, duration_ms)
    return CheckResult(
        name=check.name,
        category=check.category,
        status=found.status,
        summary=found.summary,
        remediation=found.remediation,
        details=found.details,
        duration_ms=duration_ms,
        required=check.required,
    )


def run_checks(checks: Sequence[Check], ctx: CliContext, *, timeout: float) -> list[CheckResult]:
    """Run ``checks`` one after another, in the given order."""
    return [run_check(check, ctx, timeout=timeout) for check in checks]


def select_checks(
    checks: Sequence[Check], *, categories: Sequence[str], names: Sequence[str]
) -> list[Check]:
    """The checks matching ``--category`` and ``--check``; an unknown name or category exits 2."""
    known_names = {check.name for check in checks}
    known_categories = {check.category for check in checks}
    for name in names:
        if name not in known_names:
            raise UsageError(
                f"unknown check: {name}", code="unknown_check", hint="see codekavach doctor --list"
            )
    for category in categories:
        if category not in known_categories:
            raise UsageError(
                f"unknown category: {category}",
                code="unknown_category",
                hint=f"categories: {', '.join(sorted(known_categories))}",
            )
    return [
        check
        for check in checks
        if (not categories or check.category in categories) and (not names or check.name in names)
    ]


def totals(results: Sequence[CheckResult]) -> dict[str, int]:
    """How many checks passed, warned, failed and were skipped."""
    count = dict.fromkeys(CheckStatus, 0)
    for result in results:
        count[result.status] += 1
    return {
        "passed": count[CheckStatus.PASS],
        "warnings": count[CheckStatus.WARN],
        "failed": count[CheckStatus.FAIL],
        "skipped": count[CheckStatus.SKIP],
    }


def has_failed(results: Sequence[CheckResult], *, strict: bool) -> bool:
    """True when a required check failed, or under ``strict`` any check failed or warned."""
    if strict:
        return any(result.status in {CheckStatus.FAIL, CheckStatus.WARN} for result in results)
    return any(result.required and result.status is CheckStatus.FAIL for result in results)


def totals_line(results: Sequence[CheckResult]) -> str:
    """``7 passed, 1 warning, 1 failed, 2 skipped``."""
    count = totals(results)
    warnings = "warning" if count["warnings"] == 1 else "warnings"
    return (
        f"{count['passed']} passed, {count['warnings']} {warnings}, "
        f"{count['failed']} failed, {count['skipped']} skipped"
    )


def render_lines(results: Sequence[CheckResult]) -> list[str]:
    """The human output: one row per check, the hints of non-passing checks, the totals."""
    width = max((len(result.name) for result in results), default=0)
    lines = [
        f"{result.status.value.upper():<4}  {result.name:<{width}}  {result.summary}".rstrip()
        for result in results
    ]
    lines.extend(
        f"hint  {result.name:<{width}}  {result.remediation}"
        for result in results
        if result.remediation and result.status in {CheckStatus.WARN, CheckStatus.FAIL}
    )
    lines.append(totals_line(results))
    return lines


# local checks


def _names(values: Iterable[str]) -> list[JsonValue]:
    """Distinct names, sorted, as a JSON list."""
    names: list[JsonValue] = [*sorted(set(values))]
    return names


def _python(_ctx: CliContext) -> Outcome:
    version = ".".join(str(part) for part in sys.version_info[:3])
    status = CheckStatus.PASS if sys.version_info >= MINIMUM_PYTHON else CheckStatus.FAIL
    return Outcome(status, version, {"version": version})


def _package(_ctx: CliContext) -> Outcome:
    try:
        distribution = importlib.metadata.distribution("codekavach")
    except importlib.metadata.PackageNotFoundError:
        return Outcome(CheckStatus.FAIL, "the codekavach distribution is not installed")
    location = str(distribution.locate_file(""))
    return Outcome(
        CheckStatus.PASS,
        distribution.version,
        {"version": distribution.version, "location": location},
    )


def _platform(_ctx: CliContext) -> Outcome:
    encoding = (getattr(sys.stdout, "encoding", None) or "unknown").lower()
    details: dict[str, JsonValue] = {
        "os": platform.system(),
        "architecture": platform.machine(),
        "locale": locale.getlocale()[0],
        "stdout_encoding": encoding,
        "codekavach_variables": _names(n for n in os.environ if n.startswith("CODEKAVACH_")),
    }
    summary = f"{details['os']} {details['architecture']}, stdout {encoding}"
    utf8 = encoding.replace("-", "").replace("_", "") == "utf8"
    return Outcome(CheckStatus.PASS if utf8 else CheckStatus.WARN, summary, details)


def _config(ctx: CliContext) -> Outcome:
    from codekavach.config.errors import ConfigError  # noqa: PLC0415

    try:
        loaded = ctx.loaded
    except ConfigError as error:
        count = len(error.issues)
        return Outcome(
            CheckStatus.FAIL,
            f"configuration is invalid: {count} problem(s)",
            {"codes": _names(issue.code.value for issue in error.issues)},
        )
    warnings = len(loaded.warnings)
    details: dict[str, JsonValue] = {
        "profile": loaded.profile,
        "project_config": str(loaded.project_config) if loaded.project_config else None,
        "warnings": warnings,
    }
    summary = f"profile {loaded.profile or 'none'}, {warnings} warning(s)"
    return Outcome(CheckStatus.WARN if warnings else CheckStatus.PASS, summary, details)


def state_dir_of(ctx: CliContext) -> Path:
    """The state directory of this project; the default location when the configuration fails."""
    from codekavach.config.errors import ConfigError  # noqa: PLC0415
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415

    try:
        loaded = ctx.loaded
    except ConfigError:
        return (ctx.target_hint or Path.cwd()) / ".codekavach"
    return resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir)


def _state_dir(ctx: CliContext) -> Outcome:
    path = state_dir_of(ctx)
    details: dict[str, JsonValue] = {"path": str(path)}
    if path.is_symlink():
        return Outcome(CheckStatus.FAIL, "the state directory is a symbolic link", details)
    if path.exists():
        status, summary = _existing_state_dir(path)
        return Outcome(status, summary, details)
    try:  # creation is tested in a temporary sibling path, which is removed again
        probe = Path(tempfile.mkdtemp(dir=path.parent, prefix=".codekavach-doctor-"))
        probe.rmdir()
    except OSError:
        return Outcome(CheckStatus.FAIL, "the state directory cannot be created", details)
    return Outcome(CheckStatus.PASS, "does not exist yet and can be created", details)


def _existing_state_dir(path: Path) -> tuple[CheckStatus, str]:
    if not path.is_dir():
        return CheckStatus.FAIL, "the state path is not a directory"
    if not os.access(path, os.W_OK):
        return CheckStatus.FAIL, "the state directory is not writable"
    mode = stat.S_IMODE(path.stat().st_mode)
    if os.name != "nt" and mode != STATE_DIR_MODE:
        return CheckStatus.WARN, f"mode is {mode:o}, expected 700"
    return CheckStatus.PASS, "exists and is writable"


def _artefacts(ctx: CliContext) -> Outcome:
    stats = load_backend(
        "codekavach.core.store.artefacts", "store_stats", feature="artefact statistics", epic="E04"
    )(state_dir_of(ctx))
    summary = f"{stats['blobs']} blob(s), {stats['bytes']} bytes"
    return Outcome(CheckStatus.PASS, summary, dict(stats))


def _database(ctx: CliContext) -> Outcome:
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

    probe = load_backend(
        "codekavach.core.store.repositories", "db_probe", feature="the local database", epic="E04"
    )(StateLayout(state_dir_of(ctx)))
    details: dict[str, JsonValue] = {
        "path": probe["path"],
        "revision": probe["revision"],
        "head": probe["head"],
    }
    if not probe["exists"]:
        return Outcome(CheckStatus.PASS, "no database yet; the first scan creates it", details)
    if probe["revision"] != probe["head"]:
        return Outcome(CheckStatus.FAIL, "the schema is not at the newest revision", details)
    return Outcome(CheckStatus.PASS, f"schema at {probe['head']}", details)


def _grammar(language: str) -> Callable[[CliContext], Outcome]:
    def probe(_ctx: CliContext) -> Outcome:
        load = load_backend(
            "codekavach.parsing.grammars",
            "load_grammar",
            feature="tree-sitter grammars",
            epic="E07",
        )
        try:
            load(language)
        except Exception:  # noqa: BLE001 - the reason is not shown; it may name local paths
            return Outcome(CheckStatus.FAIL, "grammar could not be loaded")
        return Outcome(CheckStatus.PASS, "grammar loads")

    return probe


def _keyring(_ctx: CliContext) -> Outcome:
    from codekavach.config.errors import SecretResolutionError  # noqa: PLC0415
    from codekavach.config.keys import KeyringUnavailableError, open_keyring  # noqa: PLC0415

    try:
        keyring = open_keyring()  # looks at the backend only; no entry is read
    except KeyringUnavailableError:
        return Outcome(CheckStatus.WARN, "no keyring backend; passphrase mode will be used")
    except SecretResolutionError:
        return Outcome(CheckStatus.WARN, "the keyring backend is insecure and is refused")
    backend = type(keyring.get_keyring()).__name__
    return Outcome(CheckStatus.PASS, f"backend {backend}", {"backend": backend})


def _plugins(_ctx: CliContext) -> Outcome:
    from codekavach.core.plugins.registry import registry_from_environment  # noqa: PLC0415

    failures = registry_from_environment().failures()
    if not failures:
        return Outcome(CheckStatus.PASS, "every plugin loads")
    broken: list[JsonValue] = [f"{failure.spec.group}:{failure.spec.name}" for failure in failures]
    return Outcome(CheckStatus.WARN, f"{len(broken)} plugin(s) failed to load", {"broken": broken})


def _register_local_checks() -> None:
    register_check(
        LocalCheck(
            "runtime:python", "runtime", _python, required=True,
            remediation="install Python 3.12 or later",
        )
    )  # fmt: skip
    register_check(
        LocalCheck(
            "runtime:package", "runtime", _package, required=True,
            remediation="reinstall with `uv sync`",
        )
    )  # fmt: skip
    register_check(
        LocalCheck("runtime:platform", "runtime", _platform, remediation="set PYTHONUTF8=1")
    )
    register_check(
        LocalCheck(
            "config:valid", "config", _config, required=True,
            remediation="run `codekavach config validate`",
        )
    )  # fmt: skip
    register_check(
        LocalCheck(
            "storage:state-dir", "storage", _state_dir, required=True,
            remediation="chmod 700 .codekavach",
        )
    )  # fmt: skip
    register_check(
        LocalCheck(
            "storage:artefacts", "storage", _artefacts,
            remediation="remove a corrupt .codekavach/artefacts",
        )
    )  # fmt: skip
    register_check(
        LocalCheck(
            "storage:database", "storage", _database,
            remediation="run a scan to migrate, or delete codekavach.db",
        )
    )  # fmt: skip
    for language in REQUIRED_GRAMMARS:
        register_check(
            LocalCheck(
                f"parsing:grammar:{language}", "parsing", _grammar(language), required=True,
                remediation="uv sync --all-extras",
            )
        )  # fmt: skip
    register_check(
        LocalCheck(
            "secrets:keyring", "secrets", _keyring,
            remediation="install a keyring backend or use passphrase mode",
        )
    )  # fmt: skip
    register_check(
        LocalCheck(
            "plugins:load", "plugins", _plugins,
            remediation="reinstall or remove the named plugin",
        )
    )  # fmt: skip


_register_local_checks()


def doctor_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    category: Annotated[
        list[str] | None, typer.Option("--category", help="Run this category only; repeatable.")
    ] = None,
    check: Annotated[
        list[str] | None, typer.Option("--check", help="Run this check only; repeatable.")
    ] = None,
    strict: Annotated[bool, typer.Option("--strict", help="Warnings count as failures.")] = False,
    list_checks: Annotated[
        bool, typer.Option("--list", help="List the checks and run nothing.")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", min=0.1, help="Seconds allowed per check.")
    ] = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """Check that this machine is ready to scan."""
    cli_ctx = get_context(ctx)
    out = get_output(ctx)
    selected = select_checks(all_checks(), categories=category or (), names=check or ())
    if list_checks:
        listing: list[JsonValue] = [
            {"name": item.name, "category": item.category, "required": item.required}
            for item in selected
        ]
        out.result(
            {"checks": listing},
            human=lambda console: _print_lines(
                console, [f"{item.name}  ({item.category})" for item in selected]
            ),
        )
        return
    results = run_checks(selected, cli_ctx, timeout=timeout)
    data: dict[str, Any] = {
        "checks": [result.to_json() for result in results],
        "totals": totals(results),
    }
    out.result(data, human=lambda console: _print_lines(console, render_lines(results)))
    if has_failed(results, strict=strict):
        raise ThresholdExceeded(f"doctor found problems: {totals_line(results)}")


def _print_lines(console: Console, lines: Sequence[str]) -> None:
    for line in lines:
        console.print(line, markup=False, highlight=False, soft_wrap=True)
