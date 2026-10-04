"""The CLI side of interrupting and resuming a scan (E05-14).

Owning epic: E05.

This module registers no signal handler. While a scan runs, the handlers of the pipeline
(``run_scan(handle_sigint=True)``, E04-29) own SIGINT and SIGTERM: the first signal cancels the
scan at the next safe point and leaves a resumable checkpoint, the second exits at once, and the
previous handlers are restored. ``KeyboardInterrupt`` in the phases before and after ``run_scan()``
reaches the single top-level handler of ``codekavach.cli.app``, which exits 130.

What lives here is what the CLI adds: the message and the JSON data of a cancelled scan, the
mapping of a refused resume to its error codes, the salt of a resumed scan, and the ``--resume``
spelling without a value.

A resumed scan must reuse the salt of its first attempt, or its pseudonyms would differ before
and after the interruption (I5). The checkpoint holds only the salt's fingerprint (I3), so the
salt itself has to come from the vault (E10). Until the vault exists this build has no stored
salt, and ``--resume`` is refused with ``resume_salt_changed`` rather than continued with a fresh
one. The resume hint and the JSON data contain a scan id and a stage name only.
"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final, NoReturn

from codekavach.cli.backends import load_backend
from codekavach.cli.console import get_err_console
from codekavach.cli.errors import BackendUnavailableError, UsageError

if TYPE_CHECKING:
    from codekavach.cli.output import Output
    from codekavach.core.pipeline.resume import ResumeMismatchError

RESUME_OPTION: Final = "--resume"
LATEST: Final = "latest"
SALT_BACKEND: Final = ("codekavach.privacy.vault", "scan_salt_for")
_DONE: Final = frozenset({"succeeded", "cached"})
_RESUME_CODES: Final = {
    "checkpoint": "resume_not_found",
    "status": "resume_not_cancelled",
    "codekavach_version": "resume_config_changed",
    "settings_fingerprint": "resume_config_changed",
    "salt_fingerprint": "resume_salt_changed",
    "target_digest": "resume_target_mismatch",
}
_RESUME_MESSAGES: Final = {
    "resume_not_found": "there is no interrupted scan to resume",
    "resume_not_cancelled": "the scan already finished",
    "resume_config_changed": "the configuration or CodeKavach changed since the scan started",
    "resume_salt_changed": "the scan salt is not the one the scan started with",
    "resume_target_mismatch": "the scan was started for another target",
}
_WITHOUT_RESUME: Final = "run without --resume to start a new scan"


def normalise_resume(argv: Sequence[str]) -> list[str]:
    """Give a bare ``--resume`` the value ``latest``.

    The option takes a scan id; written last or directly before another option it means the
    newest interrupted scan. Put the target before ``--resume`` (``scan . --resume``).
    """
    result: list[str] = []
    for index, token in enumerate(argv):
        result.append(token)
        if token != RESUME_OPTION:
            continue
        following = argv[index + 1] if index + 1 < len(argv) else None
        if following is None or following.startswith("-"):
            result.append(LATEST)
    return result


def last_completed_stage(outcome: Any) -> str | None:
    """The last stage of ``outcome`` that succeeded or was served from the cache."""
    done = [run.stage for run in outcome.result.stage_runs if str(run.outcome.value) in _DONE]
    return done[-1] if done else None


def cancellation_lines(scan_id: str, target: str, stage: str | None) -> list[str]:
    """What the user is told after a cancelled scan."""
    where = f"after stage '{stage}'" if stage else "before a stage completed"
    return [
        f"scan {scan_id} cancelled {where}",
        f"resume with: codekavach scan {target} --resume {scan_id}",
    ]


def report_cancelled(out: "Output", target: str, outcome: Any) -> NoReturn:
    """Print the resume hint (stderr) or fill the JSON envelope, then end with exit 130.

    Raises:
        ScanCancelledError: always; the top-level handler maps it to exit 130.
    """
    from codekavach.core.pipeline.cancel import ScanCancelledError  # noqa: PLC0415

    scan_id = str(outcome.scan.id)
    out.result({"scan_id": scan_id, "resumable": True}, human=lambda _console: None)
    if out.json_mode:
        out.record_error("cancelled", "the scan was cancelled")
    else:
        console = get_err_console()
        for line in cancellation_lines(scan_id, target, last_completed_stage(outcome)):
            console.print(line, markup=False, soft_wrap=True)
    raise ScanCancelledError("cancelled")


def resume_refusal(error: "ResumeMismatchError") -> UsageError:
    """The usage error (exit 2) of a resume that the pipeline refused."""
    code = _RESUME_CODES.get(error.field, "resume_not_found")
    return UsageError(_RESUME_MESSAGES[code], code=code, hint=_WITHOUT_RESUME)


def scan_salt(loaded: Any, resume: str | None) -> Any:
    """The salt of this run: a fresh one for a new scan, the stored one for a resumed scan.

    Raises:
        UsageError: ``resume_salt_changed`` when a scan is resumed and this build has no vault
            to return its salt; no fresh salt is generated in that case.
    """
    if resume is None:
        from codekavach.core.pipeline.salt import ScanSalt  # noqa: PLC0415

        return ScanSalt.generate()
    try:
        stored = load_backend(
            *SALT_BACKEND, feature="resuming a scan with its stored salt", epic="E10"
        )
    except BackendUnavailableError:
        raise UsageError(
            "this build has no stored scan salt, so the resumed scan would use other pseudonyms",
            code="resume_salt_changed",
            hint=_WITHOUT_RESUME,
        ) from None
    return stored(loaded, resume)
