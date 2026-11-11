"""Engine errors (E14-01).

Owning epic: E14.

Every error carries the engine id and a closed machine code, and never the engine's own output:
an engine quotes client code in its stderr, so the message is built from fixed phrases only
(invariant I4 read for engines: degrade and report, never leak). The codes are the closed set
that ``RunContext.fail_item`` receives as the item error code.
"""

from typing import ClassVar, Final, Literal

CODE_UNAVAILABLE: Final = "engine_unavailable"
CODE_TIMEOUT: Final = "engine_timeout"
CODE_ERROR: Final = "engine_error"
CODE_TRUNCATED: Final = "engine_output_truncated"
CODE_LICENCE_BLOCKED: Final = "engine_licence_blocked"
CODE_SANDBOX_ERROR: Final = "engine_sandbox_error"

ERROR_CODES: Final = frozenset(
    {
        CODE_UNAVAILABLE,
        CODE_TIMEOUT,
        CODE_ERROR,
        CODE_TRUNCATED,
        CODE_LICENCE_BLOCKED,
        CODE_SANDBOX_ERROR,
    }
)

LICENCE_ATTESTATION_SENTENCE: Final = (
    "I confirm that my licence for this engine permits scanning proprietary code."
)

BlockReason = Literal["licence_attestation", "hosted"]


class EngineError(Exception):
    """Base of the engine errors; ``detail`` must be a fixed phrase, never engine output."""

    code: ClassVar[str] = CODE_ERROR

    def __init__(self, engine_id: str, detail: str = "") -> None:
        self.engine_id = engine_id
        message = f"{self.code}: engine {engine_id}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class EngineUnavailable(EngineError):  # noqa: N818 - the name is fixed by E14-01
    """The engine is not installed, or its version is not usable."""

    code: ClassVar[str] = CODE_UNAVAILABLE


class EngineTimeout(EngineError):  # noqa: N818
    """The engine ran past its time limit and was killed."""

    code: ClassVar[str] = CODE_TIMEOUT


class EngineOutputTooLarge(EngineError):  # noqa: N818
    """The engine wrote more than the output cap."""

    code: ClassVar[str] = CODE_TRUNCATED


class EngineSandboxError(EngineError):
    """The sandbox could not be set up or could not run the engine."""

    code: ClassVar[str] = CODE_SANDBOX_ERROR


class EngineLicenceBlocked(EngineError):  # noqa: N818
    """The engine may not run: it needs a licence attestation, or it is refused when hosted."""

    code: ClassVar[str] = CODE_LICENCE_BLOCKED

    def __init__(self, engine_id: str, reason: BlockReason) -> None:
        self.reason: BlockReason = reason
        if reason == "licence_attestation":
            detail = (
                "its licence does not clearly allow scanning proprietary code; set "
                "engines.options.<id>.options.licence_attestation to confirm: "
                f'"{LICENCE_ATTESTATION_SENTENCE}"'
            )
        else:
            detail = "this engine is never run in a hosted deployment"
        super().__init__(engine_id, detail)
