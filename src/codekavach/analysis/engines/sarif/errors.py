"""Typed errors of the SARIF reader (E14-02).

Owning epic: E14. The messages are fixed phrases and indices. They never quote the log, because the
log quotes client code.
"""


class SarifError(ValueError):
    """Base of the errors raised while reading an engine's SARIF output."""


class SarifFormatError(SarifError):
    """The output is not a usable SARIF log. ``problems`` lists what is wrong, without content."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("; ".join(self.problems[:5]) or "malformed SARIF log")


class SarifSizeError(SarifError):
    """The output exceeds the size limit and is not parsed."""

    def __init__(self, size: int, limit: int) -> None:
        self.size = size
        self.limit = limit
        super().__init__(f"SARIF output of {size} bytes exceeds the limit of {limit} bytes")
