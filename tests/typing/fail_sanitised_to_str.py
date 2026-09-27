"""Sanitised text is not a str; expose() must be called explicitly."""

from codekavach.core.models.text import SanitisedText


def log_text(text: str) -> None:
    """Pretend to log a string."""


log_text(SanitisedText("v_1 = 1"))  # E: arg-type
