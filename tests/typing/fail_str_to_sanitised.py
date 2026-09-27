"""A plain str must not be accepted where sanitised text is expected."""

from codekavach.core.models.text import SanitisedText


def send(text: SanitisedText) -> None:
    """Pretend to send sanitised text to a model."""


send("def f(): pass")  # E: arg-type
