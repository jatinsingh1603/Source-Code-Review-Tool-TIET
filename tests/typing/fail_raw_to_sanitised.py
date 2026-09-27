"""Raw code must not be accepted where sanitised text is expected (invariant I2)."""

from codekavach.core.models.text import RawCode, SanitisedText


def send(text: SanitisedText) -> None:
    """Pretend to send sanitised text to a model."""


send(RawCode("secret code"))  # E: arg-type
