"""Correct use of the text wrappers."""

from codekavach.core.models.text import RawCode, SanitisedText, split_lines


def send(text: SanitisedText) -> int:
    """Pretend to send sanitised text to a model."""
    return len(text)


raw = RawCode("a = 1\nb = 2\n")
lines: list[str] = split_lines(raw.expose())
count: int = raw.line_count
sent: int = send(SanitisedText("v_1 = 1"))
exposed: str = SanitisedText("v_2").expose()
