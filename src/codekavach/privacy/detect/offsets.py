"""``ByteOffsets``: character index to UTF-8 byte offset, computed once per text.

Owning epic: E08.

Regular expressions over a ``str`` report character indices; a ``TypedSpan`` holds byte offsets.
Converting each match with ``len(text[:index].encode())`` is quadratic on a text with many
matches, so a detector builds one ``ByteOffsets`` per text. For an ASCII text (most code) the
two are equal and nothing is allocated.
"""

from itertools import accumulate


class ByteOffsets:
    """Maps a character index of ``text`` to the byte offset of that character in UTF-8."""

    def __init__(self, text: str) -> None:
        self._ascii = text.isascii()
        self._starts: list[int] = []
        if not self._ascii:
            widths = (len(char.encode("utf-8", errors="surrogatepass")) for char in text)
            self._starts = [0, *accumulate(widths)]

    def at(self, index: int) -> int:
        """The byte offset of the character at ``index`` (``len(text)`` gives the byte length)."""
        return index if self._ascii else self._starts[index]
