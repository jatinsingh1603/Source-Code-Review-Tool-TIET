"""Errors shared by the privacy layer.

Owning epic: E08.

``RedactionError`` is the one exception every step of detection and redaction raises when it
cannot finish correctly. It is raised instead of returning partial text, so the caller aborts the
candidate rather than send half-redacted content (invariant I4, fail closed). Its message names
the failed rule and never quotes the text being processed, a span's value or a detector's
output: an exception message is logged and printed, and the text it would quote is exactly what
this layer exists to hide.
"""


class RedactionError(Exception):
    """A detection or redaction step failed; the candidate must not be sent (I4)."""
