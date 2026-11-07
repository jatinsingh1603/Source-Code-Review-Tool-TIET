"""Errors of the restore engine.

Owning epic: E10.

``RestoreError`` is raised when restored output cannot be trusted: a token survived, a location
does not belong to the slice, or the payload and the slice do not describe the same candidate. Its
message is fixed text and never quotes a pseudonym, an original, a path or a line of model output,
because an exception message is logged and printed (invariant I3, and I4 for the refusal itself).
"""


class RestoreError(Exception):
    """Restored output failed a check; the item is failed, never partially published (I4)."""
