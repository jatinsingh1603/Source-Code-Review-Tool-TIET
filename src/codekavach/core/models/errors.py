"""Error types raised by the core models.

Owning epic: E02. Messages are plain text and never embed field values, because exception text
ends up in logs and field values may be client code or secrets.
"""


class ModelError(Exception):
    """Base class for errors raised by codekavach.core.models."""


class InvalidStatusTransition(ModelError):  # noqa: N818 - name fixed by E02-02
    """A finding status change is not allowed by the lifecycle rules."""


class UnsupportedSchemaVersion(ModelError):  # noqa: N818 - name fixed by E02-02
    """A persisted document has a schema version this release cannot load."""


class MigrationError(ModelError):
    """Upgrading a persisted document to the current schema version failed."""


class FingerprintInputError(ModelError):
    """The inputs of a finding fingerprint are missing or invalid."""
