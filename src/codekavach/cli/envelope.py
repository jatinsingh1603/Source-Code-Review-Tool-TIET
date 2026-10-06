"""The JSON envelope written to stdout in ``--json`` mode (``docs/reference/cli-json-output.md``).

Owning epic: E05.

Kept apart from ``codekavach.cli.output`` so that Pydantic is imported only when an envelope is
actually built, not on every invocation (start-up budget, E05-31). The schema is exported to
``docs/schemas/cli/envelope.schema.json`` by ``tools/export_cli_schema.py``.
"""

from typing import Literal

from pydantic import BaseModel, JsonValue


class EnvelopeMessage(BaseModel):
    """One warning or error in the envelope."""

    code: str
    message: str
    hint: str | None = None


class Envelope(BaseModel):
    """The JSON document written to stdout in ``--json`` mode (stable while additive)."""

    schema_version: Literal["1"]
    codekavach_version: str
    command: str
    ok: bool
    exit_code: int
    data: JsonValue
    warnings: tuple[EnvelopeMessage, ...]
    errors: tuple[EnvelopeMessage, ...]
