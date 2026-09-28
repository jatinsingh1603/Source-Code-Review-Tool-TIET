"""Test helpers for the log redaction processor."""

import io
import json
from collections.abc import Iterator
from typing import Any

import pytest

from codekavach.core.log import configure_logging, redaction


@pytest.fixture
def restore_redaction_patterns() -> Iterator[None]:
    """Restore the pattern registry after a test that registers patterns."""
    saved = dict(redaction._RULES)
    yield
    redaction._RULES.clear()
    redaction._RULES.update(saved)


def json_events(buffer: io.StringIO) -> list[dict[str, Any]]:
    """The JSON log lines written to ``buffer``."""
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


def capture(fmt: str) -> io.StringIO:
    """Configure logging into a fresh buffer in the given format."""
    buffer = io.StringIO()
    configure_logging(fmt=fmt, level="DEBUG", stream=buffer, force=True)  # type: ignore[arg-type]
    return buffer
